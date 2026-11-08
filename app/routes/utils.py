import hashlib
from typing import List

from app import settings
from app.files import group_dir
from app.files import write_files
from app.schema.utils import SharedFilesResponse
from app.schema.utils import UtilsResponse
from app.schema.utils import WrittenFile
from app.security import require_api_key
from app.security import require_api_key_if_configured
from defusedxml import ElementTree
from fastapi import APIRouter
from fastapi import Depends
from fastapi import File
from fastapi import Form
from fastapi import HTTPException
from fastapi import Request
from fastapi import UploadFile
from loguru import logger

utils_router = APIRouter()

MAX_SYSMON_CONFIG_BYTES = 5 * 1024 * 1024
MAX_SCRIPT_BYTES = 1024 * 1024
# The only files /shared-files will place: the Sysmon-health scripts, which
# Windows agents run as SYSTEM through a wodle in the group's agent.conf.
ALLOWED_SHARED_FILES = frozenset({"sysmon_watchdog.ps1", "sysmon_config_reload.ps1"})


async def _read_limited(upload: UploadFile, limit: int) -> bytes:
    data = await upload.read(limit + 1)
    if len(data) > limit:
        raise HTTPException(status_code=413, detail=f"{upload.filename} is too large")
    return data


def _client(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@utils_router.post(
    "/sysmon-config",
    response_model=UtilsResponse,
    description="Upload Sysmon configuration file for a customer",
    dependencies=[Depends(require_api_key_if_configured)],
)
async def upload_sysmon_config(
    request: Request,
    customer_code: str = Form(...),
    sysmon_config: UploadFile = File(...),
):
    """
    Upload a Sysmon configuration XML file for a specific customer.
    It is stored as /var/ossec/etc/shared/Windows_<customer_code>/sysmon_config.xml.
    The group must already exist; the file must be well-formed XML with a <Sysmon>
    root.
    """
    if not (sysmon_config.filename or "").endswith(".xml"):
        raise HTTPException(status_code=400, detail="File must be an XML document")
    target_dir = group_dir(f"Windows_{customer_code.replace(' ', '_')}")
    data = await _read_limited(sysmon_config, MAX_SYSMON_CONFIG_BYTES)
    try:
        root = ElementTree.fromstring(data)
    except Exception:
        raise HTTPException(status_code=400, detail="Not well-formed XML")
    if root.tag.lower() != "sysmon":
        raise HTTPException(status_code=400, detail="The root element must be <Sysmon>")

    write_files(target_dir, [("sysmon_config.xml", data)])
    digest = hashlib.sha256(data).hexdigest()
    logger.info(
        f"sysmon_config.xml written to {target_dir.name} "
        f"(sha256 {digest}) for {_client(request)}",
    )
    return UtilsResponse(
        success=True,
        message=f"Sysmon configuration uploaded successfully for {customer_code}",
    )


@utils_router.post(
    "/shared-files",
    response_model=SharedFilesResponse,
    description="Place allow-listed Sysmon-health scripts in a Windows group",
    dependencies=[Depends(require_api_key)],
)
async def upload_shared_files(
    request: Request,
    group: str = Form(...),
    files: List[UploadFile] = File(...),
    sha256: List[str] = Form(...),
):
    """
    Write allow-listed scripts into /var/ossec/etc/shared/<group>/.

    Always authenticated. ``group`` must be an existing Windows_* group. Each
    ``files`` part needs a matching ``sha256`` field (same order); every file is
    checked (name, size, hash, optional pinned allow-list) before any is written.
    """
    target_dir = group_dir(group)
    if not files or len(files) != len(sha256):
        raise HTTPException(status_code=400, detail="Send one sha256 per file")
    if len(files) > len(ALLOWED_SHARED_FILES):
        raise HTTPException(status_code=400, detail="Too many files")

    pinned = settings.allowed_sha256()
    checked = []
    for upload, expected in zip(files, sha256):
        name = upload.filename or ""
        if name not in ALLOWED_SHARED_FILES:
            raise HTTPException(status_code=400, detail=f"File not allowed: {name!r}")
        if name in (n for n, _, _ in checked):
            raise HTTPException(status_code=400, detail=f"Duplicate file: {name}")
        data = await _read_limited(upload, MAX_SCRIPT_BYTES)
        digest = hashlib.sha256(data).hexdigest()
        if digest != expected.strip().lower():
            raise HTTPException(status_code=400, detail=f"sha256 mismatch for {name}")
        if pinned is not None and not settings.hash_allowed(name, digest, pinned):
            raise HTTPException(
                status_code=403,
                detail=f"{name} (sha256 {digest}) is not in WAZUH_UTILS_ALLOWED_SHA256",
            )
        checked.append((name, data, digest))

    write_files(target_dir, [(name, data) for name, data, _ in checked])
    written = [WrittenFile(name=name, sha256=digest) for name, _, digest in checked]
    for item in written:
        logger.info(
            f"{item.name} written to {group} (sha256 {item.sha256}) "
            f"for {_client(request)}",
        )
    return SharedFilesResponse(
        success=True,
        message=f"Wrote {len(written)} file(s) to {group}",
        written=written,
    )
