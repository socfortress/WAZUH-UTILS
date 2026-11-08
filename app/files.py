"""Safe placement of files in a Wazuh group's shared folder."""
import grp
import os
import pwd
import re
import secrets
from pathlib import Path
from typing import Iterable
from typing import List
from typing import Tuple

from app import settings
from fastapi import HTTPException

# Wazuh group names: letters, digits, '_', '-', '.'.
GROUP_RE = re.compile(r"[A-Za-z0-9_.-]{1,255}")


def group_dir(group: str, prefix: str = "Windows_") -> Path:
    """The existing directory of ``group`` under the shared dir, or an HTTP error.

    Never creates a directory: a group exists on the manager before files go in,
    and a typo must not create a phantom group folder.
    """
    if (
        not GROUP_RE.fullmatch(group)
        or group in (".", "..")
        or not group.startswith(prefix)
    ):
        raise HTTPException(status_code=400, detail=f"Invalid group name: {group!r}")
    base = settings.shared_dir().resolve()
    target = (base / group).resolve()
    if target.parent != base:
        raise HTTPException(status_code=400, detail=f"Invalid group name: {group!r}")
    if not target.is_dir():
        raise HTTPException(status_code=404, detail=f"Group {group} does not exist")
    return target


def _wazuh_ids():
    try:
        return pwd.getpwnam("wazuh").pw_uid, grp.getgrnam("wazuh").gr_gid
    except KeyError:
        return None


def write_files(directory: Path, files: Iterable[Tuple[str, bytes]]) -> List[Path]:
    """Write every ``(name, data)`` into ``directory`` atomically, as wazuh 0660.

    Everything goes through file descriptors, never paths: the directory is opened
    once with O_NOFOLLOW, each temp file is created there with O_EXCL|O_NOFOLLOW,
    and mode/owner are set with fchmod/fchown on the open file. A local user who can
    rename entries in the group directory (it is wazuh-writable) therefore cannot
    redirect any of these operations through a symlink. All temp files are written
    first and renamed afterwards, so a failure leaves the old set untouched, and
    Wazuh never sees a half-written file.
    """
    files = list(files)
    for name, _ in files:
        if not name or "/" in name or name in (".", "..") or name.startswith("."):
            raise HTTPException(status_code=400, detail=f"Invalid file name: {name!r}")
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
    dir_fd = os.open(str(directory), flags)
    staged = []
    ids = _wazuh_ids()
    try:
        for name, data in files:
            tmp = f".{name}.{secrets.token_hex(8)}"
            fd = os.open(
                tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
                dir_fd=dir_fd,
            )
            staged.append((tmp, name))
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fchmod(handle.fileno(), 0o660)
                # Only root can hand files to wazuh; running as wazuh needs nothing.
                if ids and os.geteuid() == 0:
                    os.fchown(handle.fileno(), *ids)
                os.fsync(handle.fileno())
        for tmp, name in staged:
            os.replace(tmp, name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
        staged = []
        os.fsync(dir_fd)
        return [directory / name for name, _ in files]
    finally:
        for tmp, _ in staged:
            try:
                os.unlink(tmp, dir_fd=dir_fd)
            except FileNotFoundError:
                pass
        os.close(dir_fd)
