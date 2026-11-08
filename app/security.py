"""Bearer-token authentication for the sidecar's routes."""
import hmac
from typing import Optional

from app import settings
from fastapi import Header
from fastapi import HTTPException
from loguru import logger


def authorized(authorization: Optional[str], key: str) -> bool:
    if not authorization or not authorization.startswith("Bearer "):
        return False
    supplied = authorization.split(" ", 1)[1].strip()
    return hmac.compare_digest(supplied.encode(), key.encode())


async def require_api_key(authorization: Optional[str] = Header(None)) -> None:
    """Always required: refuses when no key is configured on this host."""
    key, problem = settings.api_key()
    if problem:
        logger.error(problem)
        raise HTTPException(status_code=503, detail="Authentication is misconfigured")
    if not key:
        raise HTTPException(
            status_code=503,
            detail="This endpoint requires WAZUH_UTILS_API_KEY to be configured",
        )
    if not authorized(authorization, key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")


async def require_api_key_if_configured(
    authorization: Optional[str] = Header(None),
) -> None:
    """For the legacy /sysmon-config route: enforced once a key is configured."""
    key, problem = settings.api_key()
    if problem:
        logger.error(problem)
        raise HTTPException(status_code=503, detail="Authentication is misconfigured")
    if key and not authorized(authorization, key):
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
