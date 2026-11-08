"""Reject unauthenticated or oversized uploads before the body is read.

FastAPI parses multipart bodies (and Starlette spools file parts to disk) before
route dependencies run, so an auth dependency alone would let anyone fill the
master's disk or memory and only then answer 401. This ASGI middleware decides
from the headers alone.
"""
import json

from app import security
from app import settings

# path -> True when a key is always required, False when only once configured.
PROTECTED = {
    "/provision_worker/shared-files": True,
    "/provision_worker/sysmon-config": False,
}
MAX_BODY_BYTES = 8 * 1024 * 1024


class AuthAndSizeGate:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] not in PROTECTED:
            return await self.app(scope, receive, send)
        headers = {
            k.decode("latin-1").lower(): v.decode("latin-1")
            for k, v in scope["headers"]
        }
        status, message = self._check(scope["path"], headers)
        if status:
            body = json.dumps({"success": False, "message": message}).encode()
            await send(
                {
                    "type": "http.response.start",
                    "status": status,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"connection", b"close"),
                    ],
                },
            )
            await send({"type": "http.response.body", "body": body})
            return
        return await self.app(scope, receive, send)

    @staticmethod
    def _check(path, headers):
        key, problem = settings.api_key()
        if problem:
            return 503, "Authentication is misconfigured"
        if PROTECTED[path] and not key:
            return 503, "This endpoint requires WAZUH_UTILS_API_KEY to be configured"
        if key and not security.authorized(headers.get("authorization"), key):
            return 401, "Invalid or missing API key"
        length = headers.get("content-length")
        if length is not None:
            try:
                if int(length) > MAX_BODY_BYTES:
                    return 413, "Request body too large"
            except ValueError:
                return 400, "Invalid Content-Length"
        return None, None
