from contextlib import asynccontextmanager

import uvicorn
from app import settings
from app.middleware import AuthAndSizeGate
from app.routes.utils import utils_router
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Request
from fastapi.responses import JSONResponse
from loguru import logger

description = """
SOCFortress Wazuh Utils API
"""


@asynccontextmanager
async def lifespan(_app):
    key, problem = settings.api_key()
    if problem:
        logger.error(f"{problem}: every protected route will refuse requests")
    elif not key:
        logger.warning(
            "WAZUH_UTILS_API_KEY is not set: /sysmon-config is unauthenticated and "
            "/shared-files is disabled. Set a key (see README).",
        )
    yield


app = FastAPI(
    description=description,
    version="0.2.0",
    title="SOCFortress Wazuh Utils",
    lifespan=lifespan,
    # No interactive docs or schema on a root-adjacent service reachable from the
    # network.
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

# No CORS middleware: this is a server-to-server API (CoPilot -> Wazuh master), and
# a browser on another origin has no business calling it.
app.add_middleware(AuthAndSizeGate)


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
        },
    )


@app.exception_handler(Exception)
async def unexpected_exception_handler(request: Request, exc: Exception):
    logger.exception(f"Unhandled error on {request.url.path}")
    return JSONResponse(
        status_code=500,
        content={"success": False, "message": "Internal error"},
    )


app.router.include_router(utils_router, prefix="/provision_worker")


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=5003)
