import uvicorn
from app.routes.utils import utils_router
from fastapi import FastAPI
from fastapi import HTTPException
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

description = """
SOCFortress Wazuh Utils API
"""

app = FastAPI(
    description=description,
    version="0.1.0",
    title="SOCFortress Wazuh Utils",
)

# Allow all origins, methods and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(HTTPException)
async def custom_http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "success": False,
            "message": exc.detail,
        },
    )


app.router.include_router(utils_router, prefix="/provision_worker")


if __name__ == "__main__":
    uvicorn.run(app, host="localhost", port=5003)