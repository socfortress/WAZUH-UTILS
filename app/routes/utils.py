import os
import shutil


from app.schema.utils import ProvisionWorkerResponse
from fastapi import APIRouter
from fastapi import File
from fastapi import Form
from fastapi import HTTPException
from fastapi import UploadFile
from loguru import logger

provision_utils_router = APIRouter()


@provision_utils_router.post(
    "/sysmon-config",
    response_model=ProvisionWorkerResponse,
    description="Upload Sysmon configuration file for a customer",
)
async def upload_sysmon_config(
    customer_code: str = Form(...),
    sysmon_config: UploadFile = File(...),
):
    """
    Upload a Sysmon configuration XML file for a specific customer.
    The file will be stored in /var/ossec/etc/shared/Windows_<customer_code>/
    """
    try:
        # Validate file type
        if not sysmon_config.filename.endswith(".xml"):
            raise HTTPException(status_code=400, detail="File must be an XML document")

        # Replace spaces with underscores in customer_code
        customer_code = customer_code.replace(" ", "_")

        # Create target directory if it doesn't exist
        target_dir = f"/var/ossec/etc/shared/Windows_{customer_code}"
        os.makedirs(target_dir, exist_ok=True)

        # Define the target file path
        file_path = f"{target_dir}/sysmon_config.xml"

        # Save the uploaded file
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(sysmon_config.file, buffer)

        logger.info(f"Sysmon configuration uploaded for customer {customer_code}")

        return ProvisionWorkerResponse(
            success=True,
            message=f"Sysmon configuration uploaded successfully for {customer_code}",
        )

    except Exception as e:
        logger.error(f"Failed to upload Sysmon configuration: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to upload Sysmon configuration: {str(e)}",
        )