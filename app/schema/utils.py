from pydantic import BaseModel
from pydantic import Field


class UtilsResponse(BaseModel):
    success: bool = Field(
        ...,
        example=True,
        description="Whether the operation was successful",
    )
    message: str = Field(
        ...,
        example="Operation completed successfully",
        description="The message returned by the API",
    )

