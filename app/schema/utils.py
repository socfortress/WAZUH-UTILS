from typing import List

from pydantic import BaseModel
from pydantic import Field


class UtilsResponse(BaseModel):
    success: bool = Field(
        ...,
        examples=[True],
        description="Whether the operation was successful",
    )
    message: str = Field(
        ...,
        examples=["Operation completed successfully"],
        description="The message returned by the API",
    )


class WrittenFile(BaseModel):
    name: str
    sha256: str


class SharedFilesResponse(UtilsResponse):
    written: List[WrittenFile] = Field(default_factory=list)
