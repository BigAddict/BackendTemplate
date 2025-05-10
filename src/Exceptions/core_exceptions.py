from fastapi import HTTPException, status
from typing import Optional

from src.core.config import log_message

class HTTPExceptionCustom(HTTPException):
    def __init__(self, status_code, error_message, headers = None):
        super().__init__(
            status_code,
            detail={"error": error_message},
            headers=headers
        )
        log_message(
            "error",
            f"status_code: {status_code}, message: {error_message}"
        )

class SystemError(HTTPExceptionCustom):
    def __init__(self, error_message="An error occurred while trying to process your request!"):
        super().__init__(
            status.HTTP_500_INTERNAL_SERVER_ERROR,
            error_message
        )