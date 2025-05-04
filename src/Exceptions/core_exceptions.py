from fastapi import HTTPException, status
from typing import Optional

class SystemError(HTTPException):
    def __init__(self, message: str = "System error occurred. Please try again later."):
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message
        )