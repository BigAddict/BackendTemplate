from fastapi import status

from src.Exceptions.core_exceptions import HTTPExceptionCustom

class InvalidVerificationCode(HTTPExceptionCustom):
    def __init__(self, message: str = "Invalid verification code. Please try again."):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            message
        )

class InvalidRefreshToken(HTTPExceptionCustom):
    def __init__(self, message: str = "Please login to continue!"):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            message,
            headers={"WWW-Authenticate": "Bearer"}
        )