from fastapi import HTTPException, status

class InvalidVerificationCode(HTTPException):
    def __init__(self, message: str = "Invalid verification code. Please try again."):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=message
        )

class InvalidRefreshToken(HTTPException):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Please login to continue."},
            headers={"WWW-Authenticate": "Bearer"}
        )