from fastapi import status

from src.Exceptions.core_exceptions import HTTPExceptionCustom
class EmailAlreadyExists(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            "User with this email already exists."
        )

class UsernameAlreadyExists(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            "Username already taken."
        )
    
class PhoneAlreadyExists(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            "User with this phone number already exists."
        )

class UserAlreadyExists(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            "User already exists"
        )

class UserNotFound(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_404_NOT_FOUND,
            "User not found."
        )

class UserAlreadyVerified(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            "User is already verified."
        )

class UserAlreadyActive(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_400_BAD_REQUEST,
            "User is already active."
        )

class NotAdminUser(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_403_FORBIDDEN,
            "User is not an admin."
        )

class InvalidCredentials(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid credentials."
        )

class UserNotVerified(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User not verified."
        )

class UserInactive(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_403_FORBIDDEN,
            "User is inactive."
        )

class InvalidToken(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_401_UNAUTHORIZED,
            "Invalid token."
        )

class TokenExpired(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_401_UNAUTHORIZED,
            "Token has expired."
        )

class RoleNotFound(HTTPExceptionCustom):
    def __init__(self):
        super().__init__(
            status.HTTP_404_NOT_FOUND,
            "Role not found."
        )