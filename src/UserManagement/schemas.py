from pydantic_extra_types.phone_numbers import PhoneNumber
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional

class UserBase(BaseModel):
    username: str
    email: EmailStr
    phone_number: PhoneNumber

class UserCreate(UserBase):
    password: str

class UserVerify(BaseModel):
    code: int

class UserUpdate(BaseModel):
    username: str
    email: EmailStr
    phone_number: PhoneNumber

class UserRead(BaseModel):
    email: Optional[str]
    username: Optional[str]
    phone_number: Optional[str]

class UserResponse(BaseModel):
    username: str
    email: EmailStr
    phone_number: PhoneNumber
    created_at: datetime

class PasswordReset(BaseModel):
    one_time_code: str
    new_password: str

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class AdminCreateUser(BaseModel):
    email: str
    username: str
    phone_number: PhoneNumber
    password: str
    is_superuser: Optional[bool] = False

class AdminUpdateUser(UserUpdate):
    is_superuser: Optional[bool] = False

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    expires_in: int