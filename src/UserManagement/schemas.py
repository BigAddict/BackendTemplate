from pydantic_extra_types.phone_numbers import PhoneNumber
from pydantic import BaseModel, EmailStr
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