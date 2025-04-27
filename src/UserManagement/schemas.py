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