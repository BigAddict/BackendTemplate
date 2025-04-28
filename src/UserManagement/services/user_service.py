from sqlmodel import Session, select
from pydantic import EmailStr
from pydantic_extra_types.phone_numbers import PhoneNumber
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError

from src.UserManagement.schemas import UserCreate
from src.UserManagement.models import User, UserCredential, VerificationToken
from src.Exceptions.user_exceptions import EmailAlreadyExists, UsernameAlreadyExists, PhoneAlreadyExists

async def get_user_by_email(email:EmailStr, session: Session) -> Optional[User]:
    try:
        result = session.exec(select(User).where(User.email == email)).one_or_none()
        return result
    except SQLAlchemyError as e:
        raise e
    
async def get_user_by_username(username:str, session: Session) -> Optional[User]:
    try:
        result = session.exec(select(User).where(User.username == username)).one_or_none()
        return result
    except SQLAlchemyError as e:
        raise e

async def create_user(
    user_data: UserCreate,
    session: Session
):
    pass