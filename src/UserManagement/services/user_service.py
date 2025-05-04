from sqlmodel import Session, select
from pydantic import EmailStr
from pydantic_extra_types.phone_numbers import PhoneNumber
from typing import Optional
from sqlalchemy.exc import SQLAlchemyError

from src.UserManagement.schemas import UserCreate, UserUpdate
from src.UserManagement.models import User, Role, UserCredential, VerificationToken
from src.Exceptions.user_exceptions import EmailAlreadyExists, UsernameAlreadyExists, PhoneAlreadyExists, RoleNotFound
from src.core.security.auth import get_password_hash

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
    
async def get_user_by_phone(phone:PhoneNumber, session: Session) -> Optional[User]:
    try:
        result = session.exec(select(User).where(User.phone_number == phone)).one_or_none()
        return result
    except SQLAlchemyError as e:
        raise e

async def create_user(
    user_data: UserCreate,
    session: Session
):
    try:
        # Check if email already exists
        existing_user = await get_user_by_email(user_data.email, session)
        if existing_user:
            raise EmailAlreadyExists()
        
        # Check if username already exists
        existing_user = await get_user_by_username(user_data.username, session)
        if existing_user:
            raise UsernameAlreadyExists()
        
        # Check if phone number already exists]
        existing_user = await get_user_by_phone(user_data.phone_number, session)
        if existing_user:
            raise PhoneAlreadyExists()
        
        # Create new user
        new_user = User(
            email=user_data.email,
            username=user_data.username,
            phone_number=user_data.phone_number,
            password_hash=get_password_hash(user_data.password),
            is_active=False,
            is_verified=False,
            is_superuser=False
        )
        
        role = session.exec(select(Role).where(Role.name == "User")).one_or_none()
        if not role:
            raise RoleNotFound()
        new_user.roles.append(role)

        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        return new_user
    except SQLAlchemyError as e:
        raise e

async def get_all_users(session: Session) -> list[User]:
    try:
        result = session.exec(select(User)).all()
        return result
    except SQLAlchemyError as e:
        raise e
    
async def update_user_details(new_details: UserUpdate, current_user: User, session: Session) -> User:
    try:
        for key, value in new_details.model_dump(exclude_unset=True).items():
            setattr(current_user, key, value)

        session.add(current_user)
        session.commit()
        session.refresh(current_user)
        return current_user
    except SQLAlchemyError as e:
        raise e