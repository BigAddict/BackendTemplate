from pydantic_extra_types.phone_numbers import PhoneNumber
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Session, select
from pydantic import EmailStr

from src.exceptions.user_exceptions import EmailAlreadyExists, UsernameAlreadyExists, PhoneAlreadyExists, RoleNotFound, UserAlreadyExists
from src.UserManagement.schemas import AdminCreateUser, UserRead, UserUpdate
from src.UserManagement.models import User, Role
from src.core.security.auth import get_password_hash
from src.UserManagement.services.user_service import get_user_by_email, get_user_by_username, get_user_by_phone

async def create_user(
        user_data: AdminCreateUser,
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
        
        # Check if phone already exists
        existing_user = await get_user_by_phone(user_data.phone_number, session)
        if existing_user:
            raise PhoneAlreadyExists()
        
        # Create new user
        new_user = User(
            email=user_data.email,
            username=user_data.username,
            phone_number=user_data.phone_number,
            password_hash=get_password_hash(user_data.password),
            is_active=True,
            is_verified=True,
            is_superuser=user_data.is_superuser
        )

        role = session.exec(
            select(Role)
            .where(Role.name == ("User" if not user_data.is_superuser else "Admin"))
        ).one_or_none()
        if not role:
            raise RoleNotFound()
        new_user.roles.append(role)

        session.add(new_user)
        session.commit()
        session.refresh(new_user)

        return new_user
    except SQLAlchemyError as e:
        session.rollback()
        raise e
    
async def get_user(details: UserRead, session: Session) -> User:
    try:
        if details.email:
            user = await get_user_by_email(details.email, session)
        elif details.username:
            user = await get_user_by_username(details.username, session)
        elif details.phone_number:
            user = await get_user_by_phone(details.phone_number, session)
        else:
            raise ValueError("At least one identifier (email, username, or phone number) must be provided.")
        return user
    except SQLAlchemyError as e:
        session.rollback()
        raise e
    
async def get_all_users(session: Session) -> list[User]:
    try:
        users = session.exec(select(User)).all()
        return users
    except SQLAlchemyError as e:
        session.rollback()
        raise e
    
async def update_user(
        new_details: UserUpdate,
        current_user: User,
        session: Session
):
    try:
        exsisting_user = await get_user(UserRead(**new_details.model_dump(exclude_unset=True)), session)
        if exsisting_user and (exsisting_user.id != current_user.id):
            raise UserAlreadyExists()
        
        for key, value in new_details.model_dump(exclude_unset=True).items():
            setattr(current_user, key, value)

        session.add(current_user)
        session.commit()
        session.refresh(current_user)
        return current_user
    except SQLAlchemyError as e:
        session.rollback()
        raise e