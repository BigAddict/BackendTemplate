from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlmodel import Session, select
from urllib.parse import urlencode

from src.core.security.auth import get_password_hash, get_current_user
from src.UserManagement.schemas import UserCreate, UserVerify
from src.core.utils import send_verification_email
from src.UserManagement.models import User, Role
from src.core.database import get_session
from src.core.config import get_settings

settings = get_settings()

router = APIRouter(
    prefix="/user",
    tags=["User Management"],
    responses={
        404: {"description": "Not found"},
        422: {"description": "Validation error"},
    },
)

@router.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(
    user: UserCreate,
    request: Request,
    session: Session = Depends(get_session),
):
    """
    Register a new user and send a verification email.
    """
    # Check if the user already exists
    existing_user = session.exec(select(User).where(User.email == user.email)).one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    existing_user = session.exec(select(User).where(User.username == user.username)).one_or_none()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    # Create a new user instance
    new_user = User(
        username=user.username,
        email=user.email,
        phone_number=user.phone_number,
        password_hash=get_password_hash(user.password),
        is_active=False,
        is_superuser=False,
        is_verified=False,
    )
    
    role = session.exec(select(Role).where(Role.name == "User")).one_or_none()
    if not role:
        raise HTTPException(status_code=400, detail="Role not found")
    new_user.roles.append(role)

    session.add(new_user)
    session.commit()
    session.refresh(new_user)

    success, message = await send_verification_email(new_user.id, new_user.email)
    if not success:
        session.delete(new_user)
        session.commit()
        raise HTTPException(status_code=500, detail=message)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "message": "User registered successfully. Please check your email to verify your account."
        },
    )

@router.get("/verify-email")
async def verify_email(code: UserVerify, session: Session = Depends(get_session)):
    """
    Verify the user's email using the verification code.
    """
    pass