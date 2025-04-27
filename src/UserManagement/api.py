from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlmodel import Session, select

from src.core.security.auth import get_password_hash, get_current_user, get_device_type
from src.UserManagement.schemas import UserCreate, UserVerify
from src.core.utils import send_verification_email
from src.UserManagement.models import User, Role, VerificationToken
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
    response: Response,
    session: Session = Depends(get_session),
    device: str = Depends(get_device_type)
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

    base_url = request.base_url
    success, message = await send_verification_email(new_user.id, new_user.email, base_url)
    if not success:
        session.delete(new_user)
        session.commit()
        raise HTTPException(status_code=500, detail=message)
    
    if device == "web":
        response.set_cookie(key="temp_code")

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "message": "User registered successfully. Please check your email to verify your account."
        },
    )

@router.post("/verify-email")
async def verify_email(code: UserVerify, session: Session = Depends(get_session)):
    """
    Verify the user's email using the verification code.
    """
    verification_token = session.exec(select(VerificationToken).where(VerificationToken.code == code.code)).one_or_none()
    if not verification_token:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid verification code!"
        )
    
    user = session.exec(select(User).where(User.id == verification_token.user_id)).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An error occured while processing your request."
        )
    user.is_verified = True
    user.is_active = True
    session.delete(verification_token)
    session.commit()
    return JSONResponse(
        content={"message": "Email verified successfully"}
    )