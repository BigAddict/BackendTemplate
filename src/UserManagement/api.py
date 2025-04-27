from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.encoders import jsonable_encoder
from sqlmodel import Session, select
from pydantic import EmailStr
from typing import Optional

from src.core.security.auth import get_password_hash, get_current_user, get_device_type
from src.UserManagement.schemas import UserCreate, UserVerify, UserUpdate, UserResponse
from src.core.utils import send_verification_email
from src.UserManagement.models import User, Role, VerificationToken
from src.core.database import get_session
from src.core.config import get_settings

settings = get_settings()

router = APIRouter(
    tags=["User Management"],
    responses={
        404: {"description": "Not found"},
        422: {"description": "Validation error"},
    },
)

@router.get("/user/all")
async def list_users(session : Session = Depends(get_session)):
    users = session.exec(select(User)).all()
    return JSONResponse(
        content=[jsonable_encoder(UserResponse(**user.model_dump())) for user in users],
        status_code=status.HTTP_200_OK
    )

@router.post("/user/", status_code=status.HTTP_201_CREATED)
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

@router.post("/user/verify-email")
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

@router.get("/user/", response_model=UserResponse)
async def get_current_user_info(request: Request):
    user = await get_current_user(request)
    return jsonable_encoder(UserResponse(**user.model_dump()))

@router.get("/user/")
async def get_user_by_email_or_username(
    email: Optional[str],
    username: Optional[str],
    session: Session = Depends(get_session)    
):
    if not email and not username:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="{'error': 'No email or username provided. Please try again!'}"
        )
    
    if email:
        user = session.exec(select(User).where(User.email == email)).one_or_none()
        if user:
            return jsonable_encoder(UserResponse(**user.model_dump()))
        
    if username:
        user = session.exec(select(User).where(User.username == username)).one_or_none()
        if user:
            return jsonable_encoder(UserResponse(**user.model_dump()))
        
    return JSONResponse(
        content={},
        status_code=status.HTTP_200_OK
    )

@router.patch("/user/", response_model=UserResponse)
async def update_user(
    new_details: UserUpdate,
    request: Request,
    session: Session = Depends(get_session)
):
    user = await get_current_user(request)
    if not user:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={'error': 'User not found.'}
        )
    
    for key, value in new_details.model_dump(exclude_unset=True).items():
        setattr(user, key, value)

    session.add(user)
    session.commit()
    session.refresh(user)

    return jsonable_encoder(UserResponse(**user.model_dump()))

@router.delete("/user/", response_model=UserResponse)
async def delete_user(
    request: Request,
    session: Session = Depends(get_session)
):
    user = await get_current_user(request)
    if not user:
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={'error': 'User not found.'}
        )
    
    session.delete(user)
    session.commit()
    
    return JSONResponse(
        content={'message': 'User deleted successfully.'}
    )