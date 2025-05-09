from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from fastapi.encoders import jsonable_encoder
from sqlmodel import Session, select
from pydantic import EmailStr
from typing import Optional

from src.core.security.auth import get_password_hash, get_current_user, get_device_type, get_current_admin_user, verify_password
from src.UserManagement.schemas import UserCreate, UserVerify, UserUpdate, UserResponse, PasswordReset, PasswordChange
from src.Exceptions.core_exceptions import SystemError
from src.Exceptions.user_exceptions import NotAdminUser, UserNotFound
from src.UserManagement.services.user_service import create_user, get_all_users, get_user_by_email, get_user_by_username, get_user_by_phone, update_user_details
from src.core.security.auth import OAuth2PasswordRequestForm, get_token, get_refresh_token
from src.core.utils import send_verification_email, send_password_reset_email
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
            detail="An error occurred while processing your request."
        )
    user.is_verified = True
    user.is_active = True
    session.delete(verification_token)
    session.commit()
    return JSONResponse(
        content={"message": "Email verified successfully"}
    )

@router.post("/user/verify-email/resend")
async def resend_verification_email(
    email: EmailStr,
    request: Request,
    session: Session = Depends(get_session)
):
    user = session.exec(select(User).where(User.email == email)).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found!"
        )
    if user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already verified!"
        )
    if user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already active!"
        )
    base_url = request.base_url
    success, message = await send_verification_email(user.id, user.email, base_url)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message
        )
    return JSONResponse(
        content={"message": "Verification email resent successfully."},
        status_code=status.HTTP_200_OK
    )

@router.post("/login/")
async def authenticate_user(
    response: JSONResponse,
    remember_me: Optional[bool] = False,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
):
    tokens = await get_token(data=form_data, db=session)

    if type(tokens) == dict:
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')
        expires_in = tokens.get('expires_in')
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={'error': 'Invalid Credentials.'},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    response = JSONResponse(content=jsonable_encoder(tokens), status_code=status.HTTP_200_OK)

    response.set_cookie(
        key='access_token',
        value=access_token,
        samesite='lax',
        max_age=expires_in
    )

    if remember_me:
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            samesite='lax',
            max_age=expires_in
        )
    else:
        response.set_cookie(
            key='refresh_token',
            value=refresh_token,
            samesite='lax',
        )
    return response

@router.post("/refresh-token", status_code=status.HTTP_200_OK)
async def refresh_access_token(request: Request, response: JSONResponse, refresh_token:Optional[str] = None, session: Session = Depends(get_session)):

    if not refresh_token:
        refresh_token = request.cookies.get('refresh_token')
        if not refresh_token:
            return HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={'error': 'No refresh token provided.'},
                headers={"WWW-Authenticate": "Bearer"}
            )

    tokens = await get_refresh_token(token=refresh_token, db=session)

    if type(tokens) == dict:
        access_token = tokens.get('access_token')
        refresh_token = tokens.get('refresh_token')
        expires_in = tokens.get('expires_in')
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={'error': 'Invalid refresh token.'},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    response = JSONResponse(content=jsonable_encoder(tokens), status_code=status.HTTP_200_OK)

    response.set_cookie(
        key='access_token',
        value=access_token,
        samesite='lax',
        max_age=expires_in
    )
    return response

@router.get("/user/forgot-password")
async def forgot_password(
    email: EmailStr,
    session: Session = Depends(get_session)
):
    user = session.exec(select(User).where(User.email == email)).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User not found!"
        )
    
    success, message = await send_password_reset_email(user.id, user.email)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=message
        )
    return JSONResponse(
        content={"message": "Password reset email sent successfully."},
        status_code=status.HTTP_200_OK
    )

@router.post("/user/reset-password")
async def reset_password(
    new_password: PasswordReset,
    session: Session = Depends(get_session)
):
    verification_token = session.exec(select(VerificationToken).where(VerificationToken.code == new_password.one_time_code)).one_or_none()
    if not verification_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Invalid one-time code!"}
        )
    user = session.exec(select(User).where(User.id == verification_token.user_id)).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "User not found!"}
        )
    user.password_hash = get_password_hash(new_password.new_password)
    session.delete(verification_token)
    session.add(user)
    session.commit()
    session.refresh(user)
    return JSONResponse(
        content={"message": "Password reset successfully."},
        status_code=status.HTTP_200_OK
    )

@router.get("/user/change-password")
async def change_password(
    new_password: PasswordChange,
    request: Request,
    session: Session = Depends(get_session)
):
    user = await get_current_user(request, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={'error': 'User not found.'}
        )
    if not verify_password(new_password.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={'error': 'Current password is incorrect.'}
        )
    user.password_hash = get_password_hash(new_password.new_password)
    session.add(user)
    session.commit()
    session.refresh(user)
    return JSONResponse(
        content={"message": "Password changed successfully."},
        status_code=status.HTTP_200_OK
    )