from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from sqlmodel import Session
from pydantic import EmailStr
from typing import Optional

from src.core.database import get_session
from src.UserManagement.schemas import UserVerify, TokenResponse, PasswordReset, PasswordChange
from src.UserManagement.services.auth_service import verify_email_code, get_user_by_verification_token, change_user_password
from src.Exceptions.core_exceptions import SystemError
from src.Exceptions.user_exceptions import UserNotFound, UserAlreadyVerified, InvalidCredentials
from src.Exceptions.auth_exceptions import InvalidRefreshToken
from src.UserManagement.services.user_service import get_user_by_email
from src.core.utils import send_verification_email, send_password_reset_email
from src.core.security.auth import OAuth2PasswordRequestForm, get_token, get_refresh_token, get_current_user, verify_password

router = APIRouter(prefix="/auth")

@router.post("/verify-email")
async def verify_email(
    code: UserVerify,
    session: Session = Depends(get_session)
) -> JSONResponse:
    """
    Verify the user's email using the verification code.
    """
    try:
        if await verify_email_code(code.code, session):
            return JSONResponse(
                content={"message": "Email verified successfully"}
            )
    except HTTPException as e:
        raise e
    except Exception as e:
        raise SystemError(
            message="An error occurred while processing your request."
        )
    
@router.post("/verify-email/resend")
async def resend_verification_email(
    email: EmailStr,
    request: Request,
    session: Session = Depends(get_session)
) -> JSONResponse:
    try:
        user = await get_user_by_email(email, session)
        if not user:
            raise UserNotFound()
        if user.is_verified:
            raise UserAlreadyVerified()
        
        base_url = request.base_url
        success, message = await send_verification_email(user.id, email, base_url)
        if not success:
            raise SystemError(message)
        return JSONResponse(
            content={"Message": "Verification email sent successfully."}
        )
    except Exception as e:
        raise SystemError("An unexpected error occurred!")

@router.post("/login")
async def authenticate_user(
    remember_me: Optional[bool] = False,
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session)
) -> JSONResponse:
    try:
        tokens = await get_token(form_data, session)

        response = JSONResponse(content=jsonable_encoder(tokens.model_dump()), status_code=status.HTTP_200_OK)

        response.set_cookie(
            key='access_token',
            value=tokens.access_token,
            samesite='lax',
            max_age=tokens.expires_in
        )

        if remember_me:
            response.set_cookie(
                key="refresh_token",
                value=tokens.refresh_token,
                samesite='lax',
                max_age=tokens.expires_in
            )
        else:
            response.set_cookie(
                key="refresh_token",
                value=tokens.refresh_token,
                samesite='lax'
            )
        return response

    except Exception as e:
        raise SystemError("An error occured while trying to log you in.")
    
@router.post("/rotate-login")
async def refresh_access_token(
    request: Request,
    refresh_token: Optional[str] = None,
    session: Session = Depends(get_session)
) -> JSONResponse:
    try:
        if not refresh_token:
            refresh_token = request.cookies.get('refresh_token')
            if not refresh_token:
                InvalidRefreshToken()
        
        tokens = await get_refresh_token(refresh_token, session)

        response = JSONResponse(content=jsonable_encoder(TokenResponse(**tokens.model_dump())), status_code=status.HTTP_200_OK)

        response.set_cookie(
            key="access_token",
            value=tokens.access_token,
            samesite='lax',
            max_age=tokens.expires_in
        )
        return response

    except Exception as e:
        raise SystemError(e)
    
@router.post("forgot-password")
async def user_forgot_password(
    email: EmailStr,
    session: Session = Depends(get_session)
) -> JSONResponse:
    try:
        user = await get_user_by_email(email, session)
        if not user:
            UserNotFound()
        
        success, message = await send_password_reset_email(user.id, email)
        if not success:
            raise SystemError("An error occurred")
        
        return JSONResponse(
            content={"message": "Password reset email sent successfully."},
            status_code=status.HTTP_200_OK
        )
    except Exception as e:
        raise SystemError(e)
    
@router.post("reset-password")
async def reset_password(
    new_password: PasswordReset,
    session: Session = Depends(get_session)
) -> JSONResponse:
    try:
        user = await get_user_by_verification_token(new_password.one_time_code, session)
        if not user:
            raise UserNotFound()
        await change_user_password(user, new_password.new_password, session)
        return JSONResponse(
            content={"message": "Password reset successfully."},
            status_code=status.HTTP_200_OK
        )
    except Exception as e:
        raise SystemError(e)
    
@router.post("change-password")
async def change_password(
    new_password: PasswordChange,
    request: Request,
    session: Session = Depends(get_session)
) -> JSONResponse:
    try:
        user = await get_current_user(request, session)
        if not user:
            raise UserNotFound()
        
        if not verify_password(new_password.current_password, user.password_hash):
            raise InvalidCredentials()
        
        if await change_user_password(user, new_password.new_password, session):
            return JSONResponse(
                content={"message": "Password changed successfully."}
            )
        else:
            raise SystemError("An unknown error occurred")
    except Exception as e:
        SystemError()