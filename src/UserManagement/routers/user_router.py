from fastapi import APIRouter, Request, Depends, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlmodel import Session

from src.UserManagement.schemas import UserCreate, UserUpdate, UserResponse
from src.UserManagement.services.user_service import create_user, update_user_details
from src.Exceptions.user_exceptions import UserNotFound
from src.core.security.auth import get_current_user
from src.core.utils import send_verification_email
from src.core.database import get_session
from src.core.config import get_settings

settings = get_settings()

router = APIRouter(prefix="/user")

@router.post("/", status_code=status.HTTP_201_CREATED)
async def register_user(
    user: UserCreate,
    request: Request,
    session: Session = Depends(get_session)
):
    """
    Register a new user and send a verification email.
    """
    new_user = await create_user(user, session)

    base_url = request.base_url
    success, message = await send_verification_email(new_user.id, new_user.email, base_url)
    if not success:
        session.delete(new_user)
        session.commit()
        raise SystemError(
            message
            )

    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "message": "User registered successfully. Please check your email to verify your account."
        }
    )

@router.get("/", response_model=UserResponse)
async def get_current_user_info(request: Request, session: Session = Depends(get_session)):
    user = await get_current_user(request, session)
    return jsonable_encoder(UserResponse(**user.model_dump()))

@router.patch("/", response_model=UserResponse)
async def update_user(
    new_details: UserUpdate,
    request: Request,
    session: Session = Depends(get_session)
):
    user = await get_current_user(request)

    if not user:
        raise UserNotFound()
    
    updated_user = await update_user_details(new_details, user, session)

    return jsonable_encoder(UserResponse(**updated_user.model_dump()))

@router.delete("/", response_model=UserResponse)
async def delete_user(
    request: Request,
    session: Session = Depends(get_session)
):
    user = await get_current_user(request)
    if not user:
        raise UserNotFound()
    
    user.is_active = False
    user.is_verified = False
    session.commit()
    
    return JSONResponse(
        content={'message': 'User deleted successfully.'}
    )

@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout_user(request: Request, response: JSONResponse):
    """
    Logout the user by clearing the access and refresh tokens.
    """
    response.delete_cookie(key='access_token')
    response.delete_cookie(key='refresh_token')
    return JSONResponse(
        content={'message': 'Logged out successfully.'},
        status_code=status.HTTP_200_OK
    )