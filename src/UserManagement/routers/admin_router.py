from fastapi import APIRouter, Request, Depends, status
from fastapi.encoders import jsonable_encoder
from fastapi.responses import JSONResponse
from sqlmodel import Session

from src.UserManagement.schemas import UserCreate, UserUpdate, UserResponse, UserRead
from src.UserManagement.services.admin_service import create_user, update_user, get_user, get_all_users
from src.core.security.auth import get_current_user, get_current_admin_user
from src.core.database import get_session
from src.UserManagement.models import User

router = APIRouter(prefix="/admin", dependencies=[Depends(get_current_admin_user)])

@router.post("/user")
async def add_user(
    new_user: UserCreate,
    request: Request,
    session: Session = Depends(get_session)
) -> JSONResponse:
    """
    Create a new user.
    """
    created_user = await create_user(new_user, session)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "message": "User created successfully.",
            "user": jsonable_encoder(UserResponse(**created_user.model_dump()))
        }
    )

@router.get("/user/all")
async def get_all_users_info(
    session: Session = Depends(get_session)
) -> JSONResponse:
    """
    Get all users.
    """
    users = await get_all_users(session)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=(jsonable_encoder([UserResponse(**user.model_dump()) for user in users]))
    )

@router.post("/user")
async def get_user_info(
    user_details: UserRead,
    session: Session = Depends(get_session)
) -> JSONResponse:
    """
    Get user details by email, username, or phone number.
    """
    user = await get_user(user_details, session)
    if not user:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"message": "User not found."}
        )
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=jsonable_encoder(UserResponse(**user.model_dump()))
    )

@router.patch("/user")
async def update_user_details(
    user_details: UserUpdate,
    request: Request,
    session: Session = Depends(get_session)
) -> JSONResponse:
    """
    Update user details.
    """
    user = await get_current_user(request, session)
    updated_user = await update_user(user_details, user, session)
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=jsonable_encoder(UserResponse(**updated_user.model_dump()))
    )

@router.delete("/user")
async def delete_user(
    request: Request,
    session: Session = Depends(get_session)
) -> JSONResponse:
    """
    Delete a user.
    """
    user = await get_current_user(request, session)
    user.is_active = False
    user.is_verified = False
    session.add(user)
    session.commit()
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"message": "User deleted successfully."}
    )