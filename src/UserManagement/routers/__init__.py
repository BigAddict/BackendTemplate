from fastapi import APIRouter

from .user_router import router as user_router

router = APIRouter(tags=["User Management"])
router.include_router(user_router)