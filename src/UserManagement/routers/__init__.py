from fastapi import APIRouter

from .user_router import router as user_router
from .admin_router import router as admin_router

router = APIRouter(tags=["User Management"])
router.include_router(user_router)
router.include_router(admin_router)