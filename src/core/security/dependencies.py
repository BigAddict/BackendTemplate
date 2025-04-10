from fastapi import HTTPException, status, Depends

from src.UserManagement.models import User
from src.core.security.permissions import has_role, has_permission