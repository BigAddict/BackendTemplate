from typing import List

from src.UserManagement.models import User

def get_user_roles(user: User) -> List[str]:
    return [role.name for role in user.roles]

def get_user_permissions(user: User) -> List[str]:
    perms = set()
    for role in user.roles:
        perms.update(p.name for p in role.permissions)
    return list(perms)

def has_role(user: User, role: str) -> bool:
    return role in get_user_roles(user)

def has_permission(user: User, perm: str) -> bool:
    return perm in get_user_permissions(user)