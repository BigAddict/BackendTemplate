from sqlmodel import SQLModel, Session, select
from src.core.database import engine

from src.UserManagement.models import User, Role, Permission, RolePermissionLink, UserCredential, UserRoleLink

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def seed_roles_and_permissions():
    with Session(engine) as session:
        permissions = [
            {"name": "read_users", "description": "Can view users"},
            {"name": "edit_users", "description": "Can edit users"},
            {"name": "delete_users", "description": "Can delete users"},
        ]

        roles = [
            {"name": "Admin", "description": "System administrator"},
            {"name": "User", "description": "Regular user"},
        ]

        for perm in permissions:
            existing = session.exec(select(Permission).where(Permission.name == perm["name"])).first()
            if not existing:
                session.add(Permission(**perm))

        session.commit()

        all_permissions = session.exec(select(Permission)).all()
        permission_dict = {perm.name: perm for perm in all_permissions}

        for role in roles:
            existing_role = session.exec(select(Role).where(Role.name == role["name"])).first()
            if not existing_role:
                new_role = Role(name=role["name"], description=role["description"])
                if role["name"] == "Admin":
                    new_role.permissions = list(permission_dict.values())
                session.add(new_role)
                
        session.commit()

if __name__ == "__main__":
    create_db_and_tables()