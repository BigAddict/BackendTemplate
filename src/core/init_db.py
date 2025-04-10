from sqlmodel import SQLModel
from src.core.database import engine

from src.UserManagement.models import User, Role, Permission, RolePermissionLink, UserCredential, UserRoleLink

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

if __name__ == "__main__":
    create_db_and_tables()