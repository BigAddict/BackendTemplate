from sqlmodel import SQLModel, create_engine, Session

from src.core.config import get_settings

settings = get_settings()

DATABASE_URL = settings.db_url
engine = create_engine(DATABASE_URL, echo=True)

def get_session():
    with Session(engine) as session:
        yield session