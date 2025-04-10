from starlette.middleware.authentication import AuthenticationMiddleware
from contextlib import asynccontextmanager
from fastapi import FastAPI, APIRouter

from src.core.config import AppLogging, get_settings
from src.core.security.auth import JWTAuth
from src.core.init_db import create_db_and_tables

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield

settings = get_settings()
app = FastAPI(title=settings.application_name,
              version=settings.application_version,
              docs_url="/docs",
              lifespan=lifespan)

api_router = APIRouter(prefix="/api/v1", tags=["Default"])

app.add_middleware(AuthenticationMiddleware, backend=JWTAuth())

@api_router.get("/healthcheck")
async def healthcheck():
    return {"status": "healthy"}

app.include_router(api_router)