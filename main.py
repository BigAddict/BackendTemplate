from starlette.middleware.authentication import AuthenticationMiddleware
from contextlib import asynccontextmanager
from fastapi_offline import FastAPIOffline
from fastapi import FastAPI, APIRouter

from src.core.init_db import create_db_and_tables, seed_roles_and_permissions
from src.UserManagement.routers import router as user_router
from src.core.middlewares import DeviceTypeMiddleware
from src.core.config import AppLogging, get_settings, is_online
from src.core.security.auth import JWTAuth

@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    seed_roles_and_permissions()
    yield

settings = get_settings()

if is_online:
    print("Running in online mode")
    app = FastAPI(title=settings.application_name,
                version=settings.application_version,
                docs_url="/docs",
                lifespan=lifespan)
else:
    print("Running in offline mode!")
    app = FastAPIOffline(
        title=settings.application_name,
        version=settings.application_version,
        lifespan=lifespan
    )

app.add_middleware(DeviceTypeMiddleware)
app.add_middleware(AuthenticationMiddleware, backend=JWTAuth())

api_router = APIRouter(prefix="/api/v1")

@app.get("/healthcheck", tags=["Default"])
async def healthcheck():
    return {"status": "healthy"}

api_router.include_router(user_router)

app.include_router(api_router)