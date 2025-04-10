from fastapi import FastAPI, APIRouter

from core.config import AppLogging, get_settings

settings = get_settings()

app = FastAPI(title=settings.application_name, version=settings.application_version, docs_url="/docs", redoc_url="/redoc")
api_router = APIRouter(prefix="/api/v1", tags=["api"])

@api_router.get("/healthcheck")
async def healthcheck():
    return {"status": "healthy"}

app.include_router(api_router)