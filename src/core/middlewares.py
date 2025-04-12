from starlette.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from fastapi import FastAPI, Request

class DeviceTypeMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        device_type = request.headers.get('X-Device-Type').lower()
        if not device_type:
            return JSONResponse(
                status_code=400,
                content={"detail": "Device type header is missing"}
            )
        response = await call_next(request)
        return response