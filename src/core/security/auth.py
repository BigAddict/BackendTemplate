from starlette.authentication import AuthCredentials, UnauthenticatedUser, AuthenticationBackend
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timezone, timedelta
from starlette.requests import HTTPConnection
from fastapi.responses import JSONResponse
from fastapi import HTTPException, Request, Depends
from passlib.context import CryptContext
from typing import Optional
from sqlmodel import Session, select
from jose import jwt

from src.UserManagement.models import User
from src.core.config import get_settings
from src.core.database import get_session

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/user/auth/token")

def verify_password(plain_password: str, hashed_password:str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

async def create_access_token(data: dict, expires:timedelta):
    payload = data.copy()
    expires_in = datetime.now(timezone.utc) + expires
    payload.update({"exp": expires_in})
    return jwt.encode(payload, settings.secret_key, algorithm=settings.algorithm)

async def create_refresh_token(data: dict):
    return jwt.encode(data, settings.secret_key, algorithm=settings.algorithm)

async def get_token_payload(token: str):
    try:
        payload = jwt.decode(token, settings.secret_key, algorithms=[settings.algorithm])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
async def get_device_type(request: Request) -> str:
    device_type = request.headers.get('X-Device-Type', "web").lower()
    if device_type == "mobile":
        return "mobile"
    elif device_type == "desktop":
        return "desktop"
    else:
        return "web"
    
async def get_current_user(request: Request, session: Session = Depends(get_session)) -> Optional[User]:
    try:
        device_type = await get_device_type(request)
        if device_type == "web":
            token = request.cookies.get("access_token")
        else:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="Missing or Invalid token")
            token = auth_header.replace("Bearer ", "")
        
        if not token:
            raise HTTPException(status_code=401, detail="No access token provided")
        
        payload = await get_token_payload(token)
        if not payload or not isinstance(payload, dict):
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        
        user = session.exec(select(User).where(User.id == user_id)).one_or_none()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")
        return user
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
class JWTAuth(AuthenticationBackend):
    async def authenticate(self, conn: HTTPConnection):
        try:
            user = await get_current_user(conn)
            if not user:
                return AuthCredentials(["unauthenticated"]), UnauthenticatedUser()
            elif not user.is_active or not user.is_verified:
                return AuthCredentials(["unauthenticated"]), UnauthenticatedUser()
            return AuthCredentials(["authenticated"]), user
        except HTTPException as e:
            return AuthCredentials(["unauthenticated"]), UnauthenticatedUser()
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))