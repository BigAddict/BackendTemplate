from starlette.authentication import AuthCredentials, UnauthenticatedUser, AuthenticationBackend
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from datetime import datetime, timezone, timedelta
from starlette.requests import HTTPConnection
from fastapi.responses import JSONResponse
from fastapi import HTTPException, Request, status
from passlib.context import CryptContext
from typing import Optional
from sqlmodel import Session, select
from jose import jwt

from src.UserManagement.models import User, UserCredential
from src.UserManagement.schemas import TokenResponse
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
    
async def get_current_user(request: Request, session: Session|None = None) -> Optional[User]:
    try:
        if session is None:
            session = next(get_session())

        device_type = await get_device_type(request)
        if device_type == "web":
            token = request.cookies.get("access_token")
        else:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                raise HTTPException(status_code=401, detail="Missing or Invalid token")
            token = auth_header.replace("Bearer ", "")
        
        if not token:
            raise HTTPException(status_code=401, detail="Please login to continue!")
        
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
    finally:
        if session and session.is_active:
            session.close()
    
async def get_current_admin_user(request: Request) -> Optional[User]:
    user = await get_current_user(request)

    # Check if user is superuser
    if not user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={'error': 'User is not Admin'}
        )
    return user
    
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
        
async def get_token(data, db: Session):
    user = db.exec(select(User).where(User.email == data.username)).one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "User not found!"},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={'error': "Invalid Credentials"},
            headers={"WWW-Authenticate": "Bearer"}
        )

async def _verify_user_access(user: User):
    if not user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Your account is not verified, please check your email"},
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "Your account is not active, please contact support"},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
async def _get_user_token(user: User, refresh_token: str|None = None):
    payload = {
        "user_id": user.id,
        "email": user.email,
        "username": user.username
    }

    access_token_expires = timedelta(minutes=settings.access_token_expire_minutes)
    access_token = await create_access_token(payload, access_token_expires)
    if not refresh_token:
        refresh_token = await create_refresh_token(payload)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "expires_in": access_token_expires.total_seconds()
    }

async def get_refresh_token(token, db: Session):
    payload = await get_token_payload(token)
    user_id = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={'error': 'Invalid refresh token'},
            headers={"WWW-Authenticate": "Bearer"}
        )
    user = db.exec(select(User).where(User.id == user_id)).one_or_none()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={'error': 'User not found'},
            headers={"WWW-Authenticate": "Bearer"}
        )
    await _verify_user_access(user)
    user_token = await _get_user_token(user)
    return TokenResponse(**user_token)

async def get_token(data, db: Session):
    user = db.exec(select(User).where(User.email == data.username)).one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={'error': 'User not found'},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    if not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={'error': 'Invalid Credentials'},
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    await _verify_user_access(user)

    user_token = await _get_user_token(user)

    if not user_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={'error': 'Invalid Credentials'},
            headers={"WWW-Authenticate": "Bearer"}
        )
    return TokenResponse(**user_token)