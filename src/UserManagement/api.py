from fastapi import APIRouter, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse, RedirectResponse, Response
from sqlmodel import Session, select
from urllib.parse import urlencode
import uuid

from src.core.security.auth import get_password_hash, get_current_user
from src.core.database import get_session
from src.core.config import get_settings