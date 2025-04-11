from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from sqlmodel import Session, select, delete
from fastapi import Depends
from typing import Tuple
import aiosmtplib
import secrets

from src.UserManagement.models import VerificationToken
from src.core.database import get_session
from src.core.config import get_settings

settings = get_settings()

def generate_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"

async def create_verification_code(user_id: int, minutes_valid: int = 10) -> Tuple[str, datetime]:
    code = generate_verification_code()
    try:
        session = next(get_session())
        expires = datetime.now(timezone.utc) + timedelta(minutes=minutes_valid)
        session.exec(delete(VerificationToken).where(VerificationToken.user_id == user_id))
        verification = VerificationToken(
            user_id=user_id,
            code=code,
            expires_at=expires
        )
        session.add(verification)
        session.commit()
        return code, expires
    except Exception as e:
        session.rollback()
        raise e
    finally:
        session.close()

async def send_verification_email(user_id: int, email: str) -> Tuple:
    message = EmailMessage()
    message["From"] = settings.smtp_username
    message["To"] = email
    message["Subject"] = "Verify Your Email"
    code, expires = await create_verification_code(user_id)
    message.set_content(f"Your verification code is: {code}. It expires at {expires.strftime('%Y-%m-%d %H:%M:%S UTC')}.")

    try:
        await aiosmtplib.send(
            message,
            hostname=settings.smtp_server,
            port=settings.smtp_port,
            username=settings.smtp_username,
            password=settings.smtp_password
        )
        return True, "Email sent successfully."
    except Exception as e:
        return False, str(e)