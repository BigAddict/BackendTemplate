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
    code = int(generate_verification_code())
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

async def send_verification_email(user_id: int, email: str, base_url: str) -> Tuple:
    message = EmailMessage()
    message["From"] = settings.smtp_username
    message["To"] = email
    message["Subject"] = "Verify Your Email"
    code, expires = await create_verification_code(user_id)
    verification_url = f"{base_url}/user/verify-email?token={code}"
    message.set_content(f"Your verification code is: {code}. You can also use the url below to verifiy your email. {verification_url} It expires at {expires.strftime('%Y-%m-%d %H:%M:%S UTC')}.")

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
    
async def send_password_reset_email(user_id: int, email: str) -> Tuple:
    message = EmailMessage()
    message["From"] = settings.smtp_username
    message["To"] = email
    message["Subject"] = "Verify Your Email"
    code, expires = await create_verification_code(user_id)
    email_content = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>You requested a password reset for your account.</p>
            <p>Your one-time password (OTP) is: <strong>{code}</strong></p>
            <p>This code will expire at {expires.strftime('%Y-%m-%d %H:%M:%S UTC')}.</p>
            <p>If you didn't request this, please ignore this email.</p>
        </body>
    </html>
    """
    message.set_content(email_content)
    message.set_type("text/html")

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