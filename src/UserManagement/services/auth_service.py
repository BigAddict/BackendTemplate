from sqlmodel import Session, select
from sqlalchemy.exc import SQLAlchemyError

from src.UserManagement.models import User, VerificationToken
from src.Exceptions.auth_exceptions import InvalidVerificationCode
from src.Exceptions.core_exceptions import SystemError
from src.core.security.auth import get_password_hash

async def get_verification_token(
        code: str,
        session: Session
) -> VerificationToken:
    """
    Get the verification token by code.
    """
    try:
        verification_token = session.exec(
            select(VerificationToken).where(VerificationToken.code == code)
        ).one_or_none()

        if not verification_token:
            raise InvalidVerificationCode()

        return verification_token
    except SQLAlchemyError as e:
        raise SystemError(message="An error occurred while processing your request.")
    except Exception as e:
        raise SystemError(message="An error occurred while processing your request.")

async def get_user_by_verification_token(
        code: str,
        session: Session
) -> User:
    """
    Get the user by verification token code.
    """
    try:
        verification_token = await get_verification_token(code, session)

        user = session.exec(
            select(User).where(User.id == verification_token.user_id)
        ).one_or_none()

        if not user:
            raise InvalidVerificationCode()

        return user
    except SQLAlchemyError as e:
        raise SystemError(message="An error occurred while processing your request.")
    except Exception as e:
        raise SystemError(message="An error occurred while processing your request.")

async def delete_verification_token(
        code: str,
        session: Session
) -> bool:
    """
    Delete the verification token by code.
    """
    try:
        verification_token = await get_verification_token(code, session)

        session.delete(verification_token)
        session.commit()

        return True
    except SQLAlchemyError as e:
        raise SystemError(message="An error occurred while processing your request.")
    except Exception as e:
        raise SystemError(message="An error occurred while processing your request.")

async def verify_email_code(
        code: str,
        session: Session
) -> bool:
    """
    Verify the email code.
    """
    try:
        verification_token = await get_verification_token(code, session)

        user = await get_user_by_verification_token(code, session)

        if not user:
            raise InvalidVerificationCode()

        user.is_verified = True
        user.is_active = True

        session.delete(verification_token)
        session.commit()

        return True
    except SQLAlchemyError as e:
        raise SystemError(message="An error occurred while processing your request.")
    except Exception as e:
        raise SystemError(message="An error occurred while processing your request.")
    
async def change_user_password(
    user: User,
    new_password,
    session: Session
) -> bool:
    try:
        user.password_hash = get_password_hash(new_password)
        session.add(user)
        session.commit()
        session.refresh(user)
        return True
    except SQLAlchemyError as e:
        raise SystemError("An error occurred, please try again later.")
    except Exception as e:
        raise SystemError()