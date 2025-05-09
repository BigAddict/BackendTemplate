from pydantic_settings import BaseSettings
from dotenv import load_dotenv
import requests
from pathlib import Path
import logging
import os

load_dotenv(Path(__file__).parent.parent.parent / ".env")

class Setting(BaseSettings):
    db_url: str = (os.getenv("DATABASE_URL"))

    secret_key: str = os.getenv("SECRET_KEY")
    algorithm: str = os.getenv("ALGORITHM")
    access_token_expire_minutes: int = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES")

    application_name: str = os.getenv("APP_NAME")
    application_version: str = os.getenv("APP_VERSION")
    application_description: str = os.getenv("APP_DESCRIPTION")
    logging_level: str = os.getenv("LOGGING_LEVEL")
    logging_format: str = os.getenv("LOGGING_FORMAT")
    logging_enabled: bool = os.getenv("LOGGING_ENABLED")

    smtp_server: str = os.getenv("SMTP_SERVER")
    smtp_port: int = os.getenv("SMTP_PORT")
    smtp_username: str = os.getenv("SMTP_USERNAME")
    smtp_password: str = os.getenv("SMTP_PASSWORD")

def get_settings():
    return Setting()

app_settings = Setting()

class AppLogging:
    def __init__(self):
        logging_level = app_settings.logging_level
        logging_format = app_settings.logging_format

        if app_settings.logging_enabled:
            logging.basicConfig(
                level=logging_level,
                format=logging_format,
            )
            logging.info("Logging is enabled")

    @staticmethod
    def log_message(level: str, message: str):
        if level.lower() == "info":
            return logging.info(message)
        elif level.lower() == "warning":
            return logging.warning(message)
        elif level.lower() == "error":
            return logging.error(message)
        elif level.lower() == "debug":
            return logging.debug(message)
        else:
            return logging.warning(f"Unsupported log level: {level}. Message: {message}")
        
def is_online() -> bool:
    url = "https://google.com/"
    request = requests.get(url)
    if request.ok:
        return True
    else:
        return False