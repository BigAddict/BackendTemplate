from logging.handlers import RotatingFileHandler
from pydantic_settings import BaseSettings
from dotenv import load_dotenv
from typing import Literal
from pathlib import Path
import requests
import logging
import json
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
    logging_format: str = os.getenv("LOGGING_FORMAT")
    logging_file: str = os.getenv("LOGGING_FILE", "app.log")
    logging_enabled: bool = os.getenv("LOGGING_ENABLED")

    smtp_server: str = os.getenv("SMTP_SERVER")
    smtp_port: int = os.getenv("SMTP_PORT")
    smtp_username: str = os.getenv("SMTP_USERNAME")
    smtp_password: str = os.getenv("SMTP_PASSWORD")

def get_settings():
    return Setting()

app_settings = Setting()

class AppLogger:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            cls._instance = super(AppLogger, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(
            self,
            log_dir: str = "logs",
            log_file: str = app_settings.logging_file,
            max_bytes: int = 5 * 1024 * 1024,
            backup_count: int = 5
    ):
        if self._initialized:
            return

        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / log_file

        self.logger = logging.getLogger("app_logger")
        self.logger.setLevel(logging.INFO)
        self.logger.handlers = []

        file_handler = RotatingFileHandler(
            self.log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(self._get_json_formatter())
        self.logger.addHandler(file_handler)

        self._initialized = True

    def _get_json_formatter(self) -> logging.Formatter:
        class JsonFormatter(logging.Formatter):
            def format(self, record):
                log_record = {
                    "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S"),
                    "level": record.levelname,
                    "message": record.getMessage(),
                    "module": record.module,
                    "function": record.funcName,
                    "line": record.lineno
                }
                return json.dumps(log_record)
        return JsonFormatter()

    LEVEL = Literal['debug', 'info', 'warning', 'error', 'critical']

    def log_message(self, level: LEVEL, message: str):
        log_method = getattr(self.logger, level.lower(), self.logger.warning)
        log_method(message)

logger_instance = AppLogger()

# Expose log_message function
def log_message(level: AppLogger.LEVEL, message: str):
    logger_instance.log_message(level, message)
        
def is_online() -> bool:
    url = "https://google.com/"
    request = requests.get(url)
    if request.ok:
        return True
    else:
        return False