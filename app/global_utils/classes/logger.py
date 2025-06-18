from loki_logger_handler.loki_logger_handler import LokiLoggerHandler, LoguruFormatter
from loguru import logger
from dotenv import load_dotenv
import sys
from app.config.app_config import get_config

# date format - YY:MM:DD
error_format = "%(asctime)s:%(levelname)s:%(name)s:%(funcName)s:%(message)s"
timing_format = "%(asctime)s:%(name)s:%(message)s"
error_file = "logs.log"
timing_file = "timing.log"


class Logger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Logger, cls).__new__(cls)
            load_dotenv()  # Ensure environment variables are loaded
            cls._instance._configure_logger()
        return cls._instance

    def _configure_logger(self):
        logger.remove()
        app_env = get_config().APP_ENV
        print("Current APP_ENV:", app_env)  # Print APP_ENV to verify

        if app_env == "PROD":
            # Loki Logger Handler configuration for production
            loki_handler = LokiLoggerHandler(
                url="http://35.200.129.168:3100/loki/api/v1/push",
                labels={"service": "mopid-auth-backend"},
                labelKeys={},
                timeout=10,
                defaultFormatter=LoguruFormatter(),
            )

            # Loguru logger configuration for production
            logger.configure(handlers=[{"sink": loki_handler, "serialize": True}])
        else:
            # Loguru logger configuration for development or other environments
            logger.add(
                sink=sys.stdout,
                level="DEBUG",
                format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <2}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>line number - {line}</cyan> - <level>{message}</level>",
            )

    def get_logger(self):
        return logger
