from typing import List
from pydantic_settings import BaseSettings
import os
from pathlib import Path

config_dir = Path(__file__).resolve().parent


class Configurations(BaseSettings):
    DB_NAME: str
    DB_HOST: str
    DB_USER: str
    DB_PASSWORD: str
    PRIVATE_KEY: str
    PUBLIC_KEY: str
    JWT_ALGORITHM: str
    ALLOWED_ORIGINS: List[str] = ["*"]
    ALLOWED_METHODS: List[str] = ["*"]
    ALLOWED_HEADERS: List[str] = ["*"]
    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    SENDER_EMAIL: str
    TOKEN_EXPIRY_HOURS: int
    CLIENT_SECRET_FILE: str
    SENDGRID_API_KEY: str
    FRONTEND_BASE_URL: str
    APP_ENV: str

    class Config:
        env_file = os.path.join(config_dir, ".env")
        allow_extra = True


def get_config() -> Configurations:
    if os.getenv("APP_ENV", None) == "DEV":
        return Configurations(_env_file=os.path.join(config_dir, ".env.dev"))
    elif os.getenv("APP_ENV", None) == "PROD":
        return Configurations(_env_file=os.path.join(config_dir, ".env.prod"))
    else:
        return Configurations(_env_file=os.path.join(config_dir, ".env"))


def get_env():
    return os.getenv("APP_ENV", "DEFAULT")
