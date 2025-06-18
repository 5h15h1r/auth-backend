import pymysql
from app.config.app_config import get_config
from contextvars import ContextVar
from fastapi.security.http import HTTPAuthorizationCredentials


def db_connection():
    HOST = get_config().DB_HOST
    USER = get_config().DB_USER
    PASS = get_config().DB_PASSWORD
    DATABASE = get_config().DB_NAME
    db = pymysql.connect(host=HOST, user=USER, passwd=PASS, db=DATABASE)
    return db

request_auth_token: ContextVar[HTTPAuthorizationCredentials] = ContextVar('request_auth_token')