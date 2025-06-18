from pydantic_settings import BaseSettings
from typing import Optional
from app.auth.constants.enums import ProviderEnum, UserSignupSourceEnum

class UserLogin(BaseSettings):
    email: Optional[str]
    password: Optional[str]
    provider: ProviderEnum
    token: Optional[str]

class SocialLogin(BaseSettings):
    token: str

class ForgotPassword(BaseSettings):
    email: str

class ResetPassword(BaseSettings):
    password: str

class UserSignup(BaseSettings):
    first_name: str
    last_name: Optional[str] = None
    mob_no: Optional[str] = None
    mob_no_2: Optional[str] = None
    email: str
    designation: Optional[str] = None
    role_id: int
    company_uuid: str
    signup_source: UserSignupSourceEnum


class SendEmail(BaseSettings):
    sender_email: str
    recipient_email: str
    message: str
    subject: str

class UpdateUser(BaseSettings):
    user_uuid: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    mob_no: Optional[str] = None
    designation: Optional[str] = None
    role_id: Optional[int] = None
    status: Optional[str] = None
    is_active: Optional[int] = None