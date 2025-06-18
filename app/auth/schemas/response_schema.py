from pydantic_settings import BaseSettings
from pydantic import BaseModel
from typing import List, Optional

class UserToken(BaseSettings):
    access_token: str

class LoginResponse(BaseSettings):
    status: int
    data: UserToken

class LogoutResponse(BaseSettings):
    status: int
    message: str

class ForgotPasswordResponse(BaseSettings):
    status: int
    message: str

class ResetPasswordResponse(BaseSettings):
    status: int
    message: str
class VerifyTokenResponse(BaseSettings):
    status: int
    message: str

class UUIDResponse(BaseSettings):
    uuid: str
class SignupResponse(BaseSettings):
    status: int
    message: str
    data: UUIDResponse

class UserRoleCount(BaseModel):
    user_role: str
    count: int

class UserRoleCountList(BaseModel):
    user_roles_count: List[UserRoleCount]

class UserRoleCountResponse(BaseModel):
    status: int
    data: UserRoleCountList

class TokenResponse(BaseModel):
    status: int
    data: UserToken
    
class UserInfo(BaseModel):
    user_uuid: str
    mob_no: Optional[str] = None
    email: Optional[str] = None
    name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    designation: Optional[str] = None
    role_id: Optional[int] = None
    status: Optional[str] = None
    is_active: Optional[int] = None

class GetUserResponse(BaseModel):
    status: int
    data: UserInfo

class EmailResponse(BaseModel):
    status: int
    message: str

class UpdateUserResponse(BaseModel):
    status: int
    message: str

class BulkUserResponse(BaseModel):
    status: int
    data: List[UserInfo]

class OperationStatusResponse(BaseModel):
    status: int
    message: str


class LockUserStatusResponse(BaseModel):
    status: int
    message: str
    redirect: str

