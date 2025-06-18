from enum import Enum


class ProviderEnum(str, Enum):
    LOCAL = "local"
    GOOGLE = "google"

class SessionTypeEnum(str, Enum):
    LOGIN = "login"
    REFRESH = "refresh"

class JwtAlgorithmEnum(str, Enum):
    RS256 = "RS256"

class UserRoleEnum(str, Enum):
    RECRUITER = "recruiter"
    CANDIDATE = "candidate"

class UserSignupSourceEnum(str, Enum):
    ONBOARDING = "onboarding"
    INVITE = "invite"


class LoginEvents(str, Enum):
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    RESET_SUCCESS = "reset_success"