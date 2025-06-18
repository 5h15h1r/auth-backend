

class TokenConstants:
    ISSUE_TIME = "iat"
    EXPIRY_TIME = "expiry"
    USER_ID =  "userId"
    COMPANY_ID = "companyId"
    USER_EMAIL = "email"
    DISPLAY_NAME = "name"
    PROFILE_IMAGE = "profile"
    USER_ROLE = "role"
    USER_PERMISSIONS = "permissions"
    SESSION_ID = "sessionId"
    GOOGLE_REFRESH_TOKEN=  "googleRefreshToken"


class URLConstants: 
    RESET_PASSWORD_URL = "/reset/?session_id={}&token={}"
    GMAIL_API_URL = "https://www.googleapis.com/auth/gmail.send"