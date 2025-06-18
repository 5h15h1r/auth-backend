from enum import Enum
from urllib.request import Request

from fastapi.security.http import HTTPAuthorizationCredentials, HTTPBearer
from app.config.app_config import get_config
import jwt
from fastapi.exceptions import HTTPException
from datetime import datetime
from starlette import status
from fastapi.param_functions import Security


class TokenConstants:
    """
    Constants used in JSON web tokens.

    Attributes
    ----------
    ISSUE_TIME : str
        The key for the "issued at" time claim in a JSON web token.
    EXPIRY_TIME : str
        The key for the "expiry" time claim in a JSON web token.
    ENCODING_ALGORITHM : str
        The algorithm used for encoding JSON web tokens, such as "RS256".
    USER_ROLES : str
        The key for the "user roles" claim in a JSON web token.
    """
    ISSUE_TIME = "iat"
    EXPIRY_TIME = "expiry"
    ENCODING_ALGORITHM = "RS256"
    USER_ROLES = "roles"


class UserRoleEnum(str, Enum):
    """
        Enumeration of user roles.
    """
    ADMIN = 'admin'
    HIRING_MANAGER = 'hiring_manager'
    RECRUITER = 'recruiter'
    CLIENT = 'client'


class TokenDependency:
    """
    Dependency class for token utilities.
    Attributes
    ----------
    security : HTTPBearer
        The HTTPBearer security scheme used for authentication.
    """

    security = HTTPBearer()

    def decode_token(self, token):
        """
        Decode the provided JSON web token and return its payload.

        Parameters
        ----------
        token : str
            The JSON web token to be decoded.

        Returns
        -------
        dict
            The decoded payload of the JSON web token.

        Raises
        ------
        HTTPException
            If the token is expired or invalid, raises HTTPException with status code 401 UNAUTHORIZED.
        """
        try:
            payload = jwt.decode(token,
                                 key=get_config().PUBLIC_KEY,
                                 algorithms=[TokenConstants.ENCODING_ALGORITHM])
            return payload

        except jwt.ExpiredSignatureError:
            print("ExpiredSignatureError")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token")

        except jwt.InvalidTokenError:
            print("InvalidTokenError")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token")

    def validate_token(self, token: HTTPAuthorizationCredentials = Security(HTTPBearer())):
        """
        Validate the JSON web token.

        Parameters
        ----------
        token : HTTPAuthorizationCredentials, optional
            The JSON web token provided in the "Authorization" header (default is HTTPBearer()).

        Returns
        -------
        bool
            True if the token is valid and not expired, False otherwise.
        """
        cred = token.credentials
        payload = self.decode_token(cred)

        if payload[TokenConstants.ISSUE_TIME] <= datetime.utcnow().timestamp() < payload[TokenConstants.EXPIRY_TIME]:
            return True

        return False

    def is_admin(self, email, user_id):
        return 'admin' in email or user_id == "5a526476-8ba9-45bc-802f-2cbc31471850"

    def is_super_admin(self, user_id):
        return user_id == "5a526476-8ba9-45bc-802f-2cbc31471850"

    def role_admin_or_hiring_manger_or_recruiter(self, token: HTTPAuthorizationCredentials = Security(HTTPBearer())):
        """
        Check if the user has admin, hiring manager, or recruiter role.

        Parameters
        ----------
        token : HTTPAuthorizationCredentials, optional
            The JSON web token provided in the "Authorization" header (default is HTTPBearer()).

        Returns
        -------
        bool
            True if the user has one of the allowed roles, raises HTTPException with status code 401 UNAUTHORIZED otherwise.
        """
        payload = self.decode_token(token.credentials)
        if (
                UserRoleEnum.ADMIN.value not in payload.get(TokenConstants.USER_ROLES, []) and
                UserRoleEnum.HIRING_MANAGER.value not in payload.get(TokenConstants.USER_ROLES, []) and
                UserRoleEnum.RECRUITER.value not in payload.get(TokenConstants.USER_ROLES, [])
        ):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        return True


token_dependency = TokenDependency()
