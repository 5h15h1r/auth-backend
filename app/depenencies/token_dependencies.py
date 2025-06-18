import jwt
import time
import os
import base64
from decouple import config
from app.config.app_config import get_config
from datetime import datetime, timedelta
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from app.auth.constants.constants import TokenConstants
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi import Depends, HTTPException


security = HTTPBearer()

def signJWT(userId, name, email, role, sessionExpiry, issueTime, sessionId, googleRefreshToken, companyId, profileImage):
    """
    Generate a JWT token based on the provided user information.

    Parameters
    ----------
    userId : str
        UUID of the user.
    name : str
        Display name of the user.
    email : str
        Email address of the user.
    role : str
        Role of the user.
    sessionExpiry : int
        Timestamp indicating the expiration time of the session.
    issueTime : int
        Timestamp indicating the issue time of the session.
    sessionId : str
        UUID of the session.
    googleRefreshToken : str
        Google refresh token associated with the user.
    companyId : str
        ID of the company associated with the user.
    profileImage : str
        URL of the user's profile image.

    Returns
    -------
    str
        The generated JWT token.

    """
    # PRIVATE_KEY = get_config().PRIVATE_KEY.replace("\\n", "\n")
    PRIVATE_KEY = get_config().PRIVATE_KEY
    # TODO - move JWT_ALGORITHM to enum.py
    JWT_ALGORITHM = get_config().JWT_ALGORITHM
    
    payload={
        TokenConstants.USER_ID: userId,
        TokenConstants.DISPLAY_NAME: name,
        TokenConstants.USER_EMAIL: email,
        TokenConstants.USER_ROLE: role,
        TokenConstants.EXPIRY_TIME: sessionExpiry,
        TokenConstants.ISSUE_TIME: issueTime, 
        TokenConstants.SESSION_ID: sessionId,
        TokenConstants.GOOGLE_REFRESH_TOKEN: googleRefreshToken,
        TokenConstants.COMPANY_ID: companyId,
        TokenConstants.PROFILE_IMAGE: profileImage
    }
    # TODO - add following columns to user_session table - created_at, updated_at, session_type (LOGIN/RERESH), ip_address, operating_system, browser, device_brand, device_model,
    # TODO - insert data in session table
    token = jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGORITHM)
    return token
