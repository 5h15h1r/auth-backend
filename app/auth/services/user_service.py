from fastapi.exceptions import HTTPException
from app.auth.daos.user_dao import auth_dao
from app.depenencies.token_dependencies import signJWT
from app.auth.schemas.response_schema import (
    LoginResponse,
    UserToken,
    LogoutResponse,
    ForgotPasswordResponse,
    ResetPasswordResponse,
    VerifyTokenResponse,
    SignupResponse,
    UUIDResponse,
    UserRoleCount,
    UserRoleCountList,
    UserRoleCountResponse,
    TokenResponse,
    UserInfo,
    GetUserResponse,
    UpdateUserResponse,
    BulkUserResponse,
)
from passlib.hash import bcrypt
from app.auth.schemas.request_schema import (
    SocialLogin,
    ForgotPassword,
    ResetPassword,
    UserSignup,
    UpdateUser,
)
import requests
from app.auth.services.token_service import token_service
from ua_parser import user_agent_parser
from app.auth.constants.enums import SessionTypeEnum, LoginEvents
from app.auth.services.token_service import token_service
from app.auth.constants.enums import ProviderEnum, UserRoleEnum, UserSignupSourceEnum
from google.auth.exceptions import InvalidValue
from google.oauth2 import id_token
from app.config.app_config import get_config
from app.auth.helpers.user_helper import user_helper
from app.auth.constants.constants import TokenConstants
import datetime
from datetime import timezone
from app.auth.services.email_service import email_service
from app.auth.constants.constants import URLConstants
from app.db_session import request_auth_token
from starlette import status
from app.global_utils.utils import get_uuid4
from typing import List
from app.opentelemetry.opentelemetry import otel_instrumentation
from app.global_utils.utils import validate_password_rules
from zxcvbn import zxcvbn


class AuthService:

    @otel_instrumentation()
    def login(self, login_request, request):
        """
        Perform user login and return the login response.

        Parameters
        ----------
        login_request : LoginRequest
            A LoginRequest object containing the email and password for authentication.

        Returns
        -------
        LoginResponse
            A LoginResponse object representing the login response.

        Raises
        ------
        HTTPException
            If the password is invalid (status_code=401)

        """

        

        googleRefreshToken = ""
        if login_request.provider == ProviderEnum.GOOGLE:
            user_info = self.get_google_user_info(token=login_request.token)
            email = user_info["email"]
        else:
            email = login_request.email
        email = email.strip()
        user = auth_dao.get_user(email=email)
        if not user["is_active"]:
            raise HTTPException(status_code=404, detail="User account not active")
        user_id = user["uuid"]
        attempts = auth_dao.get_login_attempts(user_id)
        print('#############LOGIN ATTEMPTS###########',attempts)
        if attempts == 3:
            raise HTTPException(
                status_code=423,
                detail="Your account is locked. Please proceed with the password reset to regain access."
            )
        
        storedPassword = user["hashed_password"]
        isValid = True

        if login_request.provider == ProviderEnum.LOCAL:
            isValid = bcrypt.verify(login_request.password, storedPassword)

        if not isValid:
            auth_dao.log_login_attempts(user_id, LoginEvents.LOGIN_FAILED)
            raise HTTPException(status_code=401, detail="Invalid Password")
        
        auth_dao.log_login_attempts(user_id, LoginEvents.LOGIN_SUCCESS)
        client_ip = request.client.host
        user_agent_string = request.headers.get("User-Agent")
        parsed_user_agent = user_agent_parser.Parse(user_agent_string)

        token, session_uuid = token_service.encode_jwt(
            user=user,
            session_type=SessionTypeEnum.LOGIN,
            parsed_user_agent=parsed_user_agent,
            ip_address=client_ip,
            googleRefreshToken=googleRefreshToken,
        )
        userToken = UserToken(access_token=token)
        return LoginResponse(status=200, data=userToken)

    @otel_instrumentation()
    def get_google_user_info(self, token: str):
        try:
            headers = {"Authorization": "Bearer " + token}
            response = requests.get(
                "https://www.googleapis.com/oauth2/v3/userinfo", headers=headers
            )
            response = response.json()

            return {
                "email": response["email"],
            }
        except Exception:
            raise HTTPException(
                status_code=500, detail="Error fetching user info from google token"
            )

    @otel_instrumentation()
    def logout(self):
        """
        Perform user logout and return the logout response.

        Parameters
        ----------
        sessionId : str
            UUID of the session.

        Returns
        -------
        LogoutResponse
            A LogoutResponse object representing the logout response.

        """
        # TODO - decode token, get session_id
        auth_token = request_auth_token.get()
        user_info = token_service.decodeJWT(token=auth_token.credentials)
        user_helper.close_session(user_info[TokenConstants.SESSION_ID])

        return LogoutResponse(status=204, message="user logged out successfully")

    @otel_instrumentation()
    def social_login(self, social_login_request: SocialLogin):
        """
        Perform social login using the provided google authorization token.

        Parameters
        ----------
        social_login_request : SocialLogin
            The `SocialLogin` object containing the token for social login.

        Returns
        -------
        LoginResponse
            The login response containing the access token in a `UserToken` object.

        Raises
        ------
        HTTPException
            If there is an error during the social login process or if the user is not found.

        """
        headers = {"Authorization": "Bearer " + social_login_request.token}

        # TODO - use google.oauth2.id_token.verify_oauth2_token for token verification
        # TODO- raise exception if response doesn't match request email

        response = requests.post(
            "https://www.googleapis.com/oauth2/v3/userinfo", headers=headers
        )
        response.raise_for_status()

        response = response.json()
        email = response["email"]

        user = auth_dao.get_user(email=email)

        role = auth_dao.get_role(user["role_id"])
        userName = user["first_name"] + user["last_name"]
        sessionId, sessionCreateTimestamp, sessionExpiry = auth_dao.create_user_session(
            user["id"]
        )
        sessionCreateTimestamp = sessionCreateTimestamp.timestamp()
        sessionExpiry = sessionExpiry.timestamp()

        # userCompany = auth_dao.get_user_company(user['uuid'])
        company_uuid = user["company_uuid"]
        if company_uuid == None:
            company_uuid = ""
        token = signJWT(
            user["uuid"],
            userName,
            user["email"],
            role["name"],
            sessionExpiry,
            sessionCreateTimestamp,
            sessionId,
            "",
            company_uuid,
            user["profile_image_url"],
        )
        userToken = UserToken(access_token=token)
        return LoginResponse(status=200, data=userToken)

    @otel_instrumentation()
    def forgot_password(self, forgot_password_request: ForgotPassword, request):
        """
        Sends a password reset email to the user.

        Parameters
        ----------
        forgot_password_request : ForgotPasswordRequest
            The request containing user's email for password reset.
        request : HttpRequest
            The HTTP request object.

        Returns
        -------
        ForgotPasswordResponse
            Response indicating the status of the email sending operation.
        """

        user = auth_dao.get_user(email=forgot_password_request.email, reset_flag=True)
        if not user["is_active"]:
            raise HTTPException(status_code=404, detail="user account not active")
        sender_email = get_config().SENDER_EMAIL
        recipient_email = forgot_password_request.email

        client_ip = user_helper.get_client_ip(request=request)
        parsed_user_agent = user_helper.get_parsed_user_agent(request=request)

        token, session_uuid = token_service.encode_jwt(
            user=user,
            session_type=SessionTypeEnum.REFRESH,
            parsed_user_agent=parsed_user_agent,
            ip_address=client_ip,
            googleRefreshToken="",
        )

        reset_link = get_config().FRONTEND_BASE_URL + URLConstants.RESET_PASSWORD_URL.format(
            session_uuid, token
        )

        subject = "Password Reset Link"
        template_data = {
            "reset_link": reset_link
        }
        
        message = email_service.create_email_message(
            template_name="reset_password_email.html",
            template_data=template_data,
            sender_email=sender_email,
            recipient_email=recipient_email,
            subject=subject,
        )
        
        email_service.send_email(message=message)
        print(message)
        return ForgotPasswordResponse(status=204, message="Email sent successfully")

    @otel_instrumentation()
    def reset_password(self, reset_password_request: ResetPassword):
        """
        Reset the password for a user.

        Parameters
        ----------
        reset_password_request : ResetPasswordRequest
            Request object containing the reset password details.

        Returns
        -------
        ResetPasswordResponse
            Response object indicating the result of the password reset.
        """
        auth_token = request_auth_token.get()

        user_info = token_service.decodeJWT(token=auth_token.credentials)
        user = auth_dao.get_user(user_uuid=user_info[TokenConstants.USER_ID])

        if user.empty:
            raise HTTPException(status_code=404, detail="No user found")
        
        auth_dao.log_login_attempts(user["uuid"], LoginEvents.RESET_SUCCESS)
        
        password_errors = validate_password_rules(reset_password_request.password)
        if password_errors:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                                           detail=", ".join(password_errors)
                                           )
        
        result = zxcvbn(reset_password_request.password)
        score = result['score']
        if score < 3:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, 
                                           detail="The password provided is too weak or too generic. Please choose a stronger, unique password.")
        
        self.verify_token(session_type=SessionTypeEnum.REFRESH)


        storedPassword = user["hashed_password"]
        isValid = (
            bcrypt.verify(reset_password_request.password, storedPassword)
            if storedPassword != ""
            else False
        )
        if isValid:
            raise HTTPException(status_code=403, detail="This password has been used previously. Please choose a new and unique password.")

        hashed_password = bcrypt.hash(reset_password_request.password)

        auth_dao.update_user_password(user_uuid=user["uuid"], password=hashed_password)
        auth_dao.update_user(user_uuid=user["uuid"] ,status="active")

        user_helper.close_session(user_info[TokenConstants.SESSION_ID])

        return ResetPasswordResponse(status=204, message="Password reset successful")

    @otel_instrumentation()
    def verify_token(self, session_type: SessionTypeEnum = None):
        """
        Verifies the validity of a token and checks for expiration.

        Parameters:
        - token (str): The token to be verified.

        Returns:
        - VerifyTokenResponse: A response indicating the status of token verification.

        Raises:
        - HTTPException: If the token is invalid or has expired.
        """
        auth_token = request_auth_token.get()
        
        user_info = token_service.decodeJWT(token=auth_token.credentials)
        
        # user = auth_dao.get_user(user_uuid=user_info[TokenConstants.USER_ID])
        
        if user_info == {}:
            raise HTTPException(status_code=401, detail="Invalid Token")

        user_session = auth_dao.get_user_session(user_info["sessionId"])

        if session_type is not None and user_session.session_type != session_type:
            raise HTTPException(status_code=401, detail="Inavlid session type")

        expiry = user_session.expiry

        current_timestamp = datetime.datetime.now(timezone.utc).replace(microsecond=0, tzinfo=None)
        if current_timestamp >= expiry:
            auth_dao.update_logout_timestamp(sessionId=user_info["sessionId"])
            raise HTTPException(status_code=401, detail="Token expired")

        return VerifyTokenResponse(status=204, message="Token verified")

    @otel_instrumentation()
    def signup(self, signup_request: UserSignup, request):
        """
        Register a new user.

        Parameters
        ----------
        signup_request : UserSignup
            The user registration request object containing user details.
        request : HttpRequest
            The incoming HTTP request object.

        Returns
        -------
        SignupResponse
            A response indicating the result of user registration.

        Raises
        ------
        HTTPException
            If a user with the same email already exists, a 409 Conflict status code is returned.
        """
        if auth_dao.user_exists(email=signup_request.email):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="email or mobile number already taken",
            )

        user_uuid = get_uuid4()

        hashed_password = user_helper.create_hashed_password(password="Welcome@123")

        if signup_request.signup_source == UserSignupSourceEnum.INVITE:
            is_active = 1
        elif signup_request.signup_source == UserSignupSourceEnum.ONBOARDING:
            is_active = 0

        role_id=signup_request.role_id

        #TODO: role assigning logic needs to be modified when RBAC is in development

        if role_id in (1,3,4):
            role = "admin"
        else:
            role = "user"

        user_uuid = auth_dao.create_user(
            user_uuid=user_uuid,
            first_name=signup_request.first_name,
            last_name=signup_request.last_name,
            email=signup_request.email,
            designation=signup_request.designation,
            mob_no=signup_request.mob_no,
            hashed_password=hashed_password,
            company_uuid=signup_request.company_uuid,
            role_id=signup_request.role_id,
            role=role,
            mob_no_2=signup_request.mob_no_2,
            is_active=is_active,
        )
        # Disabled forgot password temporarily
        # if signup_request.signup_source == UserSignupSourceEnum.INVITE:
        if False:
            forgot_password_request = ForgotPassword(email=signup_request.email)
            self.forgot_password(
                forgot_password_request=forgot_password_request, request=request
            )

        return SignupResponse(
            status=200, message="User created", data=UUIDResponse(uuid=user_uuid)
        )

    @otel_instrumentation()
    def get_company_user_roles(self, company_id, role):

        company_user_roles_df = auth_dao.get_company_user_roles(company_id=company_id)

        user_role_count_objects = [
            UserRoleCount(user_role=row["user_role"], count=row["count"])
            for _, row in company_user_roles_df.iterrows()
        ]

        user_role_count_list = UserRoleCountList(
            user_roles_count=user_role_count_objects
        )

        return UserRoleCountResponse(
            status=status.HTTP_200_OK, data=user_role_count_list
        )

    @otel_instrumentation()
    def get_token(self, session_uuid: str):
        token = auth_dao.get_token_from_session_uuid(session_uuid=session_uuid)

        return TokenResponse(
            status=status.HTTP_200_OK, data=UserToken(access_token=token)
        )

    @otel_instrumentation()
    def get_user(self, user_uuid: str, mob_no: str, email: str):
        user = auth_dao.get_user(user_uuid=user_uuid, mob_no=mob_no, email=email)
        user_role = auth_dao.get_role(roleId=user["role_id"])

        if user_role["name"] == UserRoleEnum.RECRUITER and not user["is_active"]:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="user account not active"
            )

        return GetUserResponse(
            status=status.HTTP_200_OK,
            data=UserInfo(
                user_uuid=user["uuid"],
                mob_no=user["mob_no"],
                email=user["email"],
                name=user["first_name"] + " " + user["last_name"],
            ),
        )

    @otel_instrumentation()
    def update_user(self, update_user_request: UpdateUser):
        """
        update user
        return response
        """

        affected_rows = auth_dao.update_user(
            user_uuid=update_user_request.user_uuid,
            first_name=update_user_request.first_name,
            last_name=update_user_request.last_name,
            email=update_user_request.email,
            mob_no=update_user_request.mob_no,
            designation=update_user_request.designation,
            role_id=update_user_request.role_id,
            status=update_user_request.status,
            is_active=update_user_request.is_active,
        )

        if not affected_rows:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Given user_uuid doesn't exist. Update unsuccessful",
            )

        if affected_rows > 1:
            raise HTTPException(
                status_code=status.HTTP_424_FAILED_DEPENDENCY,
                detail="More than one rows updated",
            )

        return UpdateUserResponse(status=status.HTTP_200_OK, message="User updated")

    @otel_instrumentation()
    def get_bulk_users(self, user_ids: List[str], company_uuid: str, search_value: str):
        user_list = auth_dao.get_bulk_users(
            user_ids=user_ids, company_uuid=company_uuid, search_value=search_value
        )

        user_response_list = [
            UserInfo(
                user_uuid=user["uuid"],
                name=user["first_name"] + " " + user["last_name"],
                designation=user["designation"],
                role_id=user["role_id"],
                first_name=user["first_name"],
                last_name=user["last_name"],
                email=user["email"],
                mob_no=user["mob_no"],
                status=user["status"],
                is_active=user["is_active"],
            )
            for user in user_list
        ]

        return BulkUserResponse(status=status.HTTP_200_OK, data=user_response_list)


auth_service = AuthService()
