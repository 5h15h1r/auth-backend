from app.auth.constants.constants import TokenConstants
from app.config.app_config import get_config
import jwt
from app.auth.daos.user_dao import auth_dao
from app.auth.constants.enums import JwtAlgorithmEnum
from app.opentelemetry.opentelemetry import otel_instrumentation


class TokenService:

    @otel_instrumentation()
    def encode_jwt(self, user, session_type, parsed_user_agent, ip_address, googleRefreshToken):
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
        PRIVATE_KEY = get_config().PRIVATE_KEY
        JWT_ALGORITHM = JwtAlgorithmEnum.RS256

        role = auth_dao.get_role(user['role_id'])['name'] if user['role_id'] else "" 
        userName = user['first_name'] + user['last_name']
        permissions = user['role']

        # TODO - store company_id in auth token at the time of encoding
        # userCompany = auth_dao.get_user_company(user['uuid'])
        googleRefreshToken = googleRefreshToken

        if parsed_user_agent['os']['family'] and parsed_user_agent['os']['major'] is not None:
            operating_system = parsed_user_agent['os']['family'] + ' ' + parsed_user_agent['os']['major']
        else:
            operating_system = "Unknown OS"

        if parsed_user_agent["user_agent"]["family"] and parsed_user_agent['user_agent']['major'] is not None:
            browser = parsed_user_agent['user_agent']['family'] + ' ' + parsed_user_agent['user_agent']['major']
        else:
            browser = "Unknown Browser"

        if parsed_user_agent["device"]["family"] and parsed_user_agent['device']['model'] is not None:
            device_brand = parsed_user_agent['device']['family']
            device_model = parsed_user_agent['device']['model']
        else:
            device_brand = "Unknown Device Brand"
            device_model = "Unknown Device Model"
        sessionId, issueTime, sessionExpiry = auth_dao.create_user_session(userId=user['id'], session_type=session_type, operating_system=operating_system, browser=browser, device_brand=device_brand, device_model=device_model, ip_address=ip_address)

        company_uuid = user['company_uuid']
        if company_uuid == None:
            company_uuid = ""

        payload={
            TokenConstants.USER_ID: user['uuid'],
            TokenConstants.DISPLAY_NAME: userName,
            TokenConstants.USER_EMAIL: user['email'],
            TokenConstants.USER_ROLE: role,
            TokenConstants.USER_PERMISSIONS: permissions,
            TokenConstants.EXPIRY_TIME: sessionExpiry,
            TokenConstants.ISSUE_TIME: issueTime, 
            TokenConstants.SESSION_ID: sessionId,
            TokenConstants.GOOGLE_REFRESH_TOKEN: googleRefreshToken,
            TokenConstants.COMPANY_ID: company_uuid,
            TokenConstants.PROFILE_IMAGE: user['profile_image_url']
        }
        print(PRIVATE_KEY, 'PRIVATE_KEY')
        token = jwt.encode(payload, PRIVATE_KEY, algorithm=JWT_ALGORITHM)

        auth_dao.update_user_session_with_token(session_uuid=sessionId, jwt_token=token)

        return token, sessionId

    @otel_instrumentation()
    def decodeJWT(self, token: str):
        """
        Decode a JWT token and return the decoded payload.

        Parameters
        ----------
        token : str
            The JWT token to decode.

        Returns
        -------
        dict
            The decoded payload of the JWT token.

        """
        try:
            PUBLIC_KEY = get_config().PUBLIC_KEY
            JWT_ALGORITHM = JwtAlgorithmEnum.RS256

            decode_token = jwt.decode(token, PUBLIC_KEY, algorithms=[JWT_ALGORITHM])
            return decode_token #if decode_token['expiry'] >= time.time() else None
        except:
            return {}

token_service = TokenService()
