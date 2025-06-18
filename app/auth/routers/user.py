from fastapi import APIRouter, Request, Query
from app.auth.services.user_service import auth_service
from app.auth.schemas.request_schema import UserLogin, SocialLogin, ForgotPassword, ResetPassword, UserSignup, SendEmail, UpdateUser
from app.custom_api_routers import CustomAPIRouter
from app.auth.schemas.response_schema import LoginResponse, LogoutResponse, ResetPasswordResponse, SignupResponse, GetUserResponse, UpdateUserResponse, BulkUserResponse, OperationStatusResponse, LockUserStatusResponse
from fastapi import Depends
from fastapi.security.http import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.param_functions import Security
from typing import Optional, Union
from app.auth.constants.enums import SessionTypeEnum
from typing import List
from app.global_utils.new_relic import new_relic_logger
from app.db_session import request_auth_token

user_router_v1 = CustomAPIRouter(
    prefix='/api/v1.0', 
    tags=["Auth"]
)

# TODO - name router functions appropriately

#
@user_router_v1.post('/login')
@new_relic_logger
async def login(login_request: UserLogin, request: Request):
    response = auth_service.login(login_request=login_request, request=request)
    return response


@user_router_v1.post('/logout', response_model=LogoutResponse)
@new_relic_logger
async def logout(request: Request, auth_token: HTTPAuthorizationCredentials = Security(HTTPBearer())):
    request_auth_token.set(auth_token)
    response = auth_service.logout()
    return response

@user_router_v1.post('/social-login', response_model=LoginResponse)
@new_relic_logger
async def call(social_login_request: SocialLogin, request: Request):
    response = auth_service.social_login(social_login_request)
    return response

@user_router_v1.post('/forgot-password')
@new_relic_logger
async def forgot_password(forgot_password_request: ForgotPassword, request: Request):
    response = auth_service.forgot_password(forgot_password_request=forgot_password_request, request=request)
    return response

@user_router_v1.post('/reset-password', response_model=ResetPasswordResponse)
@new_relic_logger
async def reset_password(request: Request, request_password_request: ResetPassword, auth_token: HTTPAuthorizationCredentials = Security(HTTPBearer())):
    request_auth_token.set(auth_token)
    response = auth_service.reset_password(reset_password_request=request_password_request)
    return response

@user_router_v1.get('/verify-token')
@new_relic_logger
async def verify_token(request: Request, auth_token: HTTPAuthorizationCredentials = Security(HTTPBearer()), session_type: Optional[SessionTypeEnum] = None):
    request_auth_token.set(auth_token)
    response = auth_service.verify_token(session_type=session_type)
    return response 

@user_router_v1.post('/signup', response_model=SignupResponse)
@new_relic_logger
async def signup(signup_request: UserSignup, request: Request):
    response = auth_service.signup(signup_request=signup_request, request=request)
    return response

@user_router_v1.get('/company-user-roles')
@new_relic_logger
async def get_company_user_roles(request: Request, company_id: str, role: str):
    response = auth_service.get_company_user_roles(company_id=company_id, role=role)
    return response

@user_router_v1.get('/token')
@new_relic_logger
async def get_token(request: Request, session_uuid: str): 
    response = auth_service.get_token(session_uuid=session_uuid)
    return response

@user_router_v1.get('/user', response_model=GetUserResponse)
@new_relic_logger
async def get_user_details(request: Request, user_uuid: str = Query(default=None), mob_no: str = Query(default=None), email: str = Query(default=None)):
    response = auth_service.get_user(user_uuid=user_uuid, mob_no=mob_no, email=email)
    return response

@user_router_v1.put('/user', response_model=UpdateUserResponse)
@new_relic_logger
async def update_user(request: Request, update_user_request: UpdateUser):
    response = auth_service.update_user(update_user_request=update_user_request)
    return response

@user_router_v1.get('/bulk-users', response_model=BulkUserResponse)
@new_relic_logger
async def get_bulk_users(request: Request, user_ids: Optional[List[str]] = Query([]), company_id: Optional[str] = Query(default=None, title="id of company"), search_value: Optional[str] = Query(default=None, title="name to search")):
    if user_ids == ['None']:
        user_ids = None
    if search_value == "None":
        search_value = None
    response = auth_service.get_bulk_users(user_ids=user_ids, company_uuid=company_id, search_value=search_value)
    return response 