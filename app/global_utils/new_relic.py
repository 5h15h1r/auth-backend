from enum import Enum
from typing import Union
import structlog
from functools import wraps
from fastapi import Request
from starlette.responses import JSONResponse
import json
from app.global_utils.token_dependency import token_dependency
from fastapi.security.http import HTTPAuthorizationCredentials


class LogLevel(Enum):
    """Predefined log levels for New Relic logging"""
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    DEBUG = "DEBUG"
    CRITICAL = "CRITICAL"

def get_log_level_from_status_code(status_code: Union[str, int]) -> LogLevel:
    """
    Convert HTTP status code to appropriate log level.
    
    Args:
        status_code (Union[str, int]): HTTP status code
    
    Returns:
        LogLevel: Corresponding log level
    
    Examples:
        >>> get_log_level_from_status_code('200')
        <LogLevel.INFO: 'INFO'>
        >>> get_log_level_from_status_code(404)
        <LogLevel.WARNING: 'WARNING'>
        >>> get_log_level_from_status_code('500')
        <LogLevel.ERROR: 'WARNING'>
    """
   
    try:
        status_code = int(str(status_code))
    except ValueError:
        return LogLevel.ERROR

   
    if 100 <= status_code < 200:
        return LogLevel.DEBUG.value
    elif 200 <= status_code < 300:
        return LogLevel.INFO.value
    elif 300 <= status_code < 400:
        return LogLevel.INFO.value
    elif status_code == 400:
        return LogLevel.WARNING.value
    elif 400 < status_code < 500:
        return LogLevel.WARNING.value
    elif 500 <= status_code < 600:
        return LogLevel.ERROR.value
    else:
        return LogLevel.CRITICAL.value
    
def rename_event_to_message(logger, method_name, event_dict):
    event_dict["message"] = event_dict.pop("event")
    return event_dict

structlog.configure(processors=[rename_event_to_message ,structlog.processors.JSONRenderer()])
logger = structlog.getLogger()

def log_msg(status, message, data={}):
    level = get_log_level_from_status_code(status)
    if level == "INFO":
        logger.info(str(message), data=data)
    elif level == "ERROR":
        logger.error(str(message), data=data)
    elif level == "DEBUG":
        logger.debug(str(message), data=data)
    elif level == "WARNING":
        logger.warning(str(message), data=data)
    elif level == "CRITICAL":
        logger.critical(str(message), data=data)

def filter_sensitive_data(data: dict) -> dict:
    """
    Filter out sensitive fields from the data dictionary.
    
    Args:
        data (dict): Input data dictionary
        
    Returns:
        dict: Filtered data dictionary with sensitive fields removed
    """
    sensitive_fields = ['password', 'new_password', 'confirm_password', 'old_password']
    if isinstance(data, dict):
        return {k: '[FILTERED]' if k.lower() in sensitive_fields else v for k, v in data.items()}
    return data


def parse_query_string_to_dict(query_string):
    """
    Parse a query string style string into a dictionary.
    Example: "status=500 message='Wrong file type'" -> {"status": "500", "message": "Wrong file type"}
    """
    result = {}
    if not query_string:
        return result
    
    # Split by spaces but preserve quoted strings
    parts = []
    current = ""
    in_quotes = False
    for char in query_string:
        if char == "'" or char == '"':
            in_quotes = not in_quotes
            current += char
        elif char == ' ' and not in_quotes:
            if current:
                parts.append(current)
            current = ""
        else:
            current += char
    if current:
        parts.append(current)
    
    # Parse each part
    for part in parts:
        if '=' in part:
            key, value = part.split('=', 1)
            # Remove quotes from value if present
            if (value.startswith("'") and value.endswith("'")) or (value.startswith('"') and value.endswith('"')):
                value = value[1:-1]
            result[key] = value
    return result


def new_relic_logger(func):
    """
    Decorator to log API requests and responses.
    
    This decorator will log:
    - Request method and path
    - Request parameters (query params for GET, body for POST)
    - Response status and message
    - Any exceptions that occur
    
    Usage:
        @app.post("/your-endpoint")
        @api_logger
        async def your_endpoint(request: Request):
            ...
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):

        request = None
        auth_token = None
        
        for arg in args:
            if isinstance(arg, Request):
                request = arg
            elif isinstance(arg, HTTPAuthorizationCredentials):
                auth_token = arg
        
        if not request and 'request' in kwargs:
            request = kwargs['request']
        if not auth_token and 'auth_token' in kwargs:
            auth_token = kwargs['auth_token']

        
        
        try:
            # Prepare request data based on method
            request_data = {}
            if request:
                if request.method == 'GET':
                    request_data = filter_sensitive_data(dict(request.query_params))
                # Get body for POST/PUT requests
                elif request.method in ['POST', 'PUT']:
                    try:
                        # First try to get JSON body
                        request_data = filter_sensitive_data(await request.json())
                    except:
                        try:
                            # If JSON fails, try form data
                            request_data = filter_sensitive_data(dict(await request.form()))
                        except:
                            # If both fail, try to get Pydantic models from kwargs
                            request_data = {}
                            for key, value in kwargs.items():
                                if hasattr(value, 'dict'):  # Check if it's a Pydantic model
                                    request_data[key] = filter_sensitive_data(value.dict())
                                elif not isinstance(value, (Request, HTTPAuthorizationCredentials)):
                                    request_data[key] = str(value)

            # Extract user info from auth token if present
            if auth_token:
                token_payload = token_dependency.decode_token(auth_token.credentials)
                company_id = token_payload['companyId']
                user_id = token_payload['userId']
            else:
                company_id = ""
                user_id = ""   
    
            response = await func(*args, **kwargs)
            
            response_data = {}
            status = "200"
            
            if isinstance(response, tuple):
                response_data, status_code = response
                status = str(status_code)
            else:
                response_data = response

            # Extract response data from JSONResponse or dict
            if isinstance(response_data, JSONResponse):
                response_dict = json.loads(response_data.body.decode())
            elif isinstance(response_data, dict):
                response_dict = response_data
            else:
                try:
                    # Try to parse string as JSON first
                    response_dict = json.loads(str(response_data))
                except json.JSONDecodeError:
                    # If not valid JSON, try to parse as query string
                    response_dict = parse_query_string_to_dict(str(response_data))
                    if not response_dict:
                        # If parsing fails, wrap in data field
                        response_dict = {"data": str(response_data)}

            # Get status and message from response
            status = str(response_dict.get("status", status))
            message = response_dict.get("message", "API call successful")
            
            # Log combined request and response data
            log_msg(
                status=status,
                message=message,
                data={
                    "url": str(request.url) if request else "Unknown",
                    "method": request.method,
                    "request": {
                        "params": request_data,
                        "company_id": company_id,
                        "user_id": user_id
                    },
                }
            )
            
            return response
            
        except Exception as e:
            # Log exception
            error_data = {
                "url": str(request.url) if request else "Unknown",
                "request": {
                    "params": request_data if 'request_data' in locals() else {},
                    "company_id": company_id,
                    "user_id": user_id,
                },
                "error": {
                    "message": str(e),
                    "type": type(e).__name__,
                }
            }
            
            log_msg(
                status="500",
                message=f"API Error: {str(e)}",
                data=error_data
            )
            raise e
            
            

    return wrapper

