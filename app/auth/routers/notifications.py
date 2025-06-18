from app.auth.schemas.request_schema import SendEmail
from app.auth.schemas.response_schema import EmailResponse
from app.auth.services.notfication_service import notification_service
from app.custom_api_routers import CustomAPIRouter
from app.global_utils.new_relic import new_relic_logger

notication_router_v1 = CustomAPIRouter(
    prefix='/api/v1.0', 
    tags=["Notification"]
)


@notication_router_v1.post('/send-email', response_model=EmailResponse)
@new_relic_logger
def send_email(send_email_request: SendEmail):
    response = notification_service.send_email(send_email_request=send_email_request)
    return response