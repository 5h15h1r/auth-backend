from app.auth.services.email_service import email_service
from starlette import status
from app.auth.schemas.request_schema import SendEmail
from app.auth.schemas.response_schema import EmailResponse
from app.opentelemetry.opentelemetry import otel_instrumentation

class NotificationService:

    @otel_instrumentation()
    def send_email(self, send_email_request: SendEmail): 
        email_message = email_service.create_email_message(message_text=send_email_request.message, sender_email=send_email_request.sender_email, 
                        recipient_email=send_email_request.recipient_email, subject=send_email_request.subject)
        email_service.send_email(message=email_message)

        return EmailResponse(
            status=status.HTTP_200_OK,
            message="Email sent successfully"
        )

notification_service = NotificationService()
