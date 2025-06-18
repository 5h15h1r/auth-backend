import base64
from email.mime.text import MIMEText
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from app.auth.constants.constants import URLConstants
from app.config.app_config import get_config
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from app.opentelemetry.opentelemetry import otel_instrumentation
import os
from jinja2 import Environment, FileSystemLoader

class EmailService:
    def __init__(self):
        self.template_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'templates')
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def send_html_email(self, sender_email, receiver_email, subject, message_text):
        try:
            # Initialize SendGrid client with API key
            # sg = SendGridAPIClient(get_config().SEND_GRID_API_KEY)
            sg = SendGridAPIClient(get_config().SENDGRID_API_KEY)

            # Create Mail object
            mail = Mail(
                from_email=sender_email,
                to_emails=receiver_email,
                subject=subject,
                html_content=message_text,
            )

            # Send email
            response = sg.send(mail)
            print(response)
            # Check response status code
            if response.status_code == 202:
                print(f"Email sent successfully to email = {receiver_email}")
                return True
            else:
                print(f"Failed to send email to {receiver_email}. Status code:{response.status_code}")
                return False
        except Exception as e:
            print(f"Error: {e} occurred for {receiver_email}")
            return False

    @otel_instrumentation()
    def create_email_message(self, template_name, template_data, sender_email, recipient_email, subject):
        template = self.env.get_template(template_name)
        html_content = template.render(**template_data)
        
        message = Mail(
            from_email=sender_email,
            to_emails=recipient_email,
            subject=subject,
            html_content=html_content
        )
        return message

    @otel_instrumentation()
    def send_email(self, message):
        try:
            email_service = self.get_email_service()
            email_service.send(message)
            print('Email sent successfully.')
        except Exception as e:
            print(f"Error: {e} ")
            if hasattr(e, 'body'):
                print(e.body)  # SendGrid returns error JSON here sometimes


    @otel_instrumentation()
    def get_email_service(self):
        sendgrid_api_key = get_config().SENDGRID_API_KEY
        email_service = SendGridAPIClient(sendgrid_api_key)
        return email_service

email_service = EmailService()
