from ua_parser import user_agent_parser
from app.auth.daos.user_dao import auth_dao
from passlib.hash import bcrypt
from app.opentelemetry.opentelemetry import otel_instrumentation


class UserHelper:

    @otel_instrumentation()
    def get_client_ip(self, request):
        return request.client.host

    @otel_instrumentation()
    def get_parsed_user_agent(self, request):
        user_agent_string = request.headers.get("User-Agent")
        parsed_user_agent = user_agent_parser.Parse(user_agent_string)
        return parsed_user_agent

    @otel_instrumentation()
    def close_session(self, session_id):
        session = auth_dao.get_user_session(session_id)
        auth_dao.update_logout_timestamp(session_id)
        return

    @otel_instrumentation()
    def create_hashed_password(self, password):
        return bcrypt.hash(password)

user_helper = UserHelper()
