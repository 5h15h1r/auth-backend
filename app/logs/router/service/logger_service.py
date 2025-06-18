from app.global_utils.classes.logger import Logger
from app.opentelemetry.opentelemetry import otel_instrumentation

logger_instance = Logger()

# Get the logger from the instance
logger = logger_instance.get_logger()


class Logs_Service:
    @otel_instrumentation()
    def log_initialize(self):
        logger.info("logging is initialised")
        return "logs are initialized"


logs_service = Logs_Service()
