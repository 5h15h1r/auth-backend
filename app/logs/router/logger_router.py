from app.logs.router.service.logger_service import logs_service
from app.custom_api_routers import CustomAPIRouter

log_router = CustomAPIRouter(prefix="/api/v1.0", tags=["logs"])


@log_router.get("/logs")
async def initialize_logging():
    response = logs_service.log_initialize()
    return response
