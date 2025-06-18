import uvicorn as uvicorn
from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI, Request
from app.auth.routers.user import user_router_v1
from app.auth.routers.notifications import notication_router_v1
from app.logs.router.logger_router import log_router

from app.config.app_config import get_config
from app.opentelemetry.opentelemetry import configure_opentelemetry
import newrelic.agent
import logging

loggers_to_disable = [
    "uvicorn",          # General logs including shutdown/startup
    "uvicorn.error",    # Error-level logs
    "uvicorn.access"    # Access logs (every request log)
]

for logger_name in loggers_to_disable:
    logger = logging.getLogger(logger_name)
    logger.disabled = True

if get_config().APP_ENV == "PROD":
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    print("using new relic prod")
    newrelic.agent.initialize("newrelic.ini", environment="production")
    # configure_opentelemetry(app)
elif get_config().APP_ENV=="DEV":
    app = FastAPI()
    print("using new relic dev")
    newrelic.agent.initialize("newrelic.ini", environment="development")
elif get_config().APP_ENV=="":
    app = FastAPI()

origins = get_config().ALLOWED_ORIGINS
methods = get_config().ALLOWED_METHODS
headers = get_config().ALLOWED_HEADERS


app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=methods,
    allow_headers=headers,
)

app.include_router(user_router_v1)
app.include_router(notication_router_v1)
app.include_router(log_router)



@app.get("/")
async def root():
    newrelic.agent.ignore_transaction(flag=True)
    return "Welcome to mopid-auth Backend"


# app.include_router(assignment_router.router)

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8007, log_level="info")
