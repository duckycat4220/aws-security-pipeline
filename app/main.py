from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router as api_router
from app.config import settings
from app.services.sqs_service import SQSService
from app.utils.logger import get_logger, setup_logger

setup_logger(settings.log_level)
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(
        "Starting Security Intelligence Pipeline",
        extra={
            "extra_data": {
                "environment": settings.app_env,
                "log_level": settings.log_level,
            },
        },
    )
    sqs_service = SQSService()
    sqs_service.ensure_queues()
    yield
    logger.info("Shutting down Security Intelligence Pipeline")


app = FastAPI(
    title=settings.app_name,
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(api_router)


@app.get("/health")
def healthcheck() -> dict:
    return {
        "status": "ok",
        "app": settings.app_name,
        "environment": settings.app_env,
    }