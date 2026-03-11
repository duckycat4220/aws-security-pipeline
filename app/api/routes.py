from fastapi import APIRouter, HTTPException

from app.schemas import IngestResponse, SecurityEvent
from app.services.sqs_service import SQSService
from app.utils.logger import get_logger

logger = get_logger(__name__)
router = APIRouter()
sqs_service = SQSService()


@router.post("/events", response_model=IngestResponse)
def ingest_event(event: SecurityEvent) -> IngestResponse:
    logger.info(
        "Event received by API",
        extra={
            "event_id": event.event_id,
            "extra_data": {
                "event_type": event.event_type,
                "severity": event.severity,
            },
        },
    )

    try:
        sqs_service.send_message(event.model_dump(mode="json"))

        logger.info("Event enqueued to SQS", extra={"event_id": event.event_id})

        return IngestResponse(
            message="Event received and sent to SQS",
            event_id=event.event_id,
            queue_name=sqs_service.queue_name,
        )
    except Exception as exc:
        logger.error(
            "Failed to enqueue event",
            extra={
                "event_id": event.event_id,
                "extra_data": {"stage": "api_ingestion", "error": str(exc)},
            },
            exc_info=True,
        )
        raise HTTPException(
            status_code=500,
            detail=f"Failed to enqueue event: {str(exc)}",
        ) from exc