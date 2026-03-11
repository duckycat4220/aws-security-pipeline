import json

from botocore.exceptions import BotoCoreError, ClientError
from httpx import HTTPStatusError, RequestError

from app.config import settings
from app.schemas import SecurityEvent
from app.services.callback_service import CallbackService
from app.services.mock_llm import MockLLMService
from app.services.mock_sagemaker import MockSageMakerService
from app.services.prompt_engineering import BedrockLLMService, LLMService
from app.services.sqs_service import SQSService
from app.utils.logger import get_logger

logger = get_logger(__name__)


def _build_llm_service() -> LLMService:
    if settings.llm_mode == "bedrock":
        logger.info("Using Bedrock LLM service", extra={"extra_data": {"model_id": settings.bedrock_model_id}})
        return BedrockLLMService()
    logger.info("Using Mock LLM service")
    return MockLLMService()


class SQSWorker:
    def __init__(self) -> None:
        self.sqs_service = SQSService()
        self.classifier = MockSageMakerService()
        self.llm = _build_llm_service()
        self.callback_service = CallbackService()

    def process_one_message(self) -> None:
        try:
            queue_url = self.sqs_service.get_queue_url()
        except (ClientError, BotoCoreError) as exc:
            logger.error(
                "Failed to resolve SQS queue URL",
                extra={"extra_data": {"stage": "queue_resolution", "error": str(exc)}},
            )
            return

        try:
            response = self.sqs_service.sqs.receive_message(
                QueueUrl=queue_url,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=2,
                AttributeNames=["ApproximateReceiveCount"],
            )
        except (ClientError, BotoCoreError) as exc:
            logger.error(
                "Failed to receive messages from SQS",
                extra={"extra_data": {"stage": "sqs_receive", "error": str(exc)}},
            )
            return

        messages = response.get("Messages", [])
        if not messages:
            logger.debug("No messages available")
            return

        message = messages[0]
        receipt_handle = message["ReceiptHandle"]
        message_id = message.get("MessageId", "unknown")
        receive_count = int(message.get("Attributes", {}).get("ApproximateReceiveCount", 1))
        max_receives = settings.sqs_max_receive_count

        logger.info(
            "Message received by worker",
            extra={
                "extra_data": {
                    "message_id": message_id,
                    "receive_count": receive_count,
                },
            },
        )

        if receive_count >= max_receives:
            logger.warning(
                "Message at max receive count, next failure sends it to DLQ",
                extra={
                    "extra_data": {
                        "message_id": message_id,
                        "receive_count": receive_count,
                        "max_receive_count": max_receives,
                    }
                },
            )

        # 1. Deserialize and validate
        try:
            body = json.loads(message["Body"])
            event = SecurityEvent(**body)
        except (json.JSONDecodeError, ValueError, KeyError) as exc:
            logger.error(
                "Invalid message, deleting from queue",
                extra={
                    "extra_data": {
                        "stage": "deserialization",
                        "message_id": message_id,
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                },
            )
            self._delete_message(queue_url, receipt_handle)
            return

        # 2. Classify
        classification_result = self.classifier.classify_event(event)

        # 3. Generate explanation
        explanation = self.llm.generate_explanation(event, classification_result)

        # 4. Callback
        callback_payload = {
            "event": event.model_dump(mode="json"),
            "classification": classification_result["classification"],
            "risk_score": classification_result["risk_score"],
            "reason": explanation,
        }

        try:
            self.callback_service.send_result(callback_payload)
        except (HTTPStatusError, RequestError) as exc:
            retries_left = max_receives - receive_count
            log_method = logger.critical if retries_left <= 0 else logger.error
            log_method(
                "Callback failed, message will return to queue for retry"
                if retries_left > 0
                else "Callback failed, message will be moved to DLQ",
                extra={
                    "event_id": event.event_id,
                    "extra_data": {
                        "stage": "callback_delivery",
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                        "receive_count": receive_count,
                        "retries_left": retries_left,
                    },
                },
            )
            return

        # 5. Delete message only after successful callback
        self._delete_message(queue_url, receipt_handle)
        logger.info("Message processed and deleted", extra={"event_id": event.event_id})

    def _delete_message(self, queue_url: str, receipt_handle: str) -> None:
        try:
            self.sqs_service.sqs.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=receipt_handle,
            )
        except (ClientError, BotoCoreError) as exc:
            logger.error(
                "Failed to delete message from SQS",
                extra={
                    "extra_data": {
                        "stage": "message_deletion",
                        "error_type": type(exc).__name__,
                        "error": str(exc),
                    },
                },
            )


if __name__ == "__main__":
    worker = SQSWorker()
    worker.process_one_message()
