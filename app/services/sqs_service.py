import json
import boto3

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)


class SQSService:
    def __init__(self) -> None:
        self.sqs = boto3.client(
            "sqs",
            region_name=settings.aws_region,
            aws_access_key_id=settings.aws_access_key_id,
            aws_secret_access_key=settings.aws_secret_access_key,
            endpoint_url=settings.aws_endpoint_url,
        )

        self.queue_name = settings.sqs_queue_name
        self.dlq_name = settings.sqs_dlq_name
        self.queue_url: str | None = None

    def ensure_queues(self) -> str:
        """Create DLQ and main queue with redrive policy. Idempotent."""
        # 1. Crear DLQ
        dlq_response = self.sqs.create_queue(QueueName=self.dlq_name)
        dlq_url = dlq_response["QueueUrl"]

        # 2. Obtener ARN de la DLQ
        dlq_attrs = self.sqs.get_queue_attributes(
            QueueUrl=dlq_url,
            AttributeNames=["QueueArn"],
        )
        dlq_arn = dlq_attrs["Attributes"]["QueueArn"]

        # 3. Crear cola principal con redrive policy
        redrive_policy = json.dumps({
            "deadLetterTargetArn": dlq_arn,
            "maxReceiveCount": str(settings.sqs_max_receive_count),
        })

        main_response = self.sqs.create_queue(
            QueueName=self.queue_name,
            Attributes={"RedrivePolicy": redrive_policy},
        )
        main_url = main_response["QueueUrl"]

        logger.info(
            "SQS queues ready",
            extra={
                "extra_data": {
                    "main_queue": self.queue_name,
                    "dlq": self.dlq_name,
                    "max_receive_count": settings.sqs_max_receive_count,
                }
            },
        )

        return main_url

    def get_queue_url(self) -> str:
        """Get URL from AWS/LocalStack and normalize URL for local access"""
        url = self.queue_url
        if url is not None:
            return url

        response = self.sqs.get_queue_url(QueueName=self.queue_name)
        raw_queue_url = str(response["QueueUrl"])

        new_url = raw_queue_url.replace(
            "http://localhost.localstack.cloud:4556",
            settings.aws_endpoint_url,
        ).replace(
            "http://sqs.us-east-1.localhost.localstack.cloud:4566",
            settings.aws_endpoint_url,
        )
        self.queue_url = new_url

        logger.info(
            f"SQS queue resolved: {self.queue_name}",
            extra={
                "extra_data": {
                    "raw_queue_url": raw_queue_url,
                    "normalized_queue_url": self.queue_url,
                }
            },
        )

        return new_url

    def send_message(self, message: dict) -> dict:
        """
        Envía un mensaje a la cola
        """
        queue_url = self.get_queue_url()

        response = self.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(message),
        )

        event_id = message.get("event_id")
        logger.info(
            "Event sent to SQS",
            extra={
                "event_id": event_id,
                "extra_data": {"message_id": response.get("MessageId")},
            },
        )

        return response