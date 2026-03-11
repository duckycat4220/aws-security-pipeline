import json
import boto3

from app.config import settings


def main() -> None:
    sqs = boto3.client(
        "sqs",
        region_name=settings.aws_region,
        aws_access_key_id=settings.aws_access_key_id,
        aws_secret_access_key=settings.aws_secret_access_key,
        endpoint_url=settings.aws_endpoint_url,
    )

    response = sqs.get_queue_url(QueueName=settings.sqs_queue_name)
    queue_url = response["QueueUrl"]

    messages = sqs.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=1,
        WaitTimeSeconds=1,
    )

    if "Messages" not in messages:
        print("No messages available")
        return

    message = messages["Messages"][0]
    print("Message received:")
    print(json.dumps(json.loads(message["Body"]), indent=2))


if __name__ == "__main__":
    main()