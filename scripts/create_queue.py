from app.services.sqs_service import SQSService


def main() -> None:
    sqs_service = SQSService()
    queue_url = sqs_service.ensure_queues()
    print(f"Queues ready. Main queue URL: {queue_url}")


if __name__ == "__main__":
    main()
