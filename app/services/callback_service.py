import time
from typing import Any

import httpx

from app.config import settings
from app.utils.logger import get_logger

logger = get_logger(__name__)

MAX_RETRIES = 3
BASE_DELAY = 1  # seconds — backoff: 1s, 2s, 4s


class CallbackService:
    def send_result(self, payload: dict[str, Any]) -> dict[str, Any]:
        event_id = payload.get("event", {}).get("event_id")
        last_exc: Exception | None = None

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with httpx.Client(timeout=settings.callback_timeout_seconds) as client:
                    response = client.post(settings.callback_url, json=payload)
                    response.raise_for_status()

                logger.info(
                    "Callback delivered",
                    extra={
                        "event_id": event_id,
                        "extra_data": {
                            "status_code": response.status_code,
                            "callback_url": settings.callback_url,
                            "attempt": attempt,
                        },
                    },
                )
                return {
                    "status_code": response.status_code,
                    "response_text": response.text,
                }

            except (httpx.HTTPStatusError, httpx.RequestError) as exc:
                last_exc = exc
                if attempt < MAX_RETRIES:
                    delay = BASE_DELAY * (2 ** (attempt - 1))
                    logger.warning(
                        "Callback failed, retrying",
                        extra={
                            "event_id": event_id,
                            "extra_data": {
                                "attempt": attempt,
                                "next_retry_in": delay,
                                "error": str(exc),
                            },
                        },
                    )
                    time.sleep(delay)

        logger.error(
            "Callback failed after all retries",
            extra={
                "event_id": event_id,
                "extra_data": {
                    "attempts": MAX_RETRIES,
                    "error": str(last_exc),
                },
            },
        )
        raise last_exc
