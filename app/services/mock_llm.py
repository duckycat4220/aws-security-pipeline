from typing import Any

from app.schemas import SecurityEvent
from app.services.prompt_engineering import (
    SYSTEM_PROMPT,
    build_user_prompt,
    estimate_prompt_tokens,
    _fallback_explanation,
)
from app.utils.logger import get_logger

logger = get_logger(__name__)


class MockLLMService:
    """
    Mock that replicates the BedrockLLMService interface without consuming tokens.

    In mock mode:
    - Builds the real prompt (validating that prompt engineering works)
    - Logs the prompt and token estimation (useful for debugging and tuning)
    - Returns a rule-based explanation instead of calling Bedrock
    """

    def generate_explanation(
        self,
        event: SecurityEvent,
        classification_result: dict[str, Any],
    ) -> str:
        # Build the real prompt to validate prompt engineering logic
        user_prompt = build_user_prompt(event, classification_result)
        estimated_tokens = estimate_prompt_tokens(event, classification_result)

        logger.info(
            "Mock LLM — prompt built (no API call)",
            extra={
                "event_id": event.event_id,
                "extra_data": {
                    "estimated_input_tokens": estimated_tokens,
                    "system_prompt_preview": SYSTEM_PROMPT[:80] + "...",
                    "user_prompt": user_prompt,
                },
            },
        )

        # Deterministic response using the same fallback Bedrock would use
        explanation = _fallback_explanation(event, classification_result)

        logger.info(
            "Explanation generated (mock mode)",
            extra={
                "event_id": event.event_id,
                "extra_data": {"classification": classification_result["classification"]},
            },
        )

        return explanation
