"""
Prompt engineering and AWS Bedrock integration service.

Token-efficiency design:
- Compact system prompt with precise instructions
- Structured user prompt sending only relevant fields (not the full event)
- Constrained output format to prevent verbose responses
- No few-shot examples (saves ~300 tokens per request)

Estimated consumption per invocation:
  system_prompt  ~150 tokens
  user_prompt    ~120 tokens (varies with reasons)
  output         ~100 tokens (capped by instruction)
  total          ~370 tokens (~$0.003 USD with Claude Haiku on Bedrock)
"""

import json
from typing import Any, Protocol

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.config import settings
from app.schemas import SecurityEvent
from app.utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# System prompt — compact, no redundancy, constrains output format
# ---------------------------------------------------------------------------
SYSTEM_PROMPT = (
    "Eres un analista de seguridad SOC. Recibirás un evento de seguridad ya "
    "clasificado por un modelo ML. Tu tarea es generar UNA explicación técnica "
    "concisa (máximo 3 oraciones) en español que justifique la clasificación.\n"
    "Reglas:\n"
    "- Responde SOLO con la explicación, sin encabezados ni metadata.\n"
    "- Menciona los indicadores técnicos específicos del evento.\n"
    "- Usa lenguaje profesional de SOC/CSIRT.\n"
    "- Si la clasificación es 'Evento Inusual', indica por qué no escala a amenaza."
)


def build_user_prompt(
    event: SecurityEvent,
    classification_result: dict[str, Any],
) -> str:
    """
    Build the user prompt with the minimum necessary data.

    Token-saving strategy:
    - Only relevant event fields are sent (not the full JSON)
    - Classifier reasons are capped at top 3
    - Null/empty fields are excluded
    """
    reasons = classification_result.get("reasons", [])[:3]

    # Only include fields with values to minimize tokens
    context_parts = [
        f"tipo: {event.event_type}",
        f"severidad: {event.severity}",
        f"criticidad_activo: {event.asset_criticality}",
        f"clasificación: {classification_result['classification']}",
        f"risk_score: {classification_result['risk_score']}/100",
    ]
    if event.source_ip:
        context_parts.append(f"ip_origen: {event.source_ip}")
    if event.user_id:
        context_parts.append(f"usuario: {event.user_id}")

    # Only truthy detail keys, avoid sending the entire dict
    if event.details:
        significant = {k: v for k, v in event.details.items() if v}
        if significant:
            context_parts.append(f"detalles: {json.dumps(significant, default=str)}")

    context = " | ".join(context_parts)
    reasons_text = "; ".join(reasons) if reasons else "sin indicadores significativos"

    return (
        f"Evento: {context}\n"
        f"Indicadores del clasificador: {reasons_text}\n"
        f"Genera la explicación técnica."
    )


def estimate_prompt_tokens(event: SecurityEvent, classification_result: dict[str, Any]) -> int:
    """
    Quick token estimation for cost monitoring.
    Rule of thumb: 1 token ~ 4 characters in Spanish.
    """
    user_prompt = build_user_prompt(event, classification_result)
    total_chars = len(SYSTEM_PROMPT) + len(user_prompt)
    return total_chars // 4


# ---------------------------------------------------------------------------
# Common protocol for LLM services (mock and real)
# ---------------------------------------------------------------------------
class LLMService(Protocol):
    def generate_explanation(
        self,
        event: SecurityEvent,
        classification_result: dict[str, Any],
    ) -> str: ...


# ---------------------------------------------------------------------------
# Bedrock service
# ---------------------------------------------------------------------------
class BedrockLLMService:
    """
    AWS Bedrock integration using the Claude Messages API.

    Cost configuration:
    - Model: Claude Haiku by default (most cost-effective for classification tasks)
    - max_tokens=200: caps response length for cost control
    - temperature=0.2: low creativity, consistent and deterministic responses
    - No streaming: reduces first-token latency for this use case
    """

    def __init__(self) -> None:
        self.client = boto3.client(
            "bedrock-runtime",
            region_name=settings.bedrock_region,
            endpoint_url=settings.aws_endpoint_url if settings.app_env == "development" else None,
        )
        self.model_id = settings.bedrock_model_id

    def generate_explanation(
        self,
        event: SecurityEvent,
        classification_result: dict[str, Any],
    ) -> str:
        user_prompt = build_user_prompt(event, classification_result)
        estimated_tokens = estimate_prompt_tokens(event, classification_result)

        logger.info(
            "Invoking Bedrock LLM",
            extra={
                "event_id": event.event_id,
                "extra_data": {
                    "model_id": self.model_id,
                    "estimated_input_tokens": estimated_tokens,
                },
            },
        )

        # Claude Messages API payload for Bedrock
        request_body = json.dumps({
            "anthropic_version": "bedrock-2023-10-25",
            "max_tokens": 200,
            "temperature": 0.2,
            "system": SYSTEM_PROMPT,
            "messages": [
                {"role": "user", "content": user_prompt},
            ],
        })

        try:
            response = self.client.invoke_model(
                modelId=self.model_id,
                contentType="application/json",
                accept="application/json",
                body=request_body,
            )

            response_body = json.loads(response["body"].read())
            explanation = response_body["content"][0]["text"]

            logger.info(
                "Bedrock response received",
                extra={
                    "event_id": event.event_id,
                    "extra_data": {
                        "input_tokens": response_body.get("usage", {}).get("input_tokens"),
                        "output_tokens": response_body.get("usage", {}).get("output_tokens"),
                    },
                },
            )

            return explanation

        except (ClientError, BotoCoreError) as exc:
            logger.error(
                "Bedrock invocation failed, falling back to rule-based explanation",
                extra={
                    "event_id": event.event_id,
                    "extra_data": {"error": str(exc)},
                },
            )
            # Fallback to rule-based explanation to keep the pipeline running
            return _fallback_explanation(event, classification_result)

        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            logger.error(
                "Unexpected Bedrock response format",
                extra={
                    "event_id": event.event_id,
                    "extra_data": {"error": str(exc)},
                },
            )
            return _fallback_explanation(event, classification_result)


def _fallback_explanation(
    event: SecurityEvent,
    classification_result: dict[str, Any],
) -> str:
    """Deterministic explanation used when Bedrock is unavailable."""
    classification = classification_result["classification"]
    risk_score = classification_result["risk_score"]
    reasons = classification_result.get("reasons", [])[:3]
    reasons_text = "; ".join(reasons) if reasons else "sin indicadores significativos"

    return (
        f"El evento fue clasificado como '{classification}' con un risk score de "
        f"{risk_score}/100. La decisión se basó en señales observadas en un evento "
        f"de tipo '{event.event_type}', severidad '{event.severity}' y criticidad "
        f"del activo '{event.asset_criticality}'. Indicadores principales: {reasons_text}."
    )
