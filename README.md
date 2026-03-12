# AWS Security Intelligence Pipeline

Automated security event processing pipeline that ingests alerts from detection systems, classifies threat severity using ML, generates analyst-ready explanations via LLM, and delivers enriched results back to SIEM platforms.

Built for SOC teams that need to reduce alert triage time by automating the initial classification and contextualization of security events.

## Architecture

```
                                        ┌──────────────┐
  Detection Systems ──► POST /events ──►│   SQS Queue   │
  (EDR, SIEM, IDS)      (FastAPI)       │  + DLQ retry  │
                                        └──────┬───────┘
                                               │
                                        ┌──────▼───────┐
                                        │    Worker     │
                                        │  ┌─────────┐  │
                                        │  │Classify  │  │  Mock SageMaker
                                        │  │(ML Model)│  │  (rule-based scoring)
                                        │  └────┬────┘  │
                                        │  ┌────▼────┐  │
                                        │  │Explain   │  │  Bedrock / Claude
                                        │  │(LLM)    │  │  (prompt-engineered)
                                        │  └────┬────┘  │
                                        └───────┼───────┘
                                                │
                                        ┌───────▼───────┐
                                        │   Callback     │  POST to SIEM
                                        │  (with retry)  │  dashboard
                                        └───────────────┘
```

### Pipeline flow

1. **Ingestion** — A detection system (EDR, IDS, SIEM) sends a security event via `POST /events`. The API validates the payload using Pydantic (`SecurityEvent` model with typed literals for `event_type`, `severity`, and `asset_criticality`) and immediately enqueues it to SQS for decoupled processing.

2. **Classification** — The worker polls SQS and runs each event through `MockSageMakerService`, a rule-based classifier that simulates a SageMaker endpoint. It computes a risk score (0-100) based on:
   - **Base score**: event type (8-12 pts) + severity (5-25 pts) + asset criticality (3-18 pts)
   - **Detail signals**: event-type-specific indicators (e.g., `failed_attempts >= 10` adds 25 pts for auth events, `ransomware_behavior` adds 40 pts for process activity)
   - **Output**: `Amenaza Confirmada` (>= 80), `Posible Amenaza` (50-79), or `Evento Inusual` (< 50)

3. **Explanation** — The classified event is passed to the LLM service, which generates a technical explanation in Spanish justifying the classification. In mock mode, it builds the real Bedrock prompt (validating the prompt engineering logic) but returns a deterministic rule-based explanation. In Bedrock mode, it calls Claude via the Messages API.

4. **Callback** — The enriched result (original event + classification + risk score + explanation) is delivered via HTTP POST to a configurable endpoint (SIEM dashboard, Webhook.site, or a local mock). Delivery includes exponential backoff retry (1s, 2s, 4s).

5. **Failure handling** — If callback delivery fails after all retries, the SQS message is not deleted and returns to the queue for reprocessing. After 3 failed processing cycles, the message is moved to the Dead-Letter Queue (DLQ) for manual investigation.

### Classification output (Spanish, SOC-oriented)

| Classification | Risk Score | Example triggers |
|---|---|---|
| **Amenaza Confirmada** | >= 80 | Ransomware behavior, EDR disabled + privilege escalation, brute force (>10 attempts) without MFA from unusual country |
| **Posible Amenaza** | 50-79 | Port scan detected, bulk file download (>100 MB), unsigned binary execution, suspicious IP reputation |
| **Evento Inusual** | < 50 | Routine login, normal file access, standard network traffic, regular security control events |

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.12+ (for running scripts and tests outside Docker)

### Setup and run

```bash
cp .env.example .env
docker compose up --build
```

This starts 4 services:

| Service | Port | Description |
|---|---|---|
| `localstack` | 4566 | AWS SQS emulation (main queue + DLQ with redrive policy) |
| `api` | 8000 | FastAPI event ingestion endpoint with Pydantic validation |
| `worker` | — | SQS consumer — classifies, explains, and delivers results |
| `callback-mock` | 8081 | Standalone FastAPI app that logs received callback payloads |

### Windows setup

If running on Windows, you may need to fix shell script permissions after cloning:

```bash
git update-index --chmod=+x run_worker.sh
```

Then rebuild with `docker compose up --build`.

### Send test events

```bash
# Single sample event (brute force auth attempt)
python3 -m scripts.seed_event

# Generate 50 synthetic events with mixed risk profiles, then seed them
python3 -m scripts.generate_synthetic_events
python3 -m scripts.seed_event data/generated/synthetic_events.jsonl
```

The synthetic generator produces events across all 5 types with weighted risk profiles: ~40% benign, ~35% suspicious, ~25% malicious.

### Example request

```bash
curl -X POST http://localhost:8000/events \
  -H "Content-Type: application/json" \
  -d '{
    "event_id": "evt-brute-force-001",
    "timestamp": "2026-03-11T15:30:00Z",
    "event_type": "authentication_event",
    "source": "auth-server",
    "source_ip": "203.0.113.45",
    "asset_id": "srv-db-prod-01",
    "asset_type": "database-server",
    "asset_criticality": "critical",
    "severity": "high",
    "details": {
      "failed_attempts": 15,
      "mfa_used": false,
      "country_unusual": true
    }
  }'
```

The worker picks it up, classifies it, and delivers the enriched result to the callback endpoint:

```json
{
  "event": {
    "event_id": "evt-brute-force-001",
    "timestamp": "2026-03-11T15:30:00Z",
    "event_type": "authentication_event",
    "source": "auth-server",
    "source_ip": "203.0.113.45",
    "asset_id": "srv-db-prod-01",
    "asset_type": "database-server",
    "asset_criticality": "critical",
    "severity": "high",
    "details": {
      "failed_attempts": 15,
      "mfa_used": false,
      "country_unusual": true
    }
  },
  "classification": "Amenaza Confirmada",
  "risk_score": 91,
  "reason": "El evento fue clasificado como 'Amenaza Confirmada' con un risk score de 91/100. La decisión se basó en señales observadas en un evento de tipo 'authentication_event', severidad 'high' y criticidad del activo 'critical'. Indicadores principales: failed_attempts >= 10 contributed 25 points; country_unusual=true contributed 10 points; mfa_used=false contributed 10 points."
}
```

### Using Webhook.site as external callback

To see results delivered to an external endpoint instead of the local mock:

1. Go to [webhook.site](https://webhook.site) and copy your unique URL
2. Update `CALLBACK_URL` in `docker-compose.yml` under the `worker` service environment section (the docker-compose environment overrides `.env`)
3. Restart: `docker compose down && docker compose up --build`
4. Send an event — the full payload appears in real time on the Webhook.site dashboard

## Project Structure

```
app/
├── api/routes.py               # POST /events — Pydantic validation + SQS enqueue
├── schemas.py                  # SecurityEvent model (5 event types, 4 severity levels,
│                               #   4 criticality levels, IPv4/IPv6 validation)
├── config.py                   # Environment-based settings via Pydantic Settings
├── services/
│   ├── sqs_service.py          # SQS client — queue creation with DLQ + redrive policy,
│   │                           #   URL normalization for LocalStack quirks
│   ├── mock_sagemaker.py       # Threat classifier — composite scoring formula with
│   │                           #   per-event-type detail analyzers (auth, file, process,
│   │                           #   network, security control)
│   ├── mock_llm.py             # LLM mock — builds real Bedrock prompts, returns
│   │                           #   deterministic output, logs token estimates
│   ├── prompt_engineering.py   # Bedrock integration — system/user prompt design,
│   │                           #   token estimation, BedrockLLMService with fallback
│   └── callback_service.py     # HTTP delivery — exponential backoff (3 retries)
├── workers/sqs_worker.py       # Queue consumer — 5-step pipeline orchestration
│                               #   with per-stage error handling and DLQ awareness
└── utils/logger.py             # Structured JSON logging (timestamp, level, event_id)

infra/
├── app.py                      # CDK entrypoint (per-environment context)
└── stack.py                    # IaC: SQS queues, IAM roles (least-privilege),
                                #   Secrets Manager (callback + Bedrock config)

scripts/
├── seed_event.py               # Send single or batch events to the API
├── generate_synthetic_events.py  # Generate realistic datasets (JSONL) with
│                               #   weighted risk profiles (benign/suspicious/malicious)
├── create_queue.py             # Initialize SQS infrastructure (used by worker on startup)
└── receive_message.py          # Queue inspection utility for debugging
```

## LLM Integration

The pipeline supports two modes controlled by `LLM_MODE`:

- **`mock`** (default) — Builds the real Bedrock prompt (system + user) but returns a deterministic explanation. Logs the full prompt and estimated token count for tuning. Zero cost, suitable for development and testing.
- **`bedrock`** — Calls AWS Bedrock (Claude Haiku) via the Messages API with token-optimized prompts. Includes automatic fallback to rule-based output if Bedrock is unavailable.

Prompt engineering decisions (`app/services/prompt_engineering.py`):

| Decision | Rationale |
|---|---|
| Compact system prompt (~150 tokens) | SOC analyst role, max 3 sentences, Spanish output, no headers |
| Selective user prompt fields | Only non-null event fields sent — nulls and empty details excluded |
| Reasons capped at 3 | Top classifier indicators only, avoids token bloat on complex events |
| `max_tokens=200` | Caps response length — explanations don't need more than 3 sentences |
| `temperature=0.2` | Low creativity for consistent, deterministic SOC-grade output |
| Claude Haiku model | Most cost-effective option for classification explanation tasks |
| No few-shot examples | Saves ~300 tokens/request — system prompt is sufficient for this task |

Estimated cost per invocation: **~370 input tokens + 100 - 150 approx. output tokens ($0.003 USD approx. with Haiku)**.

## Infrastructure (CDK)

The `infra/` directory defines the production-ready AWS stack in Python:

- **SQS** — Main queue + DLQ with redrive policy (3 retries before dead-letter), 14-day retention
- **IAM** — Least-privilege roles per service:
  - API role: `sqs:SendMessage` only
  - Worker role: `sqs:ReceiveMessage` + `sqs:DeleteMessage` + `bedrock:InvokeModel` (restricted to Haiku model ARN) + Secrets Manager read
- **Secrets Manager** — Callback URL + API key for the target SIEM, Bedrock model configuration. Enables automatic rotation and eliminates hardcoded credentials.
- **Environment-aware** — `RemovalPolicy.DESTROY` in development, `RETAIN` in production. Deployed via `cdk deploy --context env=production`.

```bash
cdk deploy --context env=production   # deploy
cdk diff --context env=staging        # preview changes
```

## Error Handling

| Layer | Strategy | Implementation |
|---|---|---|
| API validation | Pydantic rejects malformed events (422) before they reach SQS | `SecurityEvent` model with typed literals and field constraints |
| SQS delivery | Decouples ingestion from processing — API stays responsive under load | `SQSService.send_message()` in `routes.py` |
| Worker processing | Failed messages return to queue automatically via SQS visibility timeout | `sqs_worker.py` — message not deleted on processing errors |
| Callback delivery | Exponential backoff retry (1s, 2s, 4s) before failing back to SQS | `CallbackService.send_result()` with 3 attempts |
| Dead-letter queue | Messages that fail 3 processing cycles are moved to DLQ for investigation | SQS redrive policy configured in `sqs_service.py` and CDK stack |

## Configuration

All settings via environment variables (`.env`):

```bash
# Core
APP_ENV=development
LOG_LEVEL=INFO

# AWS / LocalStack
AWS_ENDPOINT_URL=http://localhost:4566
SQS_QUEUE_NAME=security-events-queue
SQS_DLQ_NAME=security-events-dlq
SQS_MAX_RECEIVE_COUNT=3

# LLM
LLM_MODE=mock                  # mock | bedrock
BEDROCK_MODEL_ID=anthropic.claude-haiku-4-5-20251001
BEDROCK_REGION=us-east-1

# Callback
CALLBACK_URL=http://localhost:8081/callback
CALLBACK_TIMEOUT_SECONDS=10

# Webhook
CALLBACK_URL=https://webhook.site/replace-me
```

> **Note**: When running with Docker Compose, the `environment` section in `docker-compose.yml` overrides `.env` values for `AWS_ENDPOINT_URL` and `CALLBACK_URL` to use container-internal hostnames.

## Tests

```bash
pytest                                  # full suite (91 tests)
pytest tests/test_e2e_pipeline.py       # end-to-end pipeline flow
pytest tests/test_prompt_engineering.py  # prompt design + token budget validation
pytest tests/test_mock_sagemaker.py     # classifier scoring across all threat levels
pytest tests/test_api.py                # API validation + SQS integration
pytest tests/test_schemas.py            # Pydantic model constraints
pytest tests/test_mock_llm.py           # explanation generation
pytest tests/test_generator.py          # synthetic event generation
```

The e2e test validates the complete flow (SQS message → classify → explain → callback → delete) mocking only external boundaries (SQS boto3 and HTTP), while classification and explanation run with real logic.

## Tech Stack

Python 3.12 / FastAPI / boto3 / Pydantic / httpx / AWS CDK / Docker / LocalStack
