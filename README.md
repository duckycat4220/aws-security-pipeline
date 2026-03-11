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

**Classification output** (Spanish, SOC-oriented):
- **Amenaza Confirmada** — risk score >= 80 (e.g., ransomware, EDR tampering)
- **Posible Amenaza** — risk score 50-79 (e.g., port scans, suspicious auth)
- **Evento Inusual** — risk score < 50 (e.g., routine logins, normal file access)

## Quick Start

```bash
cp .env.example .env
docker compose up --build
```

This starts 4 services:

| Service | Port | Description |
|---|---|---|
| `localstack` | 4566 | SQS emulation (queue + DLQ) |
| `api` | 8000 | Event ingestion endpoint |
| `worker` | — | Queue consumer + classification pipeline |
| `callback-mock` | 8081 | SIEM callback simulator |

### Send a test event

```bash
# Single event
python3 -m scripts.seed_event

# Batch from synthetic dataset (50 events, mixed risk profiles)
python3 -m scripts.seed_event data/generated/synthetic_events.jsonl
```

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
  "event": { "...original event..." },
  "classification": "Amenaza Confirmada",
  "risk_score": 91,
  "reason": "El evento fue clasificado como 'Amenaza Confirmada' con un risk score de 91/100..."
}
```

## Project Structure

```
app/
├── api/routes.py              # POST /events — validation + SQS enqueue
├── schemas.py                 # SecurityEvent model (typed literals, IP validation)
├── config.py                  # Environment-based settings (Pydantic Settings)
├── services/
│   ├── sqs_service.py         # SQS client with DLQ + LocalStack normalization
│   ├── mock_sagemaker.py      # Threat classifier — rule-based scoring (0-100)
│   ├── mock_llm.py            # LLM mock — uses real prompts, returns deterministic output
│   ├── prompt_engineering.py   # Bedrock integration + token-efficient prompt design
│   └── callback_service.py    # HTTP delivery with exponential backoff retry
├── workers/sqs_worker.py      # Queue consumer — orchestrates the full pipeline
└── utils/logger.py            # Structured JSON logging

infra/
├── app.py                     # CDK entrypoint (per-environment deployment)
└── stack.py                   # IaC: SQS, IAM (least-privilege), Secrets Manager

scripts/
├── seed_event.py              # Send test events to the API
├── generate_synthetic_events.py  # Generate realistic event datasets
├── create_queue.py            # Initialize SQS infrastructure
└── receive_message.py         # Queue inspection utility

tests/                         # 91 tests — unit + e2e
```

## LLM Integration

The pipeline supports two modes controlled by `LLM_MODE`:

- **`mock`** (default) — Builds the real Bedrock prompt but returns a deterministic explanation. Zero cost, suitable for development and testing.
- **`bedrock`** — Calls AWS Bedrock (Claude Haiku) with token-optimized prompts (~370 tokens/request). Includes automatic fallback to rule-based output if Bedrock is unavailable.

Prompt engineering decisions (`app/services/prompt_engineering.py`):
- Compact system prompt (~150 tokens) with SOC analyst role
- User prompt sends only relevant fields (nulls excluded, reasons capped at 3)
- `max_tokens=200`, `temperature=0.2` for consistent, low-cost responses

## Infrastructure (CDK)

The `infra/` directory defines the production-ready AWS stack:

- **SQS** — Main queue + DLQ with redrive policy (3 retries before dead-letter)
- **IAM** — Least-privilege roles: API can only send to SQS, worker can only consume + invoke Bedrock
- **Secrets Manager** — Callback credentials and Bedrock configuration (no hardcoded secrets)

```bash
# Deploy
cdk deploy --context env=production

# Preview changes
cdk diff --context env=staging
```

## Error Handling

| Layer | Strategy |
|---|---|
| API validation | Pydantic rejects malformed events (422) before they reach SQS |
| SQS delivery | Decouples ingestion from processing — API stays responsive |
| Worker processing | Failed messages return to queue automatically |
| Callback delivery | Exponential backoff (1s, 2s, 4s) before failing back to SQS retry |
| Dead-letter queue | Messages that fail 3 processing cycles are moved to DLQ for investigation |

## Configuration

All settings via environment variables (`.env`):

```bash
# Core
APP_ENV=development
LOG_LEVEL=INFO

# AWS / LocalStack
AWS_ENDPOINT_URL=http://localhost:4566
SQS_QUEUE_NAME=security-events-queue

# LLM
LLM_MODE=mock                  # mock | bedrock
BEDROCK_MODEL_ID=anthropic.claude-haiku-4-5-20251001

# Callback
CALLBACK_URL=http://localhost:8081/callback
CALLBACK_TIMEOUT_SECONDS=10
```

## Tests

```bash
pytest                              # full suite (91 tests)
pytest tests/test_e2e_pipeline.py   # end-to-end flow
pytest tests/test_prompt_engineering.py  # prompt design validation
```

## Tech Stack

Python 3.12 / FastAPI / boto3 / Pydantic / httpx / AWS CDK / Docker / LocalStack
