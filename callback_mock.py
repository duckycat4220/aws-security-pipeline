import json
import logging
import sys

from fastapi import FastAPI, Request

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
logger = logging.getLogger("callback_mock")
logger.setLevel(logging.INFO)
logger.addHandler(handler)

app = FastAPI(title="Callback Mock")


@app.post("/callback")
async def receive_callback(request: Request) -> dict:
    payload = await request.json()
    event_id = payload.get("event", {}).get("event_id")
    classification = payload.get("classification")
    risk_score = payload.get("risk_score")
    reason = payload.get("reason", "")
    logger.info(
        "Callback received | event_id=%s classification=%s risk_score=%s",
        event_id,
        classification,
        risk_score,
    )
    logger.info("  reason: %s", reason)
    logger.info("  payload:\n%s", json.dumps(payload, indent=2, ensure_ascii=False))
    return {"status": "received"}