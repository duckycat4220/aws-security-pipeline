"""
Seed security events to the API.

Usage:
    python3 -m scripts.seed_event                                    # one sample event
    python3 -m scripts.seed_event data/generated/synthetic_events.jsonl  # from JSONL file
"""

import json
import sys
from datetime import datetime, timezone

import httpx

API_URL = "http://127.0.0.1:8000/events"


def get_sample_event() -> dict:
    return {
        "event_id": "evt-seed-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "authentication_event",
        "source": "auth-server",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.1.10",
        "user_id": "usr-003",
        "user_role": "analyst",
        "asset_id": "srv-db-prod-01",
        "asset_type": "database-server",
        "asset_criticality": "high",
        "severity": "critical",
        "details": {
            "failed_attempts": 15,
            "mfa_used": False,
            "country_unusual": True,
            "outside_business_hours": True,
        },
    }


def load_events_from_jsonl(path: str) -> list[dict]:
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                events.append(json.loads(line))
    return events


def send_event(event: dict, client: httpx.Client) -> bool:
    event_id = event.get("event_id", "unknown")
    try:
        response = client.post(API_URL, json=event)
        if response.status_code == 200:
            print(f"  Seeded event {event_id}")
            return True
        else:
            print(f"  Failed event {event_id}: {response.status_code}")
            return False
    except httpx.RequestError as exc:
        print(f"  Failed event {event_id}: {exc}")
        return False


def main() -> None:
    if len(sys.argv) > 1:
        path = sys.argv[1]
        print(f"Loading events from {path}")
        events = load_events_from_jsonl(path)
    else:
        print("Sending sample event")
        events = [get_sample_event()]

    ok = 0
    fail = 0

    with httpx.Client(timeout=10) as client:
        for event in events:
            if send_event(event, client):
                ok += 1
            else:
                fail += 1

    print(f"\nDone: {ok + fail} total, {ok} seeded, {fail} failed")


if __name__ == "__main__":
    main()
