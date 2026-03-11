from datetime import datetime, timezone

import pytest

from app.schemas import SecurityEvent


def make_event(**overrides) -> SecurityEvent:
    """Build a SecurityEvent with sensible defaults, override any field."""
    defaults = {
        "event_id": "evt-test-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "authentication_event",
        "source": "auth-server",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.1.10",
        "user_id": "usr-001",
        "user_role": "admin",
        "asset_id": "srv-db-prod-01",
        "asset_type": "database-server",
        "asset_criticality": "high",
        "severity": "medium",
        "details": {},
    }
    defaults.update(overrides)
    return SecurityEvent(**defaults)


@pytest.fixture
def sample_event() -> SecurityEvent:
    return make_event()


@pytest.fixture
def valid_event_payload() -> dict:
    return {
        "event_id": "evt-test-api-001",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "authentication_event",
        "source": "auth-server",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.1.10",
        "user_id": "usr-001",
        "user_role": "admin",
        "asset_id": "srv-db-prod-01",
        "asset_type": "database-server",
        "asset_criticality": "high",
        "severity": "medium",
        "details": {},
    }
