import pytest
from pydantic import ValidationError

from app.schemas import SecurityEvent
from tests.conftest import make_event


class TestSecurityEventValidation:
    def test_valid_event_all_fields(self):
        event = make_event()
        assert event.event_id == "evt-test-001"
        assert event.event_type == "authentication_event"

    def test_valid_event_minimal_fields(self):
        event = SecurityEvent(
            event_id="evt-min-001",
            timestamp="2026-03-10T12:00:00Z",
            event_type="file_activity",
            source="file-monitor",
            asset_id="srv-01",
            asset_type="server",
            asset_criticality="low",
            severity="low",
        )
        assert event.source_ip is None
        assert event.user_id is None

    def test_all_event_types_accepted(self):
        for et in [
            "authentication_event",
            "file_activity",
            "process_activity",
            "network_activity",
            "security_control_event",
        ]:
            event = make_event(event_type=et)
            assert event.event_type == et

    def test_invalid_event_type_rejected(self):
        with pytest.raises(ValidationError):
            make_event(event_type="invalid_type")

    def test_all_severities_accepted(self):
        for sev in ["low", "medium", "high", "critical"]:
            event = make_event(severity=sev)
            assert event.severity == sev

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValidationError):
            make_event(severity="extreme")

    def test_all_criticalities_accepted(self):
        for crit in ["low", "medium", "high", "critical"]:
            event = make_event(asset_criticality=crit)
            assert event.asset_criticality == crit

    def test_invalid_criticality_rejected(self):
        with pytest.raises(ValidationError):
            make_event(asset_criticality="ultra")

    def test_valid_ipv4(self):
        event = make_event(source_ip="192.168.1.1")
        assert str(event.source_ip) == "192.168.1.1"

    def test_valid_ipv6(self):
        event = make_event(source_ip="::1")
        assert event.source_ip is not None

    def test_invalid_ip_rejected(self):
        with pytest.raises(ValidationError):
            make_event(source_ip="not-an-ip")

    def test_event_id_min_length(self):
        with pytest.raises(ValidationError):
            make_event(event_id="ab")

    def test_event_id_max_length(self):
        with pytest.raises(ValidationError):
            make_event(event_id="x" * 129)

    def test_details_default_empty_dict(self):
        event = SecurityEvent(
            event_id="evt-no-details",
            timestamp="2026-03-10T12:00:00Z",
            event_type="file_activity",
            source="file-monitor",
            asset_id="srv-01",
            asset_type="server",
            asset_criticality="low",
            severity="low",
        )
        assert event.details == {}

    def test_details_accepts_arbitrary_data(self):
        event = make_event(details={
            "custom_field": 42,
            "nested": {"key": "value"},
            "list_field": [1, 2, 3],
        })
        assert event.details["custom_field"] == 42
