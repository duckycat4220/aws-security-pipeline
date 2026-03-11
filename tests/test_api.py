from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient


def _build_client():
    """Create TestClient with SQS mocked at the boto3 level."""
    mock_boto_client = MagicMock()
    mock_boto_client.create_queue.return_value = {"QueueUrl": "http://fake/queue"}
    mock_boto_client.get_queue_attributes.return_value = {
        "Attributes": {"QueueArn": "arn:aws:sqs:us-east-1:000000000000:test-dlq"}
    }
    mock_boto_client.get_queue_url.return_value = {"QueueUrl": "http://fake/queue"}
    mock_boto_client.send_message.return_value = {"MessageId": "fake-msg-id"}

    with patch("boto3.client", return_value=mock_boto_client):
        # Force reimport so SQSService() picks up the mocked boto3
        import importlib
        import app.services.sqs_service
        importlib.reload(app.services.sqs_service)
        import app.api.routes
        importlib.reload(app.api.routes)
        import app.main
        importlib.reload(app.main)

        from app.main import app
        return TestClient(app), mock_boto_client


client, mock_boto = _build_client()


class TestHealthEndpoint:
    def test_returns_ok(self):
        response = client.get("/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert "app" in body
        assert "environment" in body


class TestIngestValidEvent:
    def test_accepts_valid_event(self, valid_event_payload):
        response = client.post("/events", json=valid_event_payload)
        assert response.status_code == 200
        body = response.json()
        assert body["event_id"] == valid_event_payload["event_id"]
        assert "message" in body

    def test_calls_sqs_send_message(self, valid_event_payload):
        mock_boto.send_message.reset_mock()
        client.post("/events", json=valid_event_payload)
        mock_boto.send_message.assert_called_once()

    def test_optional_fields_can_be_omitted(self):
        payload = {
            "event_id": "evt-minimal-001",
            "timestamp": "2026-03-10T12:00:00Z",
            "event_type": "file_activity",
            "source": "file-monitor",
            "asset_id": "srv-web-01",
            "asset_type": "web-server",
            "asset_criticality": "low",
            "severity": "low",
        }
        response = client.post("/events", json=payload)
        assert response.status_code == 200


class TestIngestRejectsInvalid:
    def test_missing_required_fields(self):
        response = client.post("/events", json={"event_id": "evt-001"})
        assert response.status_code == 422

    def test_invalid_event_type(self, valid_event_payload):
        valid_event_payload["event_type"] = "unknown_event"
        response = client.post("/events", json=valid_event_payload)
        assert response.status_code == 422

    def test_invalid_severity(self, valid_event_payload):
        valid_event_payload["severity"] = "extreme"
        response = client.post("/events", json=valid_event_payload)
        assert response.status_code == 422

    def test_invalid_source_ip(self, valid_event_payload):
        valid_event_payload["source_ip"] = "not-an-ip"
        response = client.post("/events", json=valid_event_payload)
        assert response.status_code == 422

    def test_event_id_too_short(self, valid_event_payload):
        valid_event_payload["event_id"] = "ab"
        response = client.post("/events", json=valid_event_payload)
        assert response.status_code == 422

    def test_empty_body(self):
        response = client.post("/events", json={})
        assert response.status_code == 422


class TestIngestSQSFailure:
    def test_sqs_error_returns_500(self, valid_event_payload):
        mock_boto.send_message.side_effect = RuntimeError("SQS unavailable")
        response = client.post("/events", json=valid_event_payload)
        assert response.status_code == 500
        mock_boto.send_message.side_effect = None
