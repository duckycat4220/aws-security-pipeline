"""
End-to-end pipeline test:
  Event -> Classification -> Explanation (LLM) -> Callback

Validates that all components integrate correctly without
depending on external infrastructure (SQS, Bedrock, callback HTTP).
"""

import json
from unittest.mock import MagicMock, patch

from app.schemas import SecurityEvent
from app.workers.sqs_worker import SQSWorker
from tests.conftest import make_event


def _make_sqs_message(event: SecurityEvent) -> dict:
    """Simulate the format of a received SQS message."""
    return {
        "Messages": [
            {
                "MessageId": "msg-e2e-001",
                "ReceiptHandle": "fake-receipt-handle",
                "Body": event.model_dump_json(),
                "Attributes": {"ApproximateReceiveCount": "1"},
            }
        ]
    }


class TestEndToEndPipeline:
    """
    Full flow: SQS message -> deserialize -> classify -> explain -> callback -> delete.
    Only external boundaries are mocked (SQS boto3 and HTTP callback).
    Classification and explanation run with real logic.
    """

    def test_confirmed_threat_full_flow(self):
        """Confirmed threat: ransomware + critical -> callback receives score >= 80."""
        event = make_event(
            event_type="process_activity",
            severity="critical",
            asset_criticality="critical",
            details={"ransomware_behavior": True, "known_malware_pattern": True},
        )

        callback_payloads = []

        mock_sqs = MagicMock()
        mock_sqs.get_queue_url.return_value = {"QueueUrl": "http://fake/queue"}
        mock_sqs.receive_message.return_value = _make_sqs_message(event)

        with (
            patch("boto3.client", return_value=mock_sqs),
            patch(
                "app.services.callback_service.CallbackService.send_result",
                side_effect=lambda payload: callback_payloads.append(payload),
            ),
        ):
            worker = SQSWorker()
            worker.sqs_service.sqs = mock_sqs
            worker.process_one_message()

        assert len(callback_payloads) == 1
        result = callback_payloads[0]

        # Verify callback structure
        assert result["event"]["event_id"] == event.event_id
        assert result["classification"] == "Amenaza Confirmada"
        assert result["risk_score"] >= 80
        assert isinstance(result["reason"], str)
        assert len(result["reason"]) > 0

        # Verify message was deleted from the queue
        mock_sqs.delete_message.assert_called_once()

    def test_unusual_event_full_flow(self):
        """Unusual event: benign activity -> callback receives score < 50."""
        event = make_event(
            event_type="authentication_event",
            severity="low",
            asset_criticality="low",
            details={},
        )

        callback_payloads = []

        mock_sqs = MagicMock()
        mock_sqs.get_queue_url.return_value = {"QueueUrl": "http://fake/queue"}
        mock_sqs.receive_message.return_value = _make_sqs_message(event)

        with (
            patch("boto3.client", return_value=mock_sqs),
            patch(
                "app.services.callback_service.CallbackService.send_result",
                side_effect=lambda payload: callback_payloads.append(payload),
            ),
        ):
            worker = SQSWorker()
            worker.sqs_service.sqs = mock_sqs
            worker.process_one_message()

        result = callback_payloads[0]
        assert result["classification"] == "Evento Inusual"
        assert result["risk_score"] < 50

    def test_callback_failure_does_not_delete_message(self):
        """If callback fails, the message is NOT deleted (retry via SQS)."""
        event = make_event(severity="high", details={"port_scan_detected": True})

        mock_sqs = MagicMock()
        mock_sqs.get_queue_url.return_value = {"QueueUrl": "http://fake/queue"}
        mock_sqs.receive_message.return_value = _make_sqs_message(event)

        from httpx import RequestError

        with (
            patch("boto3.client", return_value=mock_sqs),
            patch(
                "app.services.callback_service.CallbackService.send_result",
                side_effect=RequestError("Connection refused"),
            ),
        ):
            worker = SQSWorker()
            worker.sqs_service.sqs = mock_sqs
            worker.process_one_message()

        # Message should remain in the queue for retry
        mock_sqs.delete_message.assert_not_called()

    def test_callback_payload_structure(self):
        """Validates that the callback payload has the structure expected by a SIEM."""
        event = make_event(
            event_type="network_activity",
            severity="high",
            asset_criticality="high",
            source_ip="198.51.100.23",
            details={"suspicious_ip_reputation": True, "data_transfer_mb": 600},
        )

        callback_payloads = []

        mock_sqs = MagicMock()
        mock_sqs.get_queue_url.return_value = {"QueueUrl": "http://fake/queue"}
        mock_sqs.receive_message.return_value = _make_sqs_message(event)

        with (
            patch("boto3.client", return_value=mock_sqs),
            patch(
                "app.services.callback_service.CallbackService.send_result",
                side_effect=lambda payload: callback_payloads.append(payload),
            ),
        ):
            worker = SQSWorker()
            worker.sqs_service.sqs = mock_sqs
            worker.process_one_message()

        result = callback_payloads[0]

        # Required keys: event + classification + reason (+ score)
        assert "event" in result
        assert "classification" in result
        assert "risk_score" in result
        assert "reason" in result

        # Original event is preserved in full
        assert result["event"]["source_ip"] == "198.51.100.23"
        assert result["event"]["event_type"] == "network_activity"

        # Explanation is in Spanish
        assert "clasificado como" in result["reason"]

        # Payload is JSON-serializable (required for HTTP callback)
        json.dumps(result, default=str)
