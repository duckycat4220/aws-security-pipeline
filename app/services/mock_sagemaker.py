from typing import Any

from app.schemas import SecurityEvent
from app.utils.logger import get_logger

logger = get_logger(__name__)

EVENT_TYPE_SCORES = {
    "authentication_event": 8,
    "file_activity": 8,
    "process_activity": 10,
    "network_activity": 8,
    "security_control_event": 12,
}

SEVERITY_SCORES = {
    "low": 5,
    "medium": 10,
    "high": 20,
    "critical": 25,
}

CRITICALITY_SCORES = {
    "low": 3,
    "medium": 8,
    "high": 14,
    "critical": 18,
}


class MockSageMakerService:
    def classify_event(self, event: SecurityEvent) -> dict[str, Any]:
        score = 0
        reasons: list[str] = []

        score += self._score_by_event_type(event, reasons)
        score += self._score_by_severity(event, reasons)
        score += self._score_by_asset_criticality(event, reasons)
        score += self._score_by_details(event, reasons)

        score = min(score, 100)
        classification = self._map_score_to_label(score)

        logger.info(
            "Classification generated",
            extra={
                "event_id": event.event_id,
                "extra_data": {
                    "classification": classification,
                    "risk_score": score,
                    "reasons_count": len(reasons),
                },
            },
        )

        return {
            "classification": classification,
            "risk_score": score,
            "reasons": reasons,
        }

    def _score_by_event_type(self, event: SecurityEvent, reasons: list[str]) -> int:
        points = EVENT_TYPE_SCORES.get(event.event_type, 0)
        reasons.append(f"event_type={event.event_type} contributed {points} points")
        return points

    def _score_by_severity(self, event: SecurityEvent, reasons: list[str]) -> int:
        points = SEVERITY_SCORES.get(event.severity, 0)
        reasons.append(f"severity={event.severity} contributed {points} points")
        return points

    def _score_by_asset_criticality(self, event: SecurityEvent, reasons: list[str]) -> int:
        points = CRITICALITY_SCORES.get(event.asset_criticality, 0)
        reasons.append(
            f"asset_criticality={event.asset_criticality} contributed {points} points"
        )
        return points

    def _score_by_details(self, event: SecurityEvent, reasons: list[str]) -> int:
        dispatcher = {
            "authentication_event": self._score_authentication,
            "file_activity": self._score_file_activity,
            "process_activity": self._score_process_activity,
            "network_activity": self._score_network_activity,
            "security_control_event": self._score_security_control,
        }
        scorer = dispatcher.get(event.event_type)
        if scorer is None:
            return 0
        return scorer(event.details or {}, reasons)

    # -- Type-specific detail scorers --

    def _score_authentication(self, details: dict, reasons: list[str]) -> int:
        points = 0

        failed_attempts = int(details.get("failed_attempts", 0) or 0)
        if failed_attempts >= 10:
            points += 25
            reasons.append("failed_attempts >= 10 contributed 25 points")
        elif failed_attempts >= 5:
            points += 15
            reasons.append("failed_attempts >= 5 contributed 15 points")

        if details.get("country_unusual") is True:
            points += 10
            reasons.append("country_unusual=true contributed 10 points")

        if details.get("mfa_used") is False:
            points += 10
            reasons.append("mfa_used=false contributed 10 points")

        if details.get("outside_business_hours") is True:
            points += 5
            reasons.append("outside_business_hours=true contributed 5 points")

        return points

    def _score_file_activity(self, details: dict, reasons: list[str]) -> int:
        points = 0

        if details.get("bulk_download") is True:
            points += 20
            reasons.append("bulk_download=true contributed 20 points")

        download_size_mb = float(details.get("download_size_mb", 0) or 0)
        if download_size_mb >= 500:
            points += 25
            reasons.append("download_size_mb >= 500 contributed 25 points")
        elif download_size_mb >= 100:
            points += 15
            reasons.append("download_size_mb >= 100 contributed 15 points")

        if details.get("sensitive_files") is True:
            points += 15
            reasons.append("sensitive_files=true contributed 15 points")

        return points

    def _score_process_activity(self, details: dict, reasons: list[str]) -> int:
        points = 0

        if details.get("known_malware_pattern") is True:
            points += 35
            reasons.append("known_malware_pattern=true contributed 35 points")

        if details.get("ransomware_behavior") is True:
            points += 40
            reasons.append("ransomware_behavior=true contributed 40 points")

        if details.get("unsigned_binary") is True:
            points += 15
            reasons.append("unsigned_binary=true contributed 15 points")

        return points

    def _score_network_activity(self, details: dict, reasons: list[str]) -> int:
        points = 0

        if details.get("suspicious_ip_reputation") is True:
            points += 15
            reasons.append("suspicious_ip_reputation=true contributed 15 points")

        if details.get("port_scan_detected") is True:
            points += 20
            reasons.append("port_scan_detected=true contributed 20 points")

        data_transfer_mb = float(details.get("data_transfer_mb", 0) or 0)
        if data_transfer_mb >= 500:
            points += 20
            reasons.append("data_transfer_mb >= 500 contributed 20 points")
        elif data_transfer_mb >= 100:
            points += 10
            reasons.append("data_transfer_mb >= 100 contributed 10 points")

        return points

    def _score_security_control(self, details: dict, reasons: list[str]) -> int:
        points = 0

        if details.get("edr_disabled") is True:
            points += 30
            reasons.append("edr_disabled=true contributed 30 points")

        if details.get("privilege_escalation") is True:
            points += 25
            reasons.append("privilege_escalation=true contributed 25 points")

        return points

    def _map_score_to_label(self, score: int) -> str:
        if score >= 80:
            return "Amenaza Confirmada"
        if score >= 50:
            return "Posible Amenaza"
        return "Evento Inusual"
