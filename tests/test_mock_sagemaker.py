from app.services.mock_sagemaker import MockSageMakerService
from tests.conftest import make_event

classifier = MockSageMakerService()


class TestAmenazaConfirmada:
    """Events that should score >= 80 -> 'Amenaza Confirmada'."""

    def test_ransomware_critical_severity(self):
        event = make_event(
            event_type="process_activity",
            severity="critical",
            asset_criticality="critical",
            details={"ransomware_behavior": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Amenaza Confirmada"
        assert result["risk_score"] >= 80

    def test_edr_disabled_with_privilege_escalation(self):
        event = make_event(
            event_type="security_control_event",
            severity="critical",
            asset_criticality="high",
            details={"edr_disabled": True, "privilege_escalation": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Amenaza Confirmada"
        assert result["risk_score"] >= 80

    def test_brute_force_no_mfa_unusual_country(self):
        event = make_event(
            event_type="authentication_event",
            severity="critical",
            asset_criticality="critical",
            details={
                "failed_attempts": 25,
                "mfa_used": False,
                "country_unusual": True,
            },
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Amenaza Confirmada"
        assert result["risk_score"] >= 80

    def test_malware_plus_ransomware(self):
        event = make_event(
            event_type="process_activity",
            severity="high",
            asset_criticality="high",
            details={"known_malware_pattern": True, "ransomware_behavior": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Amenaza Confirmada"
        assert result["risk_score"] >= 80

    def test_massive_exfiltration(self):
        event = make_event(
            event_type="file_activity",
            severity="critical",
            asset_criticality="critical",
            details={
                "bulk_download": True,
                "download_size_mb": 2000,
                "sensitive_files": True,
            },
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Amenaza Confirmada"
        assert result["risk_score"] >= 80


class TestPosibleAmenaza:
    """Events that should score 50-79 -> 'Posible Amenaza'."""

    def test_suspicious_network_activity(self):
        event = make_event(
            event_type="network_activity",
            severity="high",
            asset_criticality="medium",
            details={"suspicious_ip_reputation": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Posible Amenaza"
        assert 50 <= result["risk_score"] < 80

    def test_medium_file_exfiltration(self):
        event = make_event(
            event_type="file_activity",
            severity="high",
            asset_criticality="medium",
            details={"download_size_mb": 200, "bulk_download": False},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Posible Amenaza"
        assert 50 <= result["risk_score"] < 80

    def test_failed_auth_attempts(self):
        event = make_event(
            event_type="authentication_event",
            severity="high",
            asset_criticality="medium",
            details={"failed_attempts": 7, "mfa_used": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Posible Amenaza"
        assert 50 <= result["risk_score"] < 80

    def test_port_scan_detected(self):
        event = make_event(
            event_type="network_activity",
            severity="high",
            asset_criticality="medium",
            details={"port_scan_detected": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Posible Amenaza"
        assert 50 <= result["risk_score"] < 80

    def test_unsigned_binary(self):
        event = make_event(
            event_type="process_activity",
            severity="high",
            asset_criticality="medium",
            details={"unsigned_binary": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Posible Amenaza"
        assert 50 <= result["risk_score"] < 80


class TestEventoInusual:
    """Events that should score < 50 -> 'Evento Inusual'."""

    def test_normal_login(self):
        event = make_event(
            event_type="authentication_event",
            severity="low",
            asset_criticality="low",
            details={"failed_attempts": 0, "mfa_used": True},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Evento Inusual"
        assert result["risk_score"] < 50

    def test_benign_file_read(self):
        event = make_event(
            event_type="file_activity",
            severity="low",
            asset_criticality="low",
            details={"download_size_mb": 5, "bulk_download": False},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Evento Inusual"
        assert result["risk_score"] < 50

    def test_routine_process(self):
        event = make_event(
            event_type="process_activity",
            severity="low",
            asset_criticality="low",
            details={
                "known_malware_pattern": False,
                "ransomware_behavior": False,
            },
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Evento Inusual"
        assert result["risk_score"] < 50

    def test_normal_network_traffic(self):
        event = make_event(
            event_type="network_activity",
            severity="low",
            asset_criticality="low",
            details={"suspicious_ip_reputation": False, "data_transfer_mb": 5},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Evento Inusual"
        assert result["risk_score"] < 50

    def test_routine_security_control(self):
        event = make_event(
            event_type="security_control_event",
            severity="low",
            asset_criticality="low",
            details={"edr_disabled": False},
        )
        result = classifier.classify_event(event)
        assert result["classification"] == "Evento Inusual"
        assert result["risk_score"] < 50

    def test_base_only_critical_stays_under_80(self):
        """Max base (severity=critical + criticality=critical) without detail
        signals should NOT reach Amenaza Confirmada."""
        event = make_event(
            event_type="security_control_event",
            severity="critical",
            asset_criticality="critical",
            details={},
        )
        result = classifier.classify_event(event)
        assert result["risk_score"] < 80


class TestScoringDetails:
    def test_score_capped_at_100(self):
        event = make_event(
            event_type="process_activity",
            severity="critical",
            asset_criticality="critical",
            details={
                "known_malware_pattern": True,
                "ransomware_behavior": True,
                "unsigned_binary": True,
            },
        )
        result = classifier.classify_event(event)
        assert result["risk_score"] == 100

    def test_result_has_required_keys(self, sample_event):
        result = classifier.classify_event(sample_event)
        assert "classification" in result
        assert "risk_score" in result
        assert "reasons" in result
        assert isinstance(result["reasons"], list)
        assert len(result["reasons"]) > 0

    def test_all_event_types_produce_valid_results(self):
        valid_labels = {"Evento Inusual", "Posible Amenaza", "Amenaza Confirmada"}
        for event_type in [
            "authentication_event",
            "file_activity",
            "process_activity",
            "network_activity",
            "security_control_event",
        ]:
            event = make_event(event_type=event_type, severity="medium", asset_criticality="medium")
            result = classifier.classify_event(event)
            assert result["classification"] in valid_labels
            assert 0 <= result["risk_score"] <= 100

    def test_irrelevant_details_ignored(self):
        """Details from another event type should not affect score."""
        event_without = make_event(
            event_type="authentication_event",
            severity="low",
            asset_criticality="low",
            details={},
        )
        event_with_irrelevant = make_event(
            event_type="authentication_event",
            severity="low",
            asset_criticality="low",
            details={"ransomware_behavior": True, "edr_disabled": True},
        )
        r1 = classifier.classify_event(event_without)
        r2 = classifier.classify_event(event_with_irrelevant)
        assert r1["risk_score"] == r2["risk_score"]
