from app.services.mock_llm import MockLLMService
from app.services.mock_sagemaker import MockSageMakerService
from tests.conftest import make_event

llm = MockLLMService()
classifier = MockSageMakerService()


class TestExplanationGeneration:
    def test_returns_string(self, sample_event):
        classification = classifier.classify_event(sample_event)
        explanation = llm.generate_explanation(sample_event, classification)
        assert isinstance(explanation, str)
        assert len(explanation) > 0

    def test_contains_classification_label(self):
        event = make_event(severity="critical", asset_criticality="critical",
                           details={"ransomware_behavior": True})
        classification = classifier.classify_event(event)
        explanation = llm.generate_explanation(event, classification)
        assert classification["classification"] in explanation

    def test_contains_risk_score(self):
        event = make_event(severity="high", asset_criticality="high")
        classification = classifier.classify_event(event)
        explanation = llm.generate_explanation(event, classification)
        assert str(classification["risk_score"]) in explanation

    def test_contains_event_type(self):
        event = make_event(event_type="network_activity")
        classification = classifier.classify_event(event)
        explanation = llm.generate_explanation(event, classification)
        assert "network_activity" in explanation

    def test_contains_severity(self):
        event = make_event(severity="high")
        classification = classifier.classify_event(event)
        explanation = llm.generate_explanation(event, classification)
        assert "high" in explanation

    def test_contains_asset_criticality(self):
        event = make_event(asset_criticality="critical")
        classification = classifier.classify_event(event)
        explanation = llm.generate_explanation(event, classification)
        assert "critical" in explanation

    def test_output_is_in_spanish(self):
        event = make_event()
        classification = classifier.classify_event(event)
        explanation = llm.generate_explanation(event, classification)
        assert "El evento fue clasificado como" in explanation
        assert "risk score de" in explanation

    def test_handles_no_reasons(self):
        event = make_event()
        fake_result = {"classification": "Evento Inusual", "risk_score": 10, "reasons": []}
        explanation = llm.generate_explanation(event, fake_result)
        assert "sin indicadores significativos" in explanation

    def test_limits_to_three_reasons(self):
        event = make_event()
        fake_result = {
            "classification": "Posible Amenaza",
            "risk_score": 60,
            "reasons": ["r1", "r2", "r3", "r4", "r5"],
        }
        explanation = llm.generate_explanation(event, fake_result)
        assert "r1" in explanation
        assert "r3" in explanation
        assert "r4" not in explanation
