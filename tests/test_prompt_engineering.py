from app.services.prompt_engineering import (
    SYSTEM_PROMPT,
    BedrockLLMService,
    build_user_prompt,
    estimate_prompt_tokens,
    _fallback_explanation,
)
from app.services.mock_sagemaker import MockSageMakerService
from tests.conftest import make_event

classifier = MockSageMakerService()


class TestSystemPrompt:
    def test_is_in_spanish(self):
        assert "español" in SYSTEM_PROMPT

    def test_limits_output_length(self):
        assert "máximo 3 oraciones" in SYSTEM_PROMPT

    def test_defines_soc_role(self):
        assert "SOC" in SYSTEM_PROMPT

    def test_token_efficiency(self):
        """System prompt should stay under 200 tokens (~800 chars)."""
        assert len(SYSTEM_PROMPT) < 800


class TestBuildUserPrompt:
    def test_includes_event_type(self):
        event = make_event(event_type="network_activity")
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert "network_activity" in prompt

    def test_includes_classification(self):
        event = make_event(severity="critical", details={"ransomware_behavior": True})
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert result["classification"] in prompt

    def test_includes_risk_score(self):
        event = make_event()
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert f"{result['risk_score']}/100" in prompt

    def test_includes_ip_when_present(self):
        event = make_event(source_ip="10.0.0.1")
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert "10.0.0.1" in prompt

    def test_excludes_ip_when_absent(self):
        event = make_event(source_ip=None)
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert "ip_origen" not in prompt

    def test_includes_user_when_present(self):
        event = make_event(user_id="admin-01")
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert "admin-01" in prompt

    def test_excludes_user_when_absent(self):
        event = make_event(user_id=None)
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert "usuario" not in prompt

    def test_limits_reasons_to_three(self):
        event = make_event()
        fake_result = {
            "classification": "Posible Amenaza",
            "risk_score": 60,
            "reasons": ["r1", "r2", "r3", "r4", "r5"],
        }
        prompt = build_user_prompt(event, fake_result)
        assert "r3" in prompt
        assert "r4" not in prompt

    def test_handles_empty_reasons(self):
        event = make_event()
        result = {"classification": "Evento Inusual", "risk_score": 10, "reasons": []}
        prompt = build_user_prompt(event, result)
        assert "sin indicadores significativos" in prompt

    def test_includes_significant_details(self):
        event = make_event(details={"ransomware_behavior": True, "empty_field": ""})
        result = classifier.classify_event(event)
        prompt = build_user_prompt(event, result)
        assert "ransomware_behavior" in prompt
        # Falsy values should be excluded
        assert "empty_field" not in prompt


class TestTokenEstimation:
    def test_returns_positive_integer(self):
        event = make_event()
        result = classifier.classify_event(event)
        tokens = estimate_prompt_tokens(event, result)
        assert isinstance(tokens, int)
        assert tokens > 0

    def test_stays_within_budget(self):
        """Total input should stay under 500 tokens for cost control."""
        event = make_event(
            details={"ransomware_behavior": True, "known_malware_pattern": True},
        )
        result = classifier.classify_event(event)
        tokens = estimate_prompt_tokens(event, result)
        assert tokens < 500


class TestFallbackExplanation:
    def test_contains_classification(self):
        event = make_event()
        result = {"classification": "Amenaza Confirmada", "risk_score": 85, "reasons": ["r1"]}
        explanation = _fallback_explanation(event, result)
        assert "Amenaza Confirmada" in explanation

    def test_contains_risk_score(self):
        event = make_event()
        result = {"classification": "Evento Inusual", "risk_score": 20, "reasons": []}
        explanation = _fallback_explanation(event, result)
        assert "20/100" in explanation

    def test_is_in_spanish(self):
        event = make_event()
        result = {"classification": "Evento Inusual", "risk_score": 10, "reasons": []}
        explanation = _fallback_explanation(event, result)
        assert "El evento fue clasificado como" in explanation


class TestBedrockLLMServiceStructure:
    """Validates that BedrockLLMService has the expected interface."""

    def test_has_generate_explanation_method(self):
        assert hasattr(BedrockLLMService, "generate_explanation")

    def test_conforms_to_protocol(self):
        """BedrockLLMService should match LLMService protocol signature."""
        import inspect
        sig = inspect.signature(BedrockLLMService.generate_explanation)
        params = list(sig.parameters.keys())
        assert "event" in params
        assert "classification_result" in params
