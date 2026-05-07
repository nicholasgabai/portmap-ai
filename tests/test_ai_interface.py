import pytest

from ai_agent.interface import (
    AIAnalysisResult,
    StubAIProvider,
    validate_analysis_result,
    validate_connection_payload,
)


def test_validate_analysis_result_clamps_score_and_coerces_factors():
    result = validate_analysis_result(
        {
            "score": 1.7,
            "score_factors": ["ml_model", 8080],
            "risk_explanation": "",
            "provider": "unit",
        }
    )

    assert result.score == 1.0
    assert result.factors == ["ml_model", "8080"]
    assert result.provider == "unit"
    assert "provider unit returned no explanation" in result.explanation


def test_validate_analysis_result_accepts_dataclass_result():
    result = validate_analysis_result(
        AIAnalysisResult(
            score=0.42,
            factors=["stub"],
            explanation="Risk score 0.420: stub.",
            provider="stub",
            label="normal",
        )
    )

    assert result.score == 0.42
    assert result.label == "normal"
    assert result.factors == ["stub"]


def test_validate_connection_payload_requires_mapping():
    with pytest.raises(TypeError):
        validate_connection_payload(["not", "a", "mapping"])

    assert validate_connection_payload({"port": 8080}) == {"port": 8080}


def test_stub_ai_provider_returns_valid_local_result():
    provider = StubAIProvider(score=0.25)

    result = provider.analyze({"port": 443})

    assert result.score == 0.25
    assert result.provider == "stub"
    assert result.factors == ["stub_provider"]
    assert "local stub provider" in result.explanation
