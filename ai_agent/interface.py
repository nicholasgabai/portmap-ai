from __future__ import annotations

from dataclasses import dataclass, field
import math
from typing import Any, Mapping, Protocol


@dataclass(frozen=True)
class AIAnalysisResult:
    score: float
    factors: list[str]
    explanation: str
    provider: str = "unknown"
    label: str | int | float | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class AIProvider(Protocol):
    name: str

    def analyze(
        self,
        connection: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> AIAnalysisResult:
        ...


class StubAIProvider:
    name = "stub"

    def __init__(self, score: float = 0.1, explanation: str | None = None):
        self.score = score
        self.explanation = explanation

    def analyze(
        self,
        connection: Mapping[str, Any],
        context: Mapping[str, Any] | None = None,
    ) -> AIAnalysisResult:
        validate_connection_payload(connection)
        result = validate_analysis_result(
            AIAnalysisResult(
                score=self.score,
                factors=["stub_provider"],
                explanation=self.explanation or f"Risk score {self.score:.3f}: local stub provider.",
                provider=self.name,
            )
        )
        return result


def validate_connection_payload(connection: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(connection, Mapping):
        raise TypeError("AI connection payload must be a mapping")
    return dict(connection)


def validate_analysis_result(
    result: AIAnalysisResult | Mapping[str, Any],
    *,
    default_provider: str = "unknown",
) -> AIAnalysisResult:
    if isinstance(result, Mapping):
        raw = dict(result)
        result = AIAnalysisResult(
            score=raw.get("score", 0.0),
            factors=list(raw.get("factors") or raw.get("score_factors") or []),
            explanation=str(raw.get("explanation") or raw.get("risk_explanation") or ""),
            provider=str(raw.get("provider") or default_provider),
            label=raw.get("label"),
            metadata=dict(raw.get("metadata") or {}),
        )

    score = _normalize_score(result.score)
    factors = [str(factor) for factor in (result.factors or []) if str(factor)]
    provider = str(result.provider or default_provider)
    explanation = str(result.explanation or "").strip()
    if not explanation:
        explanation = f"Risk score {score:.3f}: provider {provider} returned no explanation."

    metadata = result.metadata if isinstance(result.metadata, dict) else {}
    return AIAnalysisResult(
        score=score,
        factors=factors,
        explanation=explanation,
        provider=provider,
        label=result.label,
        metadata=dict(metadata),
    )


def _normalize_score(value: Any) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError):
        score = 0.0
    if not math.isfinite(score):
        score = 0.0
    return round(max(0.0, min(1.0, score)), 3)
