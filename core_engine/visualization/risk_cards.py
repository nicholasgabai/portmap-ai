from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from core_engine.visualization.timeline_models import (
    normalize_severity,
    sanitize_reference,
    sanitize_references,
    sanitize_summary,
)
from core_engine.visualization.topology_models import (
    TOPOLOGY_VISUAL_SAFETY_FLAGS,
    clamp_score,
    normalize_source_mode,
)


RISK_CARD_RECORD_VERSION = 1
RISK_CARD_TYPES = {
    "asset_risk",
    "flow_risk",
    "policy_risk",
    "drift_risk",
    "attribution_risk",
    "topology_risk",
    "remediation_preview",
    "guardrail_block",
    "runtime_health",
    "unknown",
}
RISK_DASHBOARD_SAFETY_FLAGS = {
    **TOPOLOGY_VISUAL_SAFETY_FLAGS,
    "dashboard_model_only": True,
    "export_safe": True,
    "bounded": True,
    "preview_only": True,
    "destructive_action": False,
    "browser_ui_started": False,
    "runtime_database_written": False,
}


class RiskDashboardError(ValueError):
    """Raised when visualization risk dashboard inputs are malformed."""


@dataclass(frozen=True)
class RiskCard:
    card_id: str
    card_type: str
    card_title: str
    severity_level: str = "info"
    confidence_score: float = 0.0
    risk_score: float = 0.0
    summary: str = ""
    explanation_points: list[str] = field(default_factory=list)
    related_asset_references: list[str] = field(default_factory=list)
    related_flow_references: list[str] = field(default_factory=list)
    related_policy_references: list[str] = field(default_factory=list)
    related_incident_references: list[str] = field(default_factory=list)
    related_guardrail_references: list[str] = field(default_factory=list)
    recommended_next_step: str = "monitor"
    source_modes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        modes = sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"]
        return {
            "record_type": "visual_risk_card",
            "record_version": RISK_CARD_RECORD_VERSION,
            "card_id": sanitize_reference(self.card_id),
            "card_type": normalize_card_type(self.card_type),
            "card_title": sanitize_summary(self.card_title),
            "severity_level": normalize_severity(self.severity_level),
            "confidence_score": clamp_score(self.confidence_score),
            "risk_score": clamp_score(self.risk_score),
            "summary": sanitize_summary(self.summary),
            "explanation_points": [sanitize_summary(point) for point in self.explanation_points],
            "related_asset_references": sanitize_references(self.related_asset_references),
            "related_flow_references": sanitize_references(self.related_flow_references),
            "related_policy_references": sanitize_references(self.related_policy_references),
            "related_incident_references": sanitize_references(self.related_incident_references),
            "related_guardrail_references": sanitize_references(self.related_guardrail_references),
            "recommended_next_step": _safe_token(self.recommended_next_step),
            "source_modes": modes,
            "data_sources": modes,
            "preview_only": True,
            "destructive_action": False,
            "advisory_notes": [sanitize_summary(note) for note in self.advisory_notes],
            **RISK_DASHBOARD_SAFETY_FLAGS,
        }


def make_risk_card(
    *,
    card_type: str,
    card_title: Any,
    severity_level: Any = "info",
    confidence_score: Any = 0.0,
    risk_score: Any = 0.0,
    summary: Any = "",
    explanation_points: list[Any] | None = None,
    related_asset_references: list[Any] | None = None,
    related_flow_references: list[Any] | None = None,
    related_policy_references: list[Any] | None = None,
    related_incident_references: list[Any] | None = None,
    related_guardrail_references: list[Any] | None = None,
    recommended_next_step: Any = "monitor",
    source_modes: list[Any] | None = None,
    advisory_notes: list[Any] | None = None,
) -> RiskCard:
    normalized_type = normalize_card_type(card_type)
    modes = sorted({normalize_source_mode(mode) for mode in source_modes or []}) or ["unknown"]
    asset_refs = sanitize_references(related_asset_references or [])
    flow_refs = sanitize_references(related_flow_references or [])
    policy_refs = sanitize_references(related_policy_references or [])
    incident_refs = sanitize_references(related_incident_references or [])
    guardrail_refs = sanitize_references(related_guardrail_references or [])
    card_id = "risk-card-" + _digest(
        {
            "card_type": normalized_type,
            "title": sanitize_summary(card_title),
            "severity": normalize_severity(severity_level),
            "assets": asset_refs,
            "flows": flow_refs,
            "policies": policy_refs,
            "incidents": incident_refs,
            "guardrails": guardrail_refs,
            "source_modes": modes,
        }
    )[:16]
    return RiskCard(
        card_id=card_id,
        card_type=normalized_type,
        card_title=sanitize_summary(card_title or normalized_type.replace("_", " ").title()),
        severity_level=normalize_severity(severity_level),
        confidence_score=clamp_score(confidence_score),
        risk_score=clamp_score(risk_score),
        summary=sanitize_summary(summary or "Risk dashboard metadata summary"),
        explanation_points=[sanitize_summary(point) for point in explanation_points or []],
        related_asset_references=asset_refs,
        related_flow_references=flow_refs,
        related_policy_references=policy_refs,
        related_incident_references=incident_refs,
        related_guardrail_references=guardrail_refs,
        recommended_next_step=recommended_next_step,
        source_modes=modes,
        preview_only=True,
        destructive_action=False,
        advisory_notes=[sanitize_summary(note) for note in advisory_notes or ["visual risk card is advisory-only"]],
    )


def deterministic_risk_card_json(record: RiskCard | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, RiskCard) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def normalize_card_type(value: Any) -> str:
    card_type = _safe_token(value)
    return card_type if card_type in RISK_CARD_TYPES else "unknown"


def severity_rank(value: Any) -> int:
    return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}.get(
        normalize_severity(value),
        0,
    )


def severity_from_risk_score(score: Any) -> str:
    risk = clamp_score(score)
    if risk >= 0.9:
        return "critical"
    if risk >= 0.7:
        return "high"
    if risk >= 0.45:
        return "medium"
    if risk > 0.0:
        return "low"
    return "info"


def risk_score_from_severity(severity: Any) -> float:
    return {
        "critical": 0.95,
        "high": 0.78,
        "medium": 0.55,
        "low": 0.25,
        "info": 0.05,
        "unknown": 0.0,
    }.get(normalize_severity(severity), 0.0)


def _safe_token(value: Any) -> str:
    token = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    safe = "".join(char for char in token if char.isalnum() or char == "_")
    return safe[:64] or "unknown"


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()
