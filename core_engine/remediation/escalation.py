from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


ESCALATION_STATES = frozenset(
    {
        "none",
        "monitor",
        "review_required",
        "approval_required",
        "escalation_candidate",
        "blocked_by_safety",
    }
)


class EscalationError(ValueError):
    """Raised when an escalation preview violates advisory-only constraints."""


@dataclass(slots=True)
class EscalationDecisionPreview:
    escalation_id: str
    escalation_state: str
    escalation_reason: str
    confidence_score: float
    safety_blockers: list[str] = field(default_factory=list)
    operator_actions: list[str] = field(default_factory=list)
    recommended_next_step: str = "continue_monitoring"
    preview_only: bool = True
    destructive_action: bool = False
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.escalation_id, "escalation_id")
        if self.escalation_state not in ESCALATION_STATES:
            raise EscalationError(f"unsupported escalation_state: {self.escalation_state}")
        _required_str(self.escalation_reason, "escalation_reason")
        self.confidence_score = _clamp(self.confidence_score)
        if not _is_string_list(self.safety_blockers):
            raise EscalationError("safety_blockers must be a list of strings")
        if not _is_string_list(self.operator_actions):
            raise EscalationError("operator_actions must be a list of strings")
        _required_str(self.recommended_next_step, "recommended_next_step")
        if not self.preview_only:
            raise EscalationError("escalation decisions must remain preview_only")
        if self.destructive_action:
            raise EscalationError("escalation decisions cannot be destructive")
        _required_str(self.source_mode, "source_mode")


def create_escalation_decision(
    *,
    escalation_id: str,
    escalation_state: str,
    escalation_reason: str,
    confidence_score: float = 0.0,
    safety_blockers: list[str] | None = None,
    operator_actions: list[str] | None = None,
    recommended_next_step: str = "continue_monitoring",
    preview_only: bool = True,
    destructive_action: bool = False,
    source_mode: str = "unknown",
    created_at: str | None = None,
) -> EscalationDecisionPreview:
    return EscalationDecisionPreview(
        escalation_id=escalation_id,
        escalation_state=escalation_state,
        escalation_reason=escalation_reason,
        confidence_score=confidence_score,
        safety_blockers=safety_blockers or [],
        operator_actions=operator_actions or [],
        recommended_next_step=recommended_next_step,
        preview_only=preview_only,
        destructive_action=destructive_action,
        source_mode=source_mode,
        created_at=created_at or _now(),
    )


def evaluate_escalation(
    *,
    policy_evaluations: Iterable[Any] | None = None,
    risk_score: float = 0.0,
    confidence_score: float = 0.0,
    drift_severity: str | None = None,
    topology_risk: float = 0.0,
    attribution_state: str = "unknown",
    runtime_health_state: str = "unknown",
    source_mode: str = "unknown",
    now: str | None = None,
) -> EscalationDecisionPreview:
    policies = [_as_dict(row) for row in policy_evaluations or []]
    matched_count = sum(1 for row in policies if bool(row.get("matched")))
    approval_count = sum(1 for row in policies if bool(row.get("matched")) and bool(row.get("approval_required")))
    base_confidence = _clamp(confidence_score)
    policy_confidence = _policy_confidence(policies)
    confidence = _clamp((base_confidence + policy_confidence) / 2 if policies else base_confidence)
    risk = _clamp(_clamp(risk_score) + min(0.18, matched_count * 0.06) + _severity_bonus(drift_severity) + (_clamp(topology_risk) * 0.12))

    blockers: list[str] = []
    health = str(runtime_health_state or "unknown").lower()
    if health in {"blocked", "unsafe", "unavailable"}:
        blockers.append(f"runtime_health:{health}")
    if confidence < 0.35 and risk >= 0.65:
        blockers.append("low_confidence_high_risk")

    if blockers:
        state = "blocked_by_safety"
        next_step = "collect_more_evidence"
        reason = "safety blockers prevent escalation beyond review"
    elif risk < 0.25:
        state = "none"
        next_step = "continue_monitoring"
        reason = "risk below escalation threshold"
    elif risk < 0.5 or confidence < 0.45:
        state = "monitor"
        next_step = "continue_monitoring"
        reason = "risk or confidence supports monitoring only"
    elif approval_count or risk >= 0.72:
        state = "approval_required"
        next_step = "request_operator_approval_preview"
        reason = "matched policy or elevated risk requires operator approval"
    elif risk >= 0.62 and str(attribution_state or "").lower() in {"conflicting", "unattributed", "unknown"}:
        state = "escalation_candidate"
        next_step = "prepare_supervised_response_preview"
        reason = "risk and attribution uncertainty warrant supervised review"
    else:
        state = "review_required"
        next_step = "operator_review"
        reason = "context warrants operator review"

    actions = _operator_actions(state, matched_count, attribution_state)
    material = deterministic_escalation_json(
        {
            "state": state,
            "risk": risk,
            "confidence": confidence,
            "matched": matched_count,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    return EscalationDecisionPreview(
        escalation_id="escalation-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        escalation_state=state,
        escalation_reason=reason,
        confidence_score=confidence,
        safety_blockers=blockers,
        operator_actions=actions,
        recommended_next_step=next_step,
        preview_only=True,
        destructive_action=False,
        source_mode=source_mode,
        created_at=now or _now(),
    )


def escalation_decision_to_dict(decision: EscalationDecisionPreview) -> dict[str, Any]:
    return {
        "record_type": "adaptive_remediation_escalation_preview",
        "escalation_id": decision.escalation_id,
        "escalation_state": decision.escalation_state,
        "escalation_reason": decision.escalation_reason,
        "confidence_score": decision.confidence_score,
        "safety_blockers": list(decision.safety_blockers),
        "operator_actions": list(decision.operator_actions),
        "recommended_next_step": decision.recommended_next_step,
        "preview_only": decision.preview_only,
        "destructive_action": decision.destructive_action,
        "source_mode": decision.source_mode,
        "created_at": decision.created_at,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_escalation_summary(decisions: Iterable[EscalationDecisionPreview]) -> dict[str, Any]:
    rows = list(decisions or [])
    by_state: dict[str, int] = {}
    for row in rows:
        by_state[row.escalation_state] = by_state.get(row.escalation_state, 0) + 1
    return {
        "record_type": "adaptive_remediation_escalation_summary",
        "decision_count": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "blocked_by_safety_count": by_state.get("blocked_by_safety", 0),
        "approval_required_count": by_state.get("approval_required", 0),
        "max_confidence_score": max((row.confidence_score for row in rows), default=0.0),
        "preview_only": True,
        "destructive_action": False,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def deterministic_escalation_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _operator_actions(state: str, matched_count: int, attribution_state: str) -> list[str]:
    actions = ["review_evidence_summary"]
    if matched_count:
        actions.append("review_matched_policies")
    if state in {"approval_required", "escalation_candidate", "blocked_by_safety"}:
        actions.append("confirm_rollback_preview_before_future_action")
    if str(attribution_state or "").lower() in {"conflicting", "unattributed", "unknown"}:
        actions.append("verify_process_service_attribution")
    return actions


def _policy_confidence(rows: list[dict[str, Any]]) -> float:
    values = [_clamp(row.get("confidence_score")) for row in rows if row.get("matched")]
    if not values:
        return 0.0
    return _clamp(sum(values) / len(values))


def _severity_bonus(severity: Any) -> float:
    normalized = str(severity or "").lower()
    return {"low": 0.02, "medium": 0.06, "moderate": 0.08, "high": 0.12, "critical": 0.18, "major_drift": 0.14}.get(
        normalized, 0.0
    )


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise EscalationError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _clamp(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0.0
    return round(max(0.0, min(1.0, numeric)), 3)


def _as_dict(row: Any) -> dict[str, Any]:
    if isinstance(row, dict):
        return row
    if hasattr(row, "__dict__"):
        return dict(row.__dict__)
    to_dict = getattr(row, "to_dict", None)
    if callable(to_dict):
        value = to_dict()
        if isinstance(value, dict):
            return value
    return {}


def _json_safe(value: Any) -> Any:
    if isinstance(value, EscalationDecisionPreview):
        return escalation_decision_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
