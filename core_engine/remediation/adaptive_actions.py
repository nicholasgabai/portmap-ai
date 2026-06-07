from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


RECOMMENDATION_TYPES = frozenset(
    {
        "monitor",
        "review",
        "rate_limit_preview",
        "quarantine_preview",
        "block_preview",
        "isolate_node_preview",
    }
)
SAFE_ENFORCEMENT_MODES = frozenset({"monitor", "advisory", "dry_run", "supervised_preview"})
UNSAFE_ACTION_TOKENS = frozenset(
    {
        "apply",
        "block_now",
        "quarantine_now",
        "isolate_now",
        "disable",
        "kill",
        "delete",
        "execute",
        "enforce",
        "modify_firewall",
        "stop_service",
    }
)


class RemediationError(ValueError):
    """Raised when a remediation preview would violate safety constraints."""


@dataclass(slots=True)
class RemediationRecommendation:
    recommendation_id: str
    recommendation_type: str
    recommended_action: str
    action_class: str
    confidence_score: float
    risk_score: float
    supporting_signals: list[str] = field(default_factory=list)
    policy_references: list[str] = field(default_factory=list)
    flow_references: list[str] = field(default_factory=list)
    attribution_references: list[str] = field(default_factory=list)
    drift_references: list[str] = field(default_factory=list)
    topology_references: list[str] = field(default_factory=list)
    approval_required: bool = True
    enforcement_mode: str = "dry_run"
    preview_only: bool = True
    destructive_action: bool = False
    rollback_required: bool = True
    advisory_notes: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.recommendation_id, "recommendation_id")
        if self.recommendation_type not in RECOMMENDATION_TYPES:
            raise RemediationError(f"unsupported recommendation_type: {self.recommendation_type}")
        _validate_safe_action(self.recommended_action)
        _required_str(self.action_class, "action_class")
        self.confidence_score = _clamp(self.confidence_score)
        self.risk_score = _clamp(self.risk_score)
        for field_name in (
            "supporting_signals",
            "policy_references",
            "flow_references",
            "attribution_references",
            "drift_references",
            "topology_references",
            "advisory_notes",
        ):
            if not _is_string_list(getattr(self, field_name)):
                raise RemediationError(f"{field_name} must be a list of strings")
        if self.enforcement_mode not in SAFE_ENFORCEMENT_MODES:
            raise RemediationError(f"unsafe enforcement_mode: {self.enforcement_mode}")
        if not self.preview_only:
            raise RemediationError("remediation recommendations must remain preview_only")
        if self.destructive_action:
            raise RemediationError("remediation recommendations cannot be destructive")
        if not isinstance(self.approval_required, bool):
            raise RemediationError("approval_required must be boolean")
        if not isinstance(self.rollback_required, bool):
            raise RemediationError("rollback_required must be boolean")
        _required_str(self.source_mode, "source_mode")


def create_remediation_recommendation(
    *,
    recommendation_id: str,
    recommendation_type: str,
    recommended_action: str,
    action_class: str = "operator_review",
    confidence_score: float = 0.0,
    risk_score: float = 0.0,
    supporting_signals: list[str] | None = None,
    policy_references: list[str] | None = None,
    flow_references: list[str] | None = None,
    attribution_references: list[str] | None = None,
    drift_references: list[str] | None = None,
    topology_references: list[str] | None = None,
    approval_required: bool = True,
    enforcement_mode: str = "dry_run",
    preview_only: bool = True,
    destructive_action: bool = False,
    rollback_required: bool = True,
    advisory_notes: list[str] | None = None,
    source_mode: str = "unknown",
    created_at: str | None = None,
) -> RemediationRecommendation:
    return RemediationRecommendation(
        recommendation_id=recommendation_id,
        recommendation_type=recommendation_type,
        recommended_action=recommended_action,
        action_class=action_class,
        confidence_score=confidence_score,
        risk_score=risk_score,
        supporting_signals=supporting_signals or [],
        policy_references=policy_references or [],
        flow_references=flow_references or [],
        attribution_references=attribution_references or [],
        drift_references=drift_references or [],
        topology_references=topology_references or [],
        approval_required=approval_required,
        enforcement_mode=enforcement_mode,
        preview_only=preview_only,
        destructive_action=destructive_action,
        rollback_required=rollback_required,
        advisory_notes=advisory_notes or [],
        source_mode=source_mode,
        created_at=created_at or _now(),
    )


def recommendation_to_dict(recommendation: RemediationRecommendation) -> dict[str, Any]:
    return {
        "record_type": "adaptive_remediation_recommendation",
        "recommendation_id": recommendation.recommendation_id,
        "recommendation_type": recommendation.recommendation_type,
        "recommended_action": recommendation.recommended_action,
        "action_class": recommendation.action_class,
        "confidence_score": recommendation.confidence_score,
        "risk_score": recommendation.risk_score,
        "supporting_signals": list(recommendation.supporting_signals),
        "policy_references": list(recommendation.policy_references),
        "flow_references": list(recommendation.flow_references),
        "attribution_references": list(recommendation.attribution_references),
        "drift_references": list(recommendation.drift_references),
        "topology_references": list(recommendation.topology_references),
        "approval_required": recommendation.approval_required,
        "enforcement_mode": recommendation.enforcement_mode,
        "preview_only": recommendation.preview_only,
        "destructive_action": recommendation.destructive_action,
        "rollback_required": recommendation.rollback_required,
        "advisory_notes": list(recommendation.advisory_notes),
        "source_mode": recommendation.source_mode,
        "created_at": recommendation.created_at,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_adaptive_recommendation(
    *,
    policy_evaluations: Iterable[Any] | None = None,
    risk_score: float = 0.0,
    confidence_score: float = 0.0,
    flow_context: Iterable[Any] | None = None,
    attribution_context: Iterable[Any] | None = None,
    drift_context: Iterable[Any] | None = None,
    topology_context: Iterable[Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    source_mode: str = "unknown",
    now: str | None = None,
) -> RemediationRecommendation:
    policies = [_as_dict(row) for row in policy_evaluations or []]
    flows = [_as_dict(row) for row in flow_context or []]
    attributions = [_as_dict(row) for row in attribution_context or []]
    drifts = [_as_dict(row) for row in drift_context or []]
    topology = [_as_dict(row) for row in topology_context or []]
    health = runtime_health or {}

    matched_policies = [row for row in policies if bool(row.get("matched"))]
    policy_confidence = _average(_number(row.get("confidence_score")) for row in matched_policies)
    signal_confidence = _average(
        value
        for value in [
            _number(confidence_score),
            policy_confidence if matched_policies else None,
            _optional_average(_number(row.get("reconstruction_confidence") or row.get("confidence_score")) for row in flows),
            _optional_average(
                _number(row.get("attribution_confidence") or row.get("confidence_score")) for row in attributions
            ),
            _optional_average(_number(row.get("confidence_score")) for row in drifts),
            _optional_average(_number(row.get("relationship_confidence") or row.get("confidence_score")) for row in topology),
        ]
        if value is not None
    )
    combined_risk = _combined_risk(risk_score, matched_policies, drifts, topology, health)
    rec_type = _select_recommendation_type(combined_risk, signal_confidence, matched_policies, health)
    supporting = _supporting_signals(matched_policies, flows, attributions, drifts, topology, health)
    action = _action_for_type(rec_type)
    material = deterministic_adaptive_remediation_json(
        {
            "type": rec_type,
            "risk": combined_risk,
            "confidence": signal_confidence,
            "signals": supporting,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    notes = [
        "Recommendation is advisory-only and preview-only.",
        "Operator approval is required before any future response workflow.",
    ]
    if signal_confidence < 0.5:
        notes.append("Low confidence kept the recommendation at monitor or review strength.")
    if combined_risk >= 0.8:
        notes.append("High risk increases urgency but does not permit automatic blocking.")

    return RemediationRecommendation(
        recommendation_id="remediation-rec-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        recommendation_type=rec_type,
        recommended_action=action,
        action_class="supervised_response_preview",
        confidence_score=signal_confidence,
        risk_score=combined_risk,
        supporting_signals=supporting,
        policy_references=_refs(matched_policies, "policy_id"),
        flow_references=_refs(flows, "flow_reference", "flow_id", "session_reference", "session_id"),
        attribution_references=_refs(attributions, "attribution_id", "process_correlation_id"),
        drift_references=_refs(drifts, "drift_id", "environment_drift_id"),
        topology_references=_refs(topology, "relationship_id", "dependency_id", "trust_zone_id"),
        approval_required=True,
        enforcement_mode="dry_run",
        preview_only=True,
        destructive_action=False,
        rollback_required=rec_type not in {"monitor", "review"},
        advisory_notes=notes,
        source_mode=source_mode,
        created_at=now or _now(),
    )


def build_adaptive_recommendation_summary(
    recommendations: Iterable[RemediationRecommendation],
) -> dict[str, Any]:
    rows = list(recommendations or [])
    by_type: dict[str, int] = {}
    for row in rows:
        by_type[row.recommendation_type] = by_type.get(row.recommendation_type, 0) + 1
    return {
        "record_type": "adaptive_remediation_summary",
        "recommendation_count": len(rows),
        "by_type": dict(sorted(by_type.items())),
        "approval_required_count": sum(1 for row in rows if row.approval_required),
        "rollback_required_count": sum(1 for row in rows if row.rollback_required),
        "max_risk_score": max((row.risk_score for row in rows), default=0.0),
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


def deterministic_adaptive_remediation_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _select_recommendation_type(
    risk: float,
    confidence: float,
    matched_policies: list[dict[str, Any]],
    runtime_health: dict[str, Any],
) -> str:
    if _health_is_blocking(runtime_health):
        return "review"
    if confidence < 0.35 or risk < 0.35:
        return "monitor"
    if confidence < 0.6:
        return "review"
    if risk >= 0.9 and len(matched_policies) >= 2:
        return "quarantine_preview"
    if risk >= 0.82:
        return "block_preview"
    if risk >= 0.68:
        return "rate_limit_preview"
    return "review"


def _combined_risk(
    base_risk: float,
    matched_policies: list[dict[str, Any]],
    drift_rows: list[dict[str, Any]],
    topology_rows: list[dict[str, Any]],
    runtime_health: dict[str, Any],
) -> float:
    risk = _clamp(base_risk)
    risk += min(0.18, len(matched_policies) * 0.06)
    risk += max((_severity_bonus(row.get("drift_severity") or row.get("severity")) for row in drift_rows), default=0.0)
    risk += max((_topology_bonus(row) for row in topology_rows), default=0.0)
    if str(runtime_health.get("health_state") or runtime_health.get("runtime_state") or "").lower() in {"degraded", "unhealthy"}:
        risk += 0.08
    return _clamp(risk)


def _supporting_signals(
    policies: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    attributions: list[dict[str, Any]],
    drifts: list[dict[str, Any]],
    topology: list[dict[str, Any]],
    health: dict[str, Any],
) -> list[str]:
    signals: list[str] = []
    if policies:
        signals.append(f"matched_policies:{len(policies)}")
    if flows:
        signals.append(f"flow_signals:{len(flows)}")
    if attributions:
        states = sorted({str(row.get("attribution_state") or "unknown") for row in attributions})
        signals.append("attribution_states:" + ",".join(states))
    if drifts:
        severities = sorted({str(row.get("drift_severity") or row.get("severity") or "unknown") for row in drifts})
        signals.append("drift_severity:" + ",".join(severities))
    if topology:
        signals.append(f"topology_signals:{len(topology)}")
    health_state = str(health.get("health_state") or health.get("runtime_state") or "")
    if health_state:
        signals.append(f"runtime_health:{health_state}")
    return signals or ["no_supporting_signals"]


def _action_for_type(recommendation_type: str) -> str:
    return {
        "monitor": "continue_monitoring",
        "review": "operator_review",
        "rate_limit_preview": "preview_rate_limit_plan",
        "quarantine_preview": "preview_quarantine_plan",
        "block_preview": "preview_block_plan",
        "isolate_node_preview": "preview_node_isolation_plan",
    }[recommendation_type]


def _refs(rows: Iterable[dict[str, Any]], *keys: str) -> list[str]:
    refs: list[str] = []
    for row in rows:
        for key in keys:
            value = row.get(key)
            if value:
                refs.append(str(value))
                break
    return sorted(set(refs))


def _severity_bonus(severity: Any) -> float:
    normalized = str(severity or "").lower()
    return {"low": 0.02, "medium": 0.06, "moderate": 0.08, "high": 0.12, "critical": 0.18, "major_drift": 0.14}.get(
        normalized, 0.0
    )


def _topology_bonus(row: dict[str, Any]) -> float:
    risk = row.get("topology_risk") or row.get("spread_potential") or row.get("relationship_strength")
    return min(0.12, _clamp(risk) * 0.12)


def _health_is_blocking(runtime_health: dict[str, Any]) -> bool:
    return str(runtime_health.get("health_state") or runtime_health.get("runtime_state") or "").lower() in {
        "blocked",
        "unsafe",
    }


def _average(values: Iterable[Any]) -> float:
    numbers = [_clamp(value) for value in values if value is not None]
    if not numbers:
        return 0.0
    return _clamp(sum(numbers) / len(numbers))


def _optional_average(values: Iterable[Any]) -> float | None:
    numbers = [_clamp(value) for value in values if value is not None]
    if not numbers:
        return None
    return _clamp(sum(numbers) / len(numbers))


def _number(value: Any) -> float | None:
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _validate_safe_action(action: str) -> None:
    _required_str(action, "recommended_action")
    lowered = action.lower()
    if any(token in lowered for token in UNSAFE_ACTION_TOKENS):
        raise RemediationError(f"unsafe recommended_action: {action}")


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RemediationError(f"{field_name} must be a non-empty string")


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
    if isinstance(value, RemediationRecommendation):
        return recommendation_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
