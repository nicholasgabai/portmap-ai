from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


RISK_ESCALATION_STATES = frozenset(
    {
        "none",
        "monitor",
        "investigate",
        "review_required",
        "approval_required",
        "blocked_by_safety",
        "unknown",
    }
)
SEVERITY_LEVELS = frozenset({"info", "low", "medium", "high", "critical", "unknown"})


class RiskEscalationError(ValueError):
    """Raised when risk escalation preview input violates advisory-only constraints."""


@dataclass(slots=True)
class RiskEscalationRecord:
    escalation_pipeline_id: str
    escalation_state: str
    input_signal_count: int
    combined_risk_score: float
    confidence_score: float
    severity_level: str
    escalation_reason: str
    supporting_signals: list[str] = field(default_factory=list)
    policy_matches: list[str] = field(default_factory=list)
    remediation_recommendations: list[str] = field(default_factory=list)
    attribution_signals: list[str] = field(default_factory=list)
    drift_signals: list[str] = field(default_factory=list)
    topology_signals: list[str] = field(default_factory=list)
    runtime_health_signals: list[str] = field(default_factory=list)
    provider_readiness_signals: list[str] = field(default_factory=list)
    safety_blockers: list[str] = field(default_factory=list)
    operator_actions: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.escalation_pipeline_id, "escalation_pipeline_id")
        if self.escalation_state not in RISK_ESCALATION_STATES:
            raise RiskEscalationError(f"unsupported escalation_state: {self.escalation_state}")
        if not isinstance(self.input_signal_count, int) or self.input_signal_count < 0:
            raise RiskEscalationError("input_signal_count must be a non-negative integer")
        self.combined_risk_score = _clamp(self.combined_risk_score)
        self.confidence_score = _clamp(self.confidence_score)
        if self.severity_level not in SEVERITY_LEVELS:
            raise RiskEscalationError(f"unsupported severity_level: {self.severity_level}")
        _required_str(self.escalation_reason, "escalation_reason")
        for field_name in (
            "supporting_signals",
            "policy_matches",
            "remediation_recommendations",
            "attribution_signals",
            "drift_signals",
            "topology_signals",
            "runtime_health_signals",
            "provider_readiness_signals",
            "safety_blockers",
            "operator_actions",
        ):
            if not _is_string_list(getattr(self, field_name)):
                raise RiskEscalationError(f"{field_name} must be a list of strings")
        if not self.preview_only:
            raise RiskEscalationError("risk escalation records must remain preview_only")
        if self.destructive_action:
            raise RiskEscalationError("risk escalation records cannot be destructive")
        _required_str(self.source_mode, "source_mode")


def build_risk_escalation(
    *,
    policy_evaluations: Iterable[Any] | None = None,
    remediation_recommendations: Iterable[Any] | None = None,
    flow_signals: Iterable[Any] | None = None,
    attribution_signals: Iterable[Any] | None = None,
    drift_signals: Iterable[Any] | None = None,
    topology_signals: Iterable[Any] | None = None,
    runtime_health_signals: Iterable[Any] | None = None,
    provider_readiness_signals: Iterable[Any] | None = None,
    source_mode: str = "unknown",
    now: str | None = None,
) -> RiskEscalationRecord:
    policies = [_as_dict(row) for row in policy_evaluations or []]
    remediations = [_as_dict(row) for row in remediation_recommendations or []]
    flows = [_as_dict(row) for row in flow_signals or []]
    attributions = [_as_dict(row) for row in attribution_signals or []]
    drifts = [_as_dict(row) for row in drift_signals or []]
    topology = [_as_dict(row) for row in topology_signals or []]
    health = [_as_dict(row) for row in runtime_health_signals or []]
    providers = [_as_dict(row) for row in provider_readiness_signals or []]

    policy_matches = [row for row in policies if bool(row.get("matched"))]
    risk_components = [
        _max_number(remediations, "risk_score"),
        min(0.18, len(policy_matches) * 0.06),
        _max_number(flows, "risk_score", "relationship_strength", "recurrence_score") * 0.5,
        _attribution_risk(attributions),
        _max_severity_risk(drifts),
        _max_number(topology, "topology_risk", "spread_potential", "relationship_strength") * 0.8,
        _health_risk(health),
        _provider_risk(providers),
    ]
    combined_risk = _clamp(sum(value for value in risk_components if value is not None))
    confidence = _confidence_average(policies, remediations, flows, attributions, drifts, topology)
    blockers = _safety_blockers(remediations, health, providers)
    state = _state_for(combined_risk, confidence, blockers, policy_matches, remediations)
    severity = _severity_for(combined_risk, blockers)
    reason = _reason_for(state, combined_risk, confidence, blockers)
    signal_count = sum(len(rows) for rows in (policies, remediations, flows, attributions, drifts, topology, health, providers))
    supporting = _supporting_signals(policy_matches, remediations, flows, attributions, drifts, topology, health, providers)
    material = deterministic_risk_escalation_json(
        {
            "state": state,
            "risk": combined_risk,
            "confidence": confidence,
            "signals": supporting,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    return RiskEscalationRecord(
        escalation_pipeline_id="risk-escalation-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        escalation_state=state,
        input_signal_count=signal_count,
        combined_risk_score=combined_risk,
        confidence_score=confidence,
        severity_level=severity,
        escalation_reason=reason,
        supporting_signals=supporting,
        policy_matches=_refs(policy_matches, "policy_id"),
        remediation_recommendations=_refs(remediations, "recommendation_id"),
        attribution_signals=_refs(attributions, "attribution_id", "process_correlation_id"),
        drift_signals=_refs(drifts, "drift_id", "environment_drift_id"),
        topology_signals=_refs(topology, "relationship_id", "dependency_id", "trust_zone_id"),
        runtime_health_signals=_refs(health, "health_id", "runtime_health_id", "record_type", prefix="health"),
        provider_readiness_signals=_refs(providers, "provider_name"),
        safety_blockers=blockers,
        operator_actions=_operator_actions(state, blockers),
        preview_only=True,
        destructive_action=False,
        source_mode=source_mode,
        created_at=now or _now(),
    )


def risk_escalation_to_dict(record: RiskEscalationRecord) -> dict[str, Any]:
    return {
        "record_type": "risk_escalation_pipeline",
        "escalation_pipeline_id": record.escalation_pipeline_id,
        "escalation_state": record.escalation_state,
        "input_signal_count": record.input_signal_count,
        "combined_risk_score": record.combined_risk_score,
        "confidence_score": record.confidence_score,
        "severity_level": record.severity_level,
        "escalation_reason": record.escalation_reason,
        "supporting_signals": list(record.supporting_signals),
        "policy_matches": list(record.policy_matches),
        "remediation_recommendations": list(record.remediation_recommendations),
        "attribution_signals": list(record.attribution_signals),
        "drift_signals": list(record.drift_signals),
        "topology_signals": list(record.topology_signals),
        "runtime_health_signals": list(record.runtime_health_signals),
        "provider_readiness_signals": list(record.provider_readiness_signals),
        "safety_blockers": list(record.safety_blockers),
        "operator_actions": list(record.operator_actions),
        "preview_only": record.preview_only,
        "destructive_action": record.destructive_action,
        "source_mode": record.source_mode,
        "created_at": record.created_at,
        "candidate_only": True,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_risk_escalation_summary(records: Iterable[RiskEscalationRecord]) -> dict[str, Any]:
    rows = list(records or [])
    by_state: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for row in rows:
        by_state[row.escalation_state] = by_state.get(row.escalation_state, 0) + 1
        by_severity[row.severity_level] = by_severity.get(row.severity_level, 0) + 1
    return {
        "record_type": "risk_escalation_summary",
        "pipeline_count": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "blocked_by_safety_count": by_state.get("blocked_by_safety", 0),
        "approval_required_count": by_state.get("approval_required", 0),
        "max_combined_risk_score": max((row.combined_risk_score for row in rows), default=0.0),
        "max_confidence_score": max((row.confidence_score for row in rows), default=0.0),
        "preview_only": True,
        "destructive_action": False,
        "candidate_only": True,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def deterministic_risk_escalation_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _state_for(
    risk: float,
    confidence: float,
    blockers: list[str],
    policy_matches: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
) -> str:
    if blockers:
        return "blocked_by_safety"
    if risk <= 0.0 and confidence <= 0.0:
        return "unknown"
    if risk < 0.25:
        return "none"
    if risk < 0.45 or confidence < 0.35:
        return "monitor"
    if risk < 0.62:
        return "investigate"
    if any(bool(row.get("approval_required")) for row in policy_matches + remediations) or risk >= 0.78:
        return "approval_required"
    return "review_required"


def _severity_for(risk: float, blockers: list[str]) -> str:
    if blockers:
        return "high"
    if risk <= 0.0:
        return "unknown"
    if risk < 0.25:
        return "info"
    if risk < 0.45:
        return "low"
    if risk < 0.68:
        return "medium"
    if risk < 0.88:
        return "high"
    return "critical"


def _reason_for(state: str, risk: float, confidence: float, blockers: list[str]) -> str:
    if blockers:
        return "Safety blockers prevent escalation beyond advisory review."
    if state == "unknown":
        return "No usable risk signals were available."
    if state == "none":
        return "Combined risk remains below escalation thresholds."
    if state == "monitor":
        return "Signals support continued monitoring without escalation."
    if state == "investigate":
        return "Multiple signals warrant investigation but not approval workflow."
    if state == "approval_required":
        return "Combined risk or policy context requires operator approval."
    return f"Combined risk {risk:.2f} and confidence {confidence:.2f} warrant review."


def _supporting_signals(
    policy_matches: list[dict[str, Any]],
    remediations: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    attributions: list[dict[str, Any]],
    drifts: list[dict[str, Any]],
    topology: list[dict[str, Any]],
    health: list[dict[str, Any]],
    providers: list[dict[str, Any]],
) -> list[str]:
    signals: list[str] = []
    if policy_matches:
        signals.append(f"policy_matches:{len(policy_matches)}")
    if remediations:
        types = sorted({str(row.get("recommendation_type") or "unknown") for row in remediations})
        signals.append("remediation_types:" + ",".join(types))
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
    if health:
        states = sorted({str(row.get("health_state") or row.get("runtime_state") or "unknown") for row in health})
        signals.append("runtime_health:" + ",".join(states))
    if providers:
        states = sorted({str(row.get("readiness_state") or "unknown") for row in providers})
        signals.append("provider_readiness:" + ",".join(states))
    return signals or ["no_risk_signals"]


def _operator_actions(state: str, blockers: list[str]) -> list[str]:
    if state == "none":
        return ["continue_monitoring"]
    if state == "monitor":
        return ["monitor_signal_recurrence"]
    actions = ["review_evidence_summary", "confirm_no_enforcement"]
    if state in {"review_required", "approval_required", "blocked_by_safety"}:
        actions.append("review_operator_approval_requirements")
    if blockers:
        actions.append("resolve_safety_blockers")
    return actions


def _safety_blockers(
    remediations: list[dict[str, Any]],
    health: list[dict[str, Any]],
    providers: list[dict[str, Any]],
) -> list[str]:
    blockers: list[str] = []
    for row in remediations:
        if row.get("destructive_action") or row.get("preview_only") is False:
            blockers.append("unsafe_remediation_record")
        for blocker in row.get("safety_blockers") or []:
            blockers.append(str(blocker))
    for row in health:
        state = str(row.get("health_state") or row.get("runtime_state") or "").lower()
        if state in {"blocked", "unsafe", "unavailable"}:
            blockers.append(f"runtime_health:{state}")
    for row in providers:
        state = str(row.get("readiness_state") or "").lower()
        if state in {"unavailable", "unknown"}:
            blockers.append(f"provider_state:{state}")
        if row.get("dry_run_supported") is False:
            blockers.append("provider_dry_run_unavailable")
    return sorted(set(blockers))


def _confidence_average(*groups: list[dict[str, Any]]) -> float:
    values: list[float] = []
    for rows in groups:
        for row in rows:
            for key in (
                "confidence_score",
                "metadata_confidence",
                "reconstruction_confidence",
                "attribution_confidence",
                "relationship_confidence",
            ):
                if key in row:
                    values.append(_clamp(row.get(key)))
                    break
    if not values:
        return 0.0
    return _clamp(sum(values) / len(values))


def _max_number(rows: list[dict[str, Any]], *keys: str) -> float:
    values: list[float] = []
    for row in rows:
        for key in keys:
            if key in row:
                values.append(_clamp(row.get(key)))
    return max(values, default=0.0)


def _max_severity_risk(rows: list[dict[str, Any]]) -> float:
    return max((_severity_risk(row.get("drift_severity") or row.get("severity")) for row in rows), default=0.0)


def _severity_risk(severity: Any) -> float:
    normalized = str(severity or "").lower()
    return {
        "info": 0.02,
        "low": 0.05,
        "medium": 0.12,
        "moderate": 0.14,
        "high": 0.22,
        "critical": 0.3,
        "major_drift": 0.24,
    }.get(normalized, 0.0)


def _attribution_risk(rows: list[dict[str, Any]]) -> float:
    values = []
    for row in rows:
        state = str(row.get("attribution_state") or "").lower()
        if state in {"conflicting", "unattributed", "unknown"}:
            values.append(0.12)
        elif state in {"partially_attributed", "possible"}:
            values.append(0.06)
    return max(values, default=0.0)


def _health_risk(rows: list[dict[str, Any]]) -> float:
    values = []
    for row in rows:
        state = str(row.get("health_state") or row.get("runtime_state") or "").lower()
        values.append({"healthy": 0.0, "degraded": 0.08, "unhealthy": 0.16, "blocked": 0.22, "unsafe": 0.24}.get(state, 0.0))
    return max(values, default=0.0)


def _provider_risk(rows: list[dict[str, Any]]) -> float:
    values = []
    for row in rows:
        state = str(row.get("readiness_state") or "").lower()
        values.append({"ready": 0.0, "degraded": 0.05, "unavailable": 0.12, "unknown": 0.08}.get(state, 0.0))
    return max(values, default=0.0)


def _refs(rows: Iterable[dict[str, Any]], *keys: str, prefix: str | None = None) -> list[str]:
    refs: list[str] = []
    for row in rows:
        for key in keys:
            value = row.get(key)
            if value:
                refs.append(f"{prefix}:{value}" if prefix and key == "record_type" else str(value))
                break
    return sorted(set(refs))


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


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RiskEscalationError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _clamp(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0.0
    return round(max(0.0, min(1.0, numeric)), 3)


def _json_safe(value: Any) -> Any:
    if isinstance(value, RiskEscalationRecord):
        return risk_escalation_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
