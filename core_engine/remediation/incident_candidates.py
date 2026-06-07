from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.remediation.risk_escalation import RiskEscalationRecord, risk_escalation_to_dict


INCIDENT_CANDIDATE_TYPES = frozenset(
    {
        "exposed_service_review",
        "unusual_flow_review",
        "attribution_conflict_review",
        "drift_review",
        "topology_risk_review",
        "runtime_health_review",
        "containment_readiness_review",
    }
)
INCIDENT_CANDIDATE_STATES = frozenset({"informational", "candidate", "needs_review", "blocked_by_safety", "unknown"})
INCIDENT_SEVERITY_LEVELS = frozenset({"info", "low", "medium", "high", "critical", "unknown"})


class IncidentCandidateError(ValueError):
    """Raised when incident candidate preview input is malformed or unsafe."""


@dataclass(slots=True)
class IncidentCandidateRecord:
    candidate_id: str
    candidate_type: str
    candidate_state: str
    severity_level: str
    confidence_score: float
    related_escalation_ids: list[str] = field(default_factory=list)
    related_flow_references: list[str] = field(default_factory=list)
    related_policy_ids: list[str] = field(default_factory=list)
    related_topology_references: list[str] = field(default_factory=list)
    evidence_summary: list[str] = field(default_factory=list)
    operator_summary: str = "Candidate requires operator review."
    recommended_next_step: str = "review_evidence_summary"
    approval_required: bool = True
    preview_only: bool = True
    destructive_action: bool = False
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.candidate_id, "candidate_id")
        if self.candidate_type not in INCIDENT_CANDIDATE_TYPES:
            raise IncidentCandidateError(f"unsupported candidate_type: {self.candidate_type}")
        if self.candidate_state not in INCIDENT_CANDIDATE_STATES:
            raise IncidentCandidateError(f"unsupported candidate_state: {self.candidate_state}")
        if self.severity_level not in INCIDENT_SEVERITY_LEVELS:
            raise IncidentCandidateError(f"unsupported severity_level: {self.severity_level}")
        self.confidence_score = _clamp(self.confidence_score)
        for field_name in (
            "related_escalation_ids",
            "related_flow_references",
            "related_policy_ids",
            "related_topology_references",
            "evidence_summary",
        ):
            if not _is_string_list(getattr(self, field_name)):
                raise IncidentCandidateError(f"{field_name} must be a list of strings")
        _required_str(self.operator_summary, "operator_summary")
        _required_str(self.recommended_next_step, "recommended_next_step")
        if not isinstance(self.approval_required, bool):
            raise IncidentCandidateError("approval_required must be boolean")
        if not self.preview_only:
            raise IncidentCandidateError("incident candidates must remain preview_only")
        if self.destructive_action:
            raise IncidentCandidateError("incident candidates cannot be destructive")
        _required_str(self.source_mode, "source_mode")


def build_incident_candidate(
    escalation: RiskEscalationRecord | dict[str, Any],
    *,
    candidate_type: str | None = None,
    source_mode: str = "unknown",
    now: str | None = None,
) -> IncidentCandidateRecord:
    row = _as_escalation_dict(escalation)
    selected_type = candidate_type if candidate_type in INCIDENT_CANDIDATE_TYPES else _candidate_type(row)
    state = _candidate_state(row)
    severity = str(row.get("severity_level") or "unknown")
    confidence = _clamp(row.get("confidence_score"))
    related_escalation_ids = [str(row.get("escalation_pipeline_id"))] if row.get("escalation_pipeline_id") else []
    flow_refs = _list(row.get("supporting_signals"), prefix="flow_signals:")
    flow_refs.extend(_list(row.get("flow_references")))
    policy_ids = _list(row.get("policy_matches"))
    topology_refs = _list(row.get("topology_signals"))
    evidence = _evidence_summary(row)
    material = deterministic_incident_candidate_json(
        {
            "type": selected_type,
            "state": state,
            "severity": severity,
            "escalations": related_escalation_ids,
            "evidence": evidence,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    return IncidentCandidateRecord(
        candidate_id="incident-candidate-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        candidate_type=selected_type,
        candidate_state=state,
        severity_level=severity if severity in INCIDENT_SEVERITY_LEVELS else "unknown",
        confidence_score=confidence,
        related_escalation_ids=related_escalation_ids,
        related_flow_references=sorted(set(flow_refs)),
        related_policy_ids=policy_ids,
        related_topology_references=topology_refs,
        evidence_summary=evidence,
        operator_summary=_operator_summary(selected_type, state),
        recommended_next_step=_recommended_next_step(state),
        approval_required=state in {"needs_review", "blocked_by_safety"},
        preview_only=True,
        destructive_action=False,
        source_mode=source_mode,
        created_at=now or _now(),
    )


def build_incident_candidates(
    escalations: Iterable[RiskEscalationRecord | dict[str, Any]],
    *,
    source_mode: str = "unknown",
    now: str | None = None,
) -> list[IncidentCandidateRecord]:
    return [build_incident_candidate(row, source_mode=source_mode, now=now) for row in escalations]


def incident_candidate_to_dict(candidate: IncidentCandidateRecord) -> dict[str, Any]:
    return {
        "record_type": "incident_candidate",
        "candidate_id": candidate.candidate_id,
        "candidate_type": candidate.candidate_type,
        "candidate_state": candidate.candidate_state,
        "severity_level": candidate.severity_level,
        "confidence_score": candidate.confidence_score,
        "related_escalation_ids": list(candidate.related_escalation_ids),
        "related_flow_references": list(candidate.related_flow_references),
        "related_policy_ids": list(candidate.related_policy_ids),
        "related_topology_references": list(candidate.related_topology_references),
        "evidence_summary": list(candidate.evidence_summary),
        "operator_summary": candidate.operator_summary,
        "recommended_next_step": candidate.recommended_next_step,
        "approval_required": candidate.approval_required,
        "preview_only": candidate.preview_only,
        "destructive_action": candidate.destructive_action,
        "source_mode": candidate.source_mode,
        "created_at": candidate.created_at,
        "candidate_only": True,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_incident_candidate_summary(candidates: Iterable[IncidentCandidateRecord]) -> dict[str, Any]:
    rows = list(candidates or [])
    by_type: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for row in rows:
        by_type[row.candidate_type] = by_type.get(row.candidate_type, 0) + 1
        by_state[row.candidate_state] = by_state.get(row.candidate_state, 0) + 1
    return {
        "record_type": "incident_candidate_summary",
        "candidate_count": len(rows),
        "by_type": dict(sorted(by_type.items())),
        "by_state": dict(sorted(by_state.items())),
        "approval_required_count": sum(1 for row in rows if row.approval_required),
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


def deterministic_incident_candidate_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _candidate_type(row: dict[str, Any]) -> str:
    signals = " ".join(str(item) for item in row.get("supporting_signals") or [])
    if "provider_readiness" in signals:
        return "containment_readiness_review"
    if "runtime_health" in signals:
        return "runtime_health_review"
    if row.get("topology_signals"):
        return "topology_risk_review"
    if row.get("drift_signals"):
        return "drift_review"
    if "attribution_states:conflicting" in signals or "attribution_states:unattributed" in signals:
        return "attribution_conflict_review"
    if "flow_signals" in signals:
        return "unusual_flow_review"
    return "exposed_service_review" if row.get("policy_matches") else "runtime_health_review"


def _candidate_state(row: dict[str, Any]) -> str:
    state = str(row.get("escalation_state") or "unknown")
    if state == "blocked_by_safety":
        return "blocked_by_safety"
    if state in {"approval_required", "review_required"}:
        return "needs_review"
    if state in {"investigate", "monitor"}:
        return "candidate"
    if state == "none":
        return "informational"
    return "unknown"


def _evidence_summary(row: dict[str, Any]) -> list[str]:
    evidence = []
    for key in (
        "supporting_signals",
        "policy_matches",
        "remediation_recommendations",
        "drift_signals",
        "topology_signals",
        "provider_readiness_signals",
        "safety_blockers",
    ):
        values = row.get(key) or []
        if values:
            evidence.append(f"{key}:{len(values)}")
    return evidence or ["no_evidence_summary"]


def _operator_summary(candidate_type: str, state: str) -> str:
    return f"{candidate_type} is an advisory incident candidate in {state} state; no final verdict or response is executed."


def _recommended_next_step(state: str) -> str:
    if state == "blocked_by_safety":
        return "resolve_safety_blockers"
    if state == "needs_review":
        return "operator_review_required"
    if state == "candidate":
        return "investigate_candidate"
    if state == "informational":
        return "continue_monitoring"
    return "collect_additional_context"


def _as_escalation_dict(row: RiskEscalationRecord | dict[str, Any]) -> dict[str, Any]:
    if isinstance(row, RiskEscalationRecord):
        return risk_escalation_to_dict(row)
    if isinstance(row, dict):
        return dict(row)
    return {}


def _list(value: Any, *, prefix: str | None = None) -> list[str]:
    rows = value if isinstance(value, list) else []
    if prefix:
        return [str(item).split(prefix, 1)[1] for item in rows if str(item).startswith(prefix)]
    return [str(item) for item in rows if item]


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise IncidentCandidateError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _clamp(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0.0
    return round(max(0.0, min(1.0, numeric)), 3)


def _json_safe(value: Any) -> Any:
    if isinstance(value, IncidentCandidateRecord):
        return incident_candidate_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
