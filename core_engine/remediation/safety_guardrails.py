from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


GUARDRAIL_TYPES = frozenset(
    {
        "approval_gate",
        "rollback_gate",
        "blast_radius_gate",
        "provider_readiness_gate",
        "confidence_gate",
        "runtime_health_gate",
        "policy_scope_gate",
        "emergency_stop_gate",
    }
)
GUARDRAIL_STATES = frozenset({"allowed_preview", "requires_approval", "blocked", "degraded", "unavailable", "unknown"})
BLAST_RADIUS_LEVELS = frozenset({"none", "low", "medium", "high", "critical", "unknown"})


class SafetyGuardrailError(ValueError):
    """Raised when guardrail input violates preview-only safety constraints."""


@dataclass(slots=True)
class SafetyGuardrailEvaluation:
    guardrail_id: str
    guardrail_type: str
    guardrail_state: str
    evaluated_action: str
    action_class: str
    approval_required: bool
    rollback_required: bool
    blast_radius_level: str
    safety_blockers: list[str] = field(default_factory=list)
    operator_actions: list[str] = field(default_factory=list)
    recommended_safe_mode: str = "monitor"
    confidence_score: float = 0.0
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.guardrail_id, "guardrail_id")
        if self.guardrail_type not in GUARDRAIL_TYPES:
            raise SafetyGuardrailError(f"unsupported guardrail_type: {self.guardrail_type}")
        if self.guardrail_state not in GUARDRAIL_STATES:
            raise SafetyGuardrailError(f"unsupported guardrail_state: {self.guardrail_state}")
        _required_str(self.evaluated_action, "evaluated_action")
        _required_str(self.action_class, "action_class")
        if not isinstance(self.approval_required, bool):
            raise SafetyGuardrailError("approval_required must be boolean")
        if not isinstance(self.rollback_required, bool):
            raise SafetyGuardrailError("rollback_required must be boolean")
        if self.blast_radius_level not in BLAST_RADIUS_LEVELS:
            raise SafetyGuardrailError(f"unsupported blast_radius_level: {self.blast_radius_level}")
        if not _is_string_list(self.safety_blockers):
            raise SafetyGuardrailError("safety_blockers must be a list of strings")
        if not _is_string_list(self.operator_actions):
            raise SafetyGuardrailError("operator_actions must be a list of strings")
        _required_str(self.recommended_safe_mode, "recommended_safe_mode")
        self.confidence_score = _clamp(self.confidence_score)
        if not self.preview_only:
            raise SafetyGuardrailError("safety guardrails must remain preview_only")
        if self.destructive_action:
            raise SafetyGuardrailError("safety guardrails cannot be destructive")
        if not _is_string_list(self.advisory_notes):
            raise SafetyGuardrailError("advisory_notes must be a list of strings")
        _required_str(self.source_mode, "source_mode")


def evaluate_guardrail(
    *,
    guardrail_type: str,
    evaluated_action: str,
    action_class: str = "response_preview",
    approval_available: bool = False,
    rollback_available: bool = False,
    rollback_confidence: float = 0.0,
    blast_radius_level: str = "unknown",
    provider_readiness_state: str = "unknown",
    confidence_score: float = 0.0,
    runtime_health_state: str = "unknown",
    policy_scope_state: str = "unknown",
    emergency_stop_active: bool = False,
    source_mode: str = "unknown",
    now: str | None = None,
) -> SafetyGuardrailEvaluation:
    normalized_type = guardrail_type if guardrail_type in GUARDRAIL_TYPES else "policy_scope_gate"
    confidence = _clamp(confidence_score)
    blast = blast_radius_level if blast_radius_level in BLAST_RADIUS_LEVELS else "unknown"
    blockers: list[str] = []
    state = "allowed_preview"
    approval_required = False
    rollback_required = False

    if normalized_type == "emergency_stop_gate" or emergency_stop_active:
        if emergency_stop_active:
            blockers.append("emergency_stop_active")
            state = "blocked"
    if normalized_type == "approval_gate":
        approval_required = True
        state = "allowed_preview" if approval_available else "requires_approval"
        if not approval_available:
            blockers.append("operator_approval_missing")
    elif normalized_type == "rollback_gate":
        rollback_required = True
        if not rollback_available:
            state = "blocked"
            blockers.append("rollback_unavailable")
        elif _clamp(rollback_confidence) < 0.5:
            state = "degraded"
            blockers.append("rollback_confidence_low")
    elif normalized_type == "blast_radius_gate":
        if blast in {"critical", "high"}:
            state = "requires_approval" if blast == "high" else "blocked"
            blockers.append(f"blast_radius:{blast}")
            approval_required = True
            rollback_required = True
    elif normalized_type == "provider_readiness_gate":
        provider_state = str(provider_readiness_state or "unknown").lower()
        if provider_state in {"unavailable", "unknown"}:
            state = "unavailable"
            blockers.append(f"provider_state:{provider_state}")
        elif provider_state == "degraded":
            state = "degraded"
            blockers.append("provider_state:degraded")
    elif normalized_type == "confidence_gate":
        if confidence < 0.35:
            state = "blocked"
            blockers.append("confidence_too_low")
        elif confidence < 0.65:
            state = "degraded"
            blockers.append("confidence_degraded")
    elif normalized_type == "runtime_health_gate":
        health = str(runtime_health_state or "unknown").lower()
        if health in {"blocked", "unsafe", "unavailable"}:
            state = "blocked"
            blockers.append(f"runtime_health:{health}")
        elif health in {"degraded", "unhealthy", "unknown"}:
            state = "degraded"
            blockers.append(f"runtime_health:{health}")
    elif normalized_type == "policy_scope_gate":
        scope = str(policy_scope_state or "unknown").lower()
        if scope in {"blocked", "out_of_scope", "unsafe"}:
            state = "blocked"
            blockers.append(f"policy_scope:{scope}")
        elif scope in {"unknown", "degraded"}:
            state = "degraded"
            blockers.append(f"policy_scope:{scope}")

    if emergency_stop_active and "emergency_stop_active" not in blockers:
        blockers.append("emergency_stop_active")
        state = "blocked"
    safe_mode = _safe_mode_for(state, normalized_type)
    material = deterministic_safety_guardrail_json(
        {
            "type": normalized_type,
            "action": evaluated_action,
            "state": state,
            "blockers": blockers,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    return SafetyGuardrailEvaluation(
        guardrail_id="guardrail-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        guardrail_type=normalized_type,
        guardrail_state=state,
        evaluated_action=evaluated_action,
        action_class=action_class,
        approval_required=approval_required,
        rollback_required=rollback_required,
        blast_radius_level=blast,
        safety_blockers=sorted(set(blockers)),
        operator_actions=_operator_actions(state, approval_required, rollback_required),
        recommended_safe_mode=safe_mode,
        confidence_score=confidence,
        preview_only=True,
        destructive_action=False,
        advisory_notes=_advisory_notes(state, normalized_type),
        source_mode=source_mode,
        created_at=now or _now(),
    )


def guardrail_to_dict(guardrail: SafetyGuardrailEvaluation) -> dict[str, Any]:
    return {
        "record_type": "safety_guardrail_evaluation",
        "guardrail_id": guardrail.guardrail_id,
        "guardrail_type": guardrail.guardrail_type,
        "guardrail_state": guardrail.guardrail_state,
        "evaluated_action": guardrail.evaluated_action,
        "action_class": guardrail.action_class,
        "approval_required": guardrail.approval_required,
        "rollback_required": guardrail.rollback_required,
        "blast_radius_level": guardrail.blast_radius_level,
        "safety_blockers": list(guardrail.safety_blockers),
        "operator_actions": list(guardrail.operator_actions),
        "recommended_safe_mode": guardrail.recommended_safe_mode,
        "confidence_score": guardrail.confidence_score,
        "preview_only": guardrail.preview_only,
        "destructive_action": guardrail.destructive_action,
        "advisory_notes": list(guardrail.advisory_notes),
        "source_mode": guardrail.source_mode,
        "created_at": guardrail.created_at,
        "automatic_changes": False,
        "enforcement_executed": False,
        "rollback_executed": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "files_modified": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_safety_guardrail_summary(guardrails: Iterable[SafetyGuardrailEvaluation]) -> dict[str, Any]:
    rows = list(guardrails or [])
    by_state: dict[str, int] = {}
    by_type: dict[str, int] = {}
    for row in rows:
        by_state[row.guardrail_state] = by_state.get(row.guardrail_state, 0) + 1
        by_type[row.guardrail_type] = by_type.get(row.guardrail_type, 0) + 1
    return {
        "record_type": "safety_guardrail_summary",
        "guardrail_count": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "by_type": dict(sorted(by_type.items())),
        "blocked_count": by_state.get("blocked", 0) + by_state.get("unavailable", 0),
        "approval_required_count": sum(1 for row in rows if row.approval_required),
        "rollback_required_count": sum(1 for row in rows if row.rollback_required),
        "preview_only": True,
        "destructive_action": False,
        "automatic_changes": False,
        "enforcement_executed": False,
        "rollback_executed": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "files_modified": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def deterministic_safety_guardrail_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _safe_mode_for(state: str, guardrail_type: str) -> str:
    if state in {"blocked", "unavailable"}:
        return "monitor"
    if state in {"requires_approval", "degraded"}:
        return "supervised_preview"
    if guardrail_type == "emergency_stop_gate":
        return "monitor"
    return "advisory_preview"


def _operator_actions(state: str, approval_required: bool, rollback_required: bool) -> list[str]:
    actions = ["review_guardrail_evidence", "confirm_preview_only"]
    if approval_required or state == "requires_approval":
        actions.append("obtain_operator_approval")
    if rollback_required:
        actions.append("confirm_rollback_preview")
    if state in {"blocked", "unavailable"}:
        actions.append("resolve_safety_blockers")
    return actions


def _advisory_notes(state: str, guardrail_type: str) -> list[str]:
    notes = [f"{guardrail_type} evaluated in preview-only mode."]
    if state in {"blocked", "unavailable"}:
        notes.append("Future response must not proceed until blockers are resolved.")
    return notes


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise SafetyGuardrailError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _clamp(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0.0
    return round(max(0.0, min(1.0, numeric)), 3)


def _json_safe(value: Any) -> Any:
    if isinstance(value, SafetyGuardrailEvaluation):
        return guardrail_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
