from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.remediation.enforcement_modes import EnforcementModeRecord, enforcement_mode_to_dict


AUTONOMY_LEVELS = frozenset({"none", "advisory", "supervised_preview", "autonomous_preview", "hardened_preview"})
AUTONOMY_READINESS_STATES = frozenset({"available", "degraded", "blocked", "unavailable", "unknown"})


class AutonomyControlError(ValueError):
    """Raised when autonomy controls violate advisory-only safety constraints."""


@dataclass(slots=True)
class AutonomyControlSummary:
    control_id: str
    selected_mode: str
    autonomy_level: str
    escalation_allowed: bool
    containment_allowed: bool
    approval_required: bool
    emergency_stop_required: bool
    audit_required: bool
    safety_blockers: list[str] = field(default_factory=list)
    operator_actions: list[str] = field(default_factory=list)
    recommended_mode: str = "monitor"
    readiness_state: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.control_id, "control_id")
        _required_str(self.selected_mode, "selected_mode")
        if self.autonomy_level not in AUTONOMY_LEVELS:
            raise AutonomyControlError(f"unsupported autonomy_level: {self.autonomy_level}")
        if not isinstance(self.escalation_allowed, bool):
            raise AutonomyControlError("escalation_allowed must be boolean")
        if self.containment_allowed:
            raise AutonomyControlError("containment_allowed must remain false")
        if not isinstance(self.approval_required, bool):
            raise AutonomyControlError("approval_required must be boolean")
        if not isinstance(self.emergency_stop_required, bool):
            raise AutonomyControlError("emergency_stop_required must be boolean")
        if not isinstance(self.audit_required, bool):
            raise AutonomyControlError("audit_required must be boolean")
        if not _is_string_list(self.safety_blockers):
            raise AutonomyControlError("safety_blockers must be a list of strings")
        if not _is_string_list(self.operator_actions):
            raise AutonomyControlError("operator_actions must be a list of strings")
        _required_str(self.recommended_mode, "recommended_mode")
        if self.readiness_state not in AUTONOMY_READINESS_STATES:
            raise AutonomyControlError(f"unsupported readiness_state: {self.readiness_state}")
        if not self.preview_only:
            raise AutonomyControlError("autonomy controls must remain preview_only")
        if self.destructive_action:
            raise AutonomyControlError("autonomy controls cannot be destructive")
        _required_str(self.source_mode, "source_mode")


def build_autonomy_control_summary(
    mode: EnforcementModeRecord | dict[str, Any],
    *,
    guardrail_blockers: Iterable[str] | None = None,
    emergency_stop_ready: bool = False,
    audit_ready: bool = False,
    source_mode: str = "unknown",
    now: str | None = None,
) -> AutonomyControlSummary:
    row = _mode_dict(mode)
    selected = str(row.get("mode_name") or "monitor")
    mode_state = str(row.get("mode_state") or "unknown")
    level = _autonomy_level(selected)
    blockers = sorted(set(_strings(guardrail_blockers) + _extract_blockers(row)))
    if selected in {"autonomous_preview", "hardened_preview"} and not emergency_stop_ready:
        blockers.append("emergency_stop_missing")
    if selected != "monitor" and not audit_ready:
        blockers.append("audit_summary_missing")
    blockers = sorted(set(blockers))
    readiness = _readiness(mode_state, blockers)
    recommended = _recommended_mode(selected, readiness, blockers)
    approval_required = selected in {"supervised", "autonomous_preview", "hardened_preview"} or bool(blockers)
    emergency_required = selected in {"autonomous_preview", "hardened_preview"}
    audit_required = selected != "monitor"
    escalation_allowed = readiness in {"available", "degraded"} and selected != "monitor"
    material = deterministic_autonomy_control_json(
        {
            "selected": selected,
            "level": level,
            "readiness": readiness,
            "blockers": blockers,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    return AutonomyControlSummary(
        control_id="autonomy-control-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        selected_mode=selected,
        autonomy_level=level,
        escalation_allowed=escalation_allowed,
        containment_allowed=False,
        approval_required=approval_required,
        emergency_stop_required=emergency_required,
        audit_required=audit_required,
        safety_blockers=blockers,
        operator_actions=_operator_actions(readiness, blockers, approval_required),
        recommended_mode=recommended,
        readiness_state=readiness,
        preview_only=True,
        destructive_action=False,
        source_mode=source_mode,
        created_at=now or _now(),
    )


def autonomy_control_to_dict(control: AutonomyControlSummary) -> dict[str, Any]:
    return {
        "record_type": "autonomy_control_summary",
        "control_id": control.control_id,
        "selected_mode": control.selected_mode,
        "autonomy_level": control.autonomy_level,
        "escalation_allowed": control.escalation_allowed,
        "containment_allowed": control.containment_allowed,
        "approval_required": control.approval_required,
        "emergency_stop_required": control.emergency_stop_required,
        "audit_required": control.audit_required,
        "safety_blockers": list(control.safety_blockers),
        "operator_actions": list(control.operator_actions),
        "recommended_mode": control.recommended_mode,
        "readiness_state": control.readiness_state,
        "preview_only": control.preview_only,
        "destructive_action": control.destructive_action,
        "source_mode": control.source_mode,
        "created_at": control.created_at,
        "enforcement_active": False,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "rollback_executed": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_autonomy_control_summary_report(controls: Iterable[AutonomyControlSummary]) -> dict[str, Any]:
    rows = list(controls or [])
    by_state: dict[str, int] = {}
    by_level: dict[str, int] = {}
    for row in rows:
        by_state[row.readiness_state] = by_state.get(row.readiness_state, 0) + 1
        by_level[row.autonomy_level] = by_level.get(row.autonomy_level, 0) + 1
    return {
        "record_type": "autonomy_control_summary_report",
        "control_count": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "by_level": dict(sorted(by_level.items())),
        "blocked_count": by_state.get("blocked", 0) + by_state.get("unavailable", 0),
        "containment_allowed": False,
        "preview_only": True,
        "destructive_action": False,
        "enforcement_active": False,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "rollback_executed": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def deterministic_autonomy_control_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _mode_dict(mode: EnforcementModeRecord | dict[str, Any]) -> dict[str, Any]:
    if isinstance(mode, EnforcementModeRecord):
        return enforcement_mode_to_dict(mode)
    if isinstance(mode, dict):
        return dict(mode)
    return {"mode_name": "monitor", "mode_state": "unknown"}


def _autonomy_level(mode_name: str) -> str:
    return {
        "monitor": "none",
        "supervised": "supervised_preview",
        "autonomous_preview": "autonomous_preview",
        "hardened_preview": "hardened_preview",
    }.get(mode_name, "advisory")


def _extract_blockers(row: dict[str, Any]) -> list[str]:
    blockers: list[str] = []
    for key in (
        "approval_requirements",
        "safety_guardrails_required",
        "rollback_requirements",
        "provider_requirements",
        "runtime_health_requirements",
        "audit_requirements",
    ):
        blockers.extend(str(item) for item in row.get(key) or [] if str(item).endswith("_missing") or ":" in str(item))
    if row.get("mode_state") in {"blocked", "unavailable"}:
        blockers.append(f"mode_state:{row.get('mode_state')}")
    return blockers


def _readiness(mode_state: str, blockers: list[str]) -> str:
    if mode_state in {"blocked", "unavailable"}:
        return "blocked"
    if blockers:
        return "degraded" if mode_state == "available" else "blocked"
    if mode_state in AUTONOMY_READINESS_STATES:
        return mode_state
    return "unknown"


def _recommended_mode(selected: str, readiness: str, blockers: list[str]) -> str:
    if readiness in {"blocked", "unavailable"}:
        return "monitor"
    if blockers and selected in {"autonomous_preview", "hardened_preview"}:
        return "supervised"
    return selected if selected in {"monitor", "supervised", "autonomous_preview", "hardened_preview"} else "monitor"


def _operator_actions(readiness: str, blockers: list[str], approval_required: bool) -> list[str]:
    actions = ["review_autonomy_mode_summary", "confirm_containment_disabled"]
    if approval_required:
        actions.append("confirm_operator_approval_path")
    if blockers:
        actions.append("resolve_autonomy_safety_blockers")
    if readiness in {"blocked", "unavailable"}:
        actions.append("remain_in_monitor_mode")
    return actions


def _strings(values: Iterable[str] | None) -> list[str]:
    return sorted({str(value) for value in values or [] if str(value).strip()})


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise AutonomyControlError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, AutonomyControlSummary):
        return autonomy_control_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
