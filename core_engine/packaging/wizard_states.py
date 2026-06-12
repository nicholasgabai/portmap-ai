from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.installer_previews import PACKAGING_SAFETY_FLAGS, sanitize_list
from core_engine.scaling.bus_envelopes import digest, sanitize_reference, sanitize_text, sanitize_token


WIZARD_STATE_RECORD_VERSION = 1
WIZARD_STEP_TYPES = {
    "environment_check",
    "platform_selection",
    "install_method_selection",
    "profile_selection",
    "service_preview",
    "update_preview",
    "validation",
    "summary",
    "unknown",
}
WIZARD_STEP_STATES = {"complete", "pending", "blocked", "degraded", "unavailable", "unknown"}
WIZARD_STATE_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    "installer_executed": False,
    "package_created": False,
    "service_created": False,
    "service_modified": False,
    "filesystem_written": False,
    "admin_escalation_requested": False,
    "credential_stored": False,
    "runtime_behavior_changed": False,
}


@dataclass(frozen=True)
class WizardStateRecord:
    wizard_state_id: str
    step_name: str
    step_type: str
    step_state: str
    selected_profile: str
    environment_checks: dict[str, Any] = field(default_factory=dict)
    validation_steps: list[str] = field(default_factory=list)
    rollback_available: bool = False
    uninstall_available: bool = False
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "deployment_wizard_state",
            "record_version": WIZARD_STATE_RECORD_VERSION,
            "wizard_state_id": sanitize_reference(self.wizard_state_id),
            "step_name": sanitize_text(self.step_name) or "wizard step",
            "step_type": normalize_wizard_step_type(self.step_type),
            "step_state": normalize_wizard_step_state(self.step_state),
            "selected_profile": sanitize_text(self.selected_profile) or "unknown",
            "environment_checks": sanitize_environment_checks(self.environment_checks),
            "validation_steps": sanitize_list(self.validation_steps),
            "rollback_available": bool(self.rollback_available),
            "uninstall_available": bool(self.uninstall_available),
            "advisory_notes": sanitize_list(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **WIZARD_STATE_SAFETY_FLAGS,
        }


def build_wizard_state(
    *,
    wizard_state_id: Any = "",
    step_name: Any = "Wizard step",
    step_type: Any = "unknown",
    step_state: Any = "pending",
    selected_profile: Any = "unknown",
    environment_checks: dict[str, Any] | None = None,
    validation_steps: Iterable[Any] | None = None,
    rollback_available: Any = False,
    uninstall_available: Any = False,
    advisory_notes: Iterable[Any] | None = None,
) -> WizardStateRecord:
    normalized_type = normalize_wizard_step_type(step_type)
    normalized_state = normalize_wizard_step_state(step_state)
    checks = sanitize_environment_checks(environment_checks or {})
    validations = sanitize_list(validation_steps or ["review wizard step", "confirm preview-only behavior"])
    notes = sanitize_list(advisory_notes or ["deployment wizard step is metadata-only and advisory"])
    safe_id = sanitize_reference(wizard_state_id)
    if not safe_id:
        safe_id = "wizard-state-" + digest(
            {
                "step_name": sanitize_text(step_name),
                "step_type": normalized_type,
                "step_state": normalized_state,
                "selected_profile": sanitize_text(selected_profile),
            }
        )[:16]
    return WizardStateRecord(
        wizard_state_id=safe_id,
        step_name=sanitize_text(step_name) or "Wizard step",
        step_type=normalized_type,
        step_state=normalized_state,
        selected_profile=sanitize_text(selected_profile) or "unknown",
        environment_checks=checks,
        validation_steps=validations,
        rollback_available=bool(rollback_available),
        uninstall_available=bool(uninstall_available),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_wizard_state_record(value: Any) -> WizardStateRecord:
    if isinstance(value, WizardStateRecord):
        return value
    if not isinstance(value, dict):
        return build_wizard_state(
            step_name="Invalid wizard step",
            step_type="unknown",
            step_state="unknown",
            advisory_notes=["invalid wizard state generated from malformed input"],
        )
    try:
        return build_wizard_state(
            wizard_state_id=value.get("wizard_state_id", ""),
            step_name=value.get("step_name", value.get("name", "Wizard step")),
            step_type=value.get("step_type", value.get("type", "unknown")),
            step_state=value.get("step_state", value.get("state", "pending")),
            selected_profile=value.get("selected_profile", "unknown"),
            environment_checks=value.get("environment_checks") if isinstance(value.get("environment_checks"), dict) else None,
            validation_steps=value.get("validation_steps") if isinstance(value.get("validation_steps"), list) else None,
            rollback_available=value.get("rollback_available", False),
            uninstall_available=value.get("uninstall_available", False),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_wizard_state(step_name="Invalid wizard step", step_state="unknown", advisory_notes=[str(exc)])


def summarize_wizard_states(states: Iterable[WizardStateRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_wizard_state_record(state).to_dict() for state in list(states or [])]
    type_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    for row in rows:
        type_counts[row["step_type"]] = type_counts.get(row["step_type"], 0) + 1
        state_counts[row["step_state"]] = state_counts.get(row["step_state"], 0) + 1
    return {
        "step_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "rollback_available_count": sum(1 for row in rows if row.get("rollback_available")),
        "uninstall_available_count": sum(1 for row in rows if row.get("uninstall_available")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **WIZARD_STATE_SAFETY_FLAGS,
    }


def sanitize_environment_checks(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    sanitized: dict[str, Any] = {}
    for key, raw_value in list(value.items())[:32]:
        safe_key = sanitize_token(key).lower()
        if not safe_key:
            continue
        if isinstance(raw_value, bool):
            sanitized[safe_key] = raw_value
        elif isinstance(raw_value, (int, float)):
            sanitized[safe_key] = raw_value
        elif isinstance(raw_value, (list, tuple)):
            sanitized[safe_key] = [sanitize_text(item)[:120] for item in raw_value][:16]
        else:
            sanitized[safe_key] = sanitize_text(raw_value)[:160]
    return sanitized


def normalize_wizard_step_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in WIZARD_STEP_TYPES else "unknown"


def normalize_wizard_step_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in WIZARD_STEP_STATES else "unknown"


def deterministic_wizard_state_json(record: WizardStateRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, WizardStateRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "WIZARD_STATE_SAFETY_FLAGS",
    "WIZARD_STEP_STATES",
    "WIZARD_STEP_TYPES",
    "WizardStateRecord",
    "build_wizard_state",
    "deterministic_wizard_state_json",
    "normalize_wizard_state_record",
    "normalize_wizard_step_state",
    "normalize_wizard_step_type",
    "sanitize_environment_checks",
    "summarize_wizard_states",
]
