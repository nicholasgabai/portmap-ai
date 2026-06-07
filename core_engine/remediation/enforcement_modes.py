from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


ENFORCEMENT_MODES = frozenset({"monitor", "supervised", "autonomous_preview", "hardened_preview"})
ENFORCEMENT_MODE_STATES = frozenset({"available", "degraded", "blocked", "unavailable", "unknown"})
ACTION_CLASSES = frozenset(
    {
        "observe",
        "operator_review",
        "advisory_recommendation",
        "escalation_preview",
        "containment_preview",
        "rollback_preview",
        "audit_preview",
    }
)


class EnforcementModeError(ValueError):
    """Raised when enforcement mode preview input violates safety constraints."""


@dataclass(slots=True)
class EnforcementModeRecord:
    mode_id: str
    mode_name: str
    mode_state: str
    allowed_action_classes: list[str] = field(default_factory=list)
    blocked_action_classes: list[str] = field(default_factory=list)
    approval_requirements: list[str] = field(default_factory=list)
    safety_guardrails_required: list[str] = field(default_factory=list)
    rollback_requirements: list[str] = field(default_factory=list)
    provider_requirements: list[str] = field(default_factory=list)
    runtime_health_requirements: list[str] = field(default_factory=list)
    audit_requirements: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.mode_id, "mode_id")
        if self.mode_name not in ENFORCEMENT_MODES:
            raise EnforcementModeError(f"unsupported mode_name: {self.mode_name}")
        if self.mode_state not in ENFORCEMENT_MODE_STATES:
            raise EnforcementModeError(f"unsupported mode_state: {self.mode_state}")
        self.allowed_action_classes = _validate_actions(self.allowed_action_classes, "allowed_action_classes")
        self.blocked_action_classes = _validate_actions(self.blocked_action_classes, "blocked_action_classes")
        for field_name in (
            "approval_requirements",
            "safety_guardrails_required",
            "rollback_requirements",
            "provider_requirements",
            "runtime_health_requirements",
            "audit_requirements",
            "advisory_notes",
        ):
            if not _is_string_list(getattr(self, field_name)):
                raise EnforcementModeError(f"{field_name} must be a list of strings")
        if not self.preview_only:
            raise EnforcementModeError("enforcement mode records must remain preview_only")
        if self.destructive_action:
            raise EnforcementModeError("enforcement mode records cannot be destructive")
        _required_str(self.source_mode, "source_mode")


def build_enforcement_mode(
    mode_name: str,
    *,
    approval_ready: bool = False,
    guardrails_ready: bool = False,
    rollback_ready: bool = False,
    provider_ready: bool = False,
    runtime_health_state: str = "unknown",
    audit_ready: bool = False,
    emergency_stop_ready: bool = False,
    source_mode: str = "unknown",
    now: str | None = None,
) -> EnforcementModeRecord:
    normalized = mode_name if mode_name in ENFORCEMENT_MODES else "monitor"
    requirements = _requirements(normalized)
    blockers = _missing_requirements(
        normalized,
        approval_ready=approval_ready,
        guardrails_ready=guardrails_ready,
        rollback_ready=rollback_ready,
        provider_ready=provider_ready,
        runtime_health_state=runtime_health_state,
        audit_ready=audit_ready,
        emergency_stop_ready=emergency_stop_ready,
    )
    state = _mode_state(normalized, blockers, runtime_health_state)
    allowed, blocked = _action_classes(normalized, state)
    notes = [
        f"{normalized} mode is modeled as preview-only.",
        "No enforcement, containment, firewall, process, service, or rollback action is executed.",
    ]
    if blockers:
        notes.append("Missing prerequisites block or degrade this mode until operator review.")
    material = deterministic_enforcement_mode_json(
        {
            "mode": normalized,
            "state": state,
            "blockers": blockers,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    return EnforcementModeRecord(
        mode_id="enforcement-mode-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        mode_name=normalized,
        mode_state=state,
        allowed_action_classes=allowed,
        blocked_action_classes=blocked,
        approval_requirements=requirements["approval"] + [item for item in blockers if item.startswith("approval")],
        safety_guardrails_required=requirements["guardrails"] + [item for item in blockers if item.startswith("guardrail")],
        rollback_requirements=requirements["rollback"] + [item for item in blockers if item.startswith("rollback")],
        provider_requirements=requirements["provider"] + [item for item in blockers if item.startswith("provider")],
        runtime_health_requirements=requirements["runtime"] + [
            item for item in blockers if item.startswith("runtime") or item.startswith("emergency")
        ],
        audit_requirements=requirements["audit"] + [item for item in blockers if item.startswith("audit")],
        preview_only=True,
        destructive_action=False,
        advisory_notes=notes,
        source_mode=source_mode,
        created_at=now or _now(),
    )


def enforcement_mode_to_dict(mode: EnforcementModeRecord) -> dict[str, Any]:
    return {
        "record_type": "autonomous_enforcement_mode",
        "mode_id": mode.mode_id,
        "mode_name": mode.mode_name,
        "mode_state": mode.mode_state,
        "allowed_action_classes": list(mode.allowed_action_classes),
        "blocked_action_classes": list(mode.blocked_action_classes),
        "approval_requirements": list(mode.approval_requirements),
        "safety_guardrails_required": list(mode.safety_guardrails_required),
        "rollback_requirements": list(mode.rollback_requirements),
        "provider_requirements": list(mode.provider_requirements),
        "runtime_health_requirements": list(mode.runtime_health_requirements),
        "audit_requirements": list(mode.audit_requirements),
        "preview_only": mode.preview_only,
        "destructive_action": mode.destructive_action,
        "advisory_notes": list(mode.advisory_notes),
        "source_mode": mode.source_mode,
        "created_at": mode.created_at,
        "enforcement_active": False,
        "containment_allowed": False,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "rollback_executed": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_enforcement_mode_summary(modes: Iterable[EnforcementModeRecord]) -> dict[str, Any]:
    rows = list(modes or [])
    by_state: dict[str, int] = {}
    by_mode: dict[str, int] = {}
    for row in rows:
        by_state[row.mode_state] = by_state.get(row.mode_state, 0) + 1
        by_mode[row.mode_name] = by_mode.get(row.mode_name, 0) + 1
    return {
        "record_type": "autonomous_enforcement_mode_summary",
        "mode_count": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "by_mode": dict(sorted(by_mode.items())),
        "blocked_count": by_state.get("blocked", 0) + by_state.get("unavailable", 0),
        "preview_only": True,
        "destructive_action": False,
        "enforcement_active": False,
        "containment_allowed": False,
        "automatic_changes": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "rollback_executed": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def deterministic_enforcement_mode_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _requirements(mode_name: str) -> dict[str, list[str]]:
    base = {
        "approval": [],
        "guardrails": ["guardrail_summary_required"],
        "rollback": [],
        "provider": [],
        "runtime": ["runtime_health_supported"],
        "audit": ["audit_summary_required"],
    }
    if mode_name == "monitor":
        return base
    if mode_name == "supervised":
        base["approval"] = ["operator_approval_required"]
        base["rollback"] = ["rollback_preview_required"]
        return base
    if mode_name == "autonomous_preview":
        base["approval"] = ["operator_approval_required", "rbac_approval_path_required"]
        base["rollback"] = ["rollback_preview_required", "rollback_validation_required"]
        base["provider"] = ["provider_readiness_required"]
        base["runtime"].append("emergency_stop_required")
        base["audit"].append("audit_trail_required")
        return base
    base["approval"] = ["operator_approval_required", "rbac_approval_path_required", "release_approval_required"]
    base["guardrails"] = ["guardrail_summary_required", "all_guardrails_required"]
    base["rollback"] = ["rollback_preview_required", "rollback_validation_required", "backup_reference_required"]
    base["provider"] = ["provider_readiness_required", "provider_dry_run_required"]
    base["runtime"] = ["runtime_health_supported", "runtime_health_healthy_required", "emergency_stop_required"]
    base["audit"] = ["audit_summary_required", "audit_trail_required", "tamper_check_required"]
    return base


def _missing_requirements(
    mode_name: str,
    *,
    approval_ready: bool,
    guardrails_ready: bool,
    rollback_ready: bool,
    provider_ready: bool,
    runtime_health_state: str,
    audit_ready: bool,
    emergency_stop_ready: bool,
) -> list[str]:
    blockers: list[str] = []
    health = str(runtime_health_state or "unknown").lower()
    if health in {"blocked", "unsafe", "unavailable"}:
        blockers.append(f"runtime_health:{health}")
    elif mode_name in {"autonomous_preview", "hardened_preview"} and health != "healthy":
        blockers.append(f"runtime_health_not_ready:{health}")
    if not guardrails_ready and mode_name != "monitor":
        blockers.append("guardrail_summary_missing")
    if not audit_ready and mode_name != "monitor":
        blockers.append("audit_summary_missing")
    if mode_name in {"supervised", "autonomous_preview", "hardened_preview"}:
        if not approval_ready:
            blockers.append("approval_path_missing")
        if not rollback_ready:
            blockers.append("rollback_preview_missing")
    if mode_name in {"autonomous_preview", "hardened_preview"}:
        if not provider_ready:
            blockers.append("provider_readiness_missing")
        if not emergency_stop_ready:
            blockers.append("emergency_stop_missing")
    return sorted(set(blockers))


def _mode_state(mode_name: str, blockers: list[str], runtime_health_state: str) -> str:
    health = str(runtime_health_state or "unknown").lower()
    if health in {"blocked", "unsafe", "unavailable"}:
        return "blocked"
    if mode_name == "monitor":
        return "available" if health in {"healthy", "degraded", "unknown"} else "unknown"
    if not blockers:
        return "available"
    if mode_name == "supervised" and all(item in {"approval_path_missing", "rollback_preview_missing"} for item in blockers):
        return "degraded"
    if mode_name == "hardened_preview":
        return "blocked"
    return "blocked" if any("missing" in item for item in blockers) else "degraded"


def _action_classes(mode_name: str, state: str) -> tuple[list[str], list[str]]:
    all_actions = set(ACTION_CLASSES)
    if state in {"blocked", "unavailable", "unknown"}:
        allowed = {"observe", "operator_review", "advisory_recommendation", "audit_preview"}
    elif mode_name == "monitor":
        allowed = {"observe", "operator_review", "advisory_recommendation", "audit_preview"}
    elif mode_name == "supervised":
        allowed = {"observe", "operator_review", "advisory_recommendation", "escalation_preview", "rollback_preview", "audit_preview"}
    else:
        allowed = {
            "observe",
            "operator_review",
            "advisory_recommendation",
            "escalation_preview",
            "containment_preview",
            "rollback_preview",
            "audit_preview",
        }
    return sorted(allowed), sorted(all_actions - allowed)


def _validate_actions(actions: list[str], field_name: str) -> list[str]:
    if not isinstance(actions, list):
        raise EnforcementModeError(f"{field_name} must be a list")
    normalized = []
    for action in actions:
        if action not in ACTION_CLASSES:
            raise EnforcementModeError(f"unsupported action class in {field_name}: {action}")
        normalized.append(action)
    return sorted(set(normalized))


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise EnforcementModeError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _json_safe(value: Any) -> Any:
    if isinstance(value, EnforcementModeRecord):
        return enforcement_mode_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
