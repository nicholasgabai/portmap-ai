from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.deployment.manifests import (
    DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    build_deployment_manifest,
)
from core_engine.deployment.migration_plans import build_default_migration_plan_set


UPGRADE_READINESS_RECORD_VERSION = 1

UPGRADE_READINESS_STATES = frozenset({"ready", "degraded", "blocked", "unknown"})

UPGRADE_READINESS_SAFETY_FLAGS = {
    **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    "upgrade_preview_only": True,
    "migration_executed": False,
    "config_modified": False,
    "history_store_modified": False,
    "snapshots_rewritten": False,
    "snapshots_deleted": False,
    "services_modified": False,
    "credentials_generated": False,
    "destructive_action": False,
}


def build_upgrade_readiness_report(
    *,
    current_version: str = "0.1.0",
    target_version: str = "0.1.0",
    deployment_mode: str = "standalone",
    platform: str = "cross-platform",
    runtime_profile_impact: dict[str, Any] | str | None = None,
    deployment_manifest_impact: dict[str, Any] | str | None = None,
    service_lifecycle_impact: dict[str, Any] | str | None = None,
    telemetry_impact: dict[str, Any] | str | None = None,
    history_retention_impact: dict[str, Any] | str | None = None,
    rollback_available: bool | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build upgrade readiness without executing migrations or modifying stores."""
    timestamp = generated_at or _now()
    current = _version_label(current_version)
    target = _version_label(target_version)
    compatibility = build_version_compatibility_summary(
        current_version=current,
        target_version=target,
        generated_at=timestamp,
    )
    manifest = build_deployment_manifest(deployment_mode, generated_at=timestamp)
    impacts = {
        "runtime_profile_impact": build_upgrade_impact_summary("runtime_profile", runtime_profile_impact, default_state="ready", generated_at=timestamp),
        "deployment_manifest_impact": build_upgrade_impact_summary("deployment_manifest", deployment_manifest_impact or manifest["deployment_readiness"], default_state="ready", generated_at=timestamp),
        "service_lifecycle_impact": build_upgrade_impact_summary("service_lifecycle", service_lifecycle_impact, default_state="degraded", generated_at=timestamp),
        "telemetry_impact": build_upgrade_impact_summary("telemetry", telemetry_impact, default_state="ready", generated_at=timestamp),
        "history_retention_impact": build_upgrade_impact_summary("history_retention", history_retention_impact, default_state="ready", generated_at=timestamp),
    }
    migration_plan = build_default_migration_plan_set(
        current_version=current,
        target_version=target,
        platform=platform,
        generated_at=timestamp,
    )
    rollback = bool(rollback_available) if rollback_available is not None else compatibility["state"] != "unknown"
    readiness_state = determine_upgrade_readiness_state(
        compatibility_state=compatibility["state"],
        impacts=impacts,
        rollback_available=rollback,
    )
    advisory = build_upgrade_advisory_notes(
        state=readiness_state,
        compatibility=compatibility,
        impacts=impacts,
        rollback_available=rollback,
    )
    operator_required = readiness_state != "ready" or any(row["state"] != "ready" for row in impacts.values())
    return {
        "record_type": "upgrade_readiness_report",
        "record_version": UPGRADE_READINESS_RECORD_VERSION,
        "upgrade_readiness_id": "upgrade-readiness-" + _digest(
            {
                "current_version": current,
                "target_version": target,
                "deployment_mode": deployment_mode,
                "platform": platform,
                "generated_at": timestamp,
                "state": readiness_state,
            }
        )[:16],
        "generated_at": timestamp,
        "current_version": current,
        "target_version": target,
        "compatibility_state": compatibility["state"],
        "readiness_state": readiness_state,
        "runtime_profile_impact": impacts["runtime_profile_impact"],
        "deployment_manifest_impact": impacts["deployment_manifest_impact"],
        "service_lifecycle_impact": impacts["service_lifecycle_impact"],
        "telemetry_impact": impacts["telemetry_impact"],
        "history_retention_impact": impacts["history_retention_impact"],
        "operator_action_required": operator_required,
        "rollback_available": rollback,
        "advisory_notes": advisory,
        "migration_plan": migration_plan,
        "dashboard_status": build_upgrade_dashboard_record(state=readiness_state, current_version=current, target_version=target, generated_at=timestamp),
        "api_status": build_upgrade_api_response(state=readiness_state, current_version=current, target_version=target, generated_at=timestamp),
        "export": build_upgrade_export_dict(state=readiness_state, current_version=current, target_version=target, operator_action_required=operator_required, rollback_available=rollback, generated_at=timestamp),
        **UPGRADE_READINESS_SAFETY_FLAGS,
    }


def build_version_compatibility_summary(
    *,
    current_version: str,
    target_version: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    current = _version_tuple(current_version)
    target = _version_tuple(target_version)
    if current is None or target is None:
        state = "unknown"
        summary = "Version compatibility is unknown because one or more versions are malformed."
    elif target < current:
        state = "blocked"
        summary = "Target version is older than current version; downgrade is blocked in readiness preview."
    elif target[0] > current[0] + 1:
        state = "blocked"
        summary = "Target major version jump requires an explicit intermediate upgrade plan."
    elif target[0] > current[0] or target[1] > current[1] + 1:
        state = "degraded"
        summary = "Upgrade spans a larger compatibility window and requires operator review."
    else:
        state = "ready"
        summary = "Version compatibility is ready for migration preview."
    return {
        "record_type": "upgrade_version_compatibility",
        "record_version": UPGRADE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "current_version": _version_label(current_version),
        "target_version": _version_label(target_version),
        "state": state,
        "operator_summary": summary,
        **UPGRADE_READINESS_SAFETY_FLAGS,
    }


def build_upgrade_impact_summary(
    component: str,
    impact: dict[str, Any] | str | None,
    *,
    default_state: str = "ready",
    generated_at: str | None = None,
) -> dict[str, Any]:
    state = _impact_state(impact, default_state=default_state)
    return {
        "record_type": "upgrade_impact_summary",
        "record_version": UPGRADE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "component": str(component),
        "state": state,
        "source_status": _source_status(impact),
        "operator_review_required": state != "ready",
        "operator_summary": _impact_summary(component, state),
        **UPGRADE_READINESS_SAFETY_FLAGS,
    }


def determine_upgrade_readiness_state(
    *,
    compatibility_state: str,
    impacts: dict[str, dict[str, Any]],
    rollback_available: bool,
) -> str:
    states = [_state(compatibility_state)] + [_state(row.get("state")) for row in impacts.values()]
    if "blocked" in states:
        return "blocked"
    if "unknown" in states:
        return "unknown"
    if not rollback_available:
        return "degraded"
    if "degraded" in states:
        return "degraded"
    return "ready"


def build_upgrade_advisory_notes(
    *,
    state: str,
    compatibility: dict[str, Any],
    impacts: dict[str, dict[str, Any]],
    rollback_available: bool,
) -> list[str]:
    notes = {
        "Upgrade readiness is preview-only; no migrations are executed.",
        "Backups and rollback references should be reviewed before any external upgrade.",
        "Configuration files, history stores, snapshots, services, and credentials are not modified.",
    }
    if state != "ready":
        notes.add("Resolve degraded, blocked, or unknown checks before upgrade execution.")
    if not rollback_available:
        notes.add("Rollback is not available in supplied readiness inputs.")
    if compatibility["state"] != "ready":
        notes.add("Version compatibility requires operator review.")
    for component, impact in impacts.items():
        if impact["state"] != "ready":
            notes.add(f"{component} requires operator review.")
    return sorted(notes)


def build_upgrade_dashboard_record(*, state: str, current_version: str, target_version: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "upgrade_readiness_dashboard",
        "record_version": UPGRADE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "state": _state(state),
        "current_version": current_version,
        "target_version": target_version,
        "operator_review_required": _state(state) != "ready",
        **UPGRADE_READINESS_SAFETY_FLAGS,
    }


def build_upgrade_api_response(*, state: str, current_version: str, target_version: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "upgrade_readiness_api_response",
        "record_version": UPGRADE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "state": _state(state),
        "current_version": current_version,
        "target_version": target_version,
        "preview_only": True,
        **UPGRADE_READINESS_SAFETY_FLAGS,
    }


def build_upgrade_export_dict(
    *,
    state: str,
    current_version: str,
    target_version: str,
    operator_action_required: bool,
    rollback_available: bool,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "upgrade_readiness_export",
        "record_version": UPGRADE_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "state": _state(state),
        "current_version": current_version,
        "target_version": target_version,
        "operator_action_required": bool(operator_action_required),
        "rollback_available": bool(rollback_available),
        "preview_only": True,
        **UPGRADE_READINESS_SAFETY_FLAGS,
    }


def upgrade_readiness_to_dict(record: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record or {})
    return {
        "record_type": str(payload.get("record_type") or "upgrade_readiness_report"),
        "record_version": int(payload.get("record_version") or UPGRADE_READINESS_RECORD_VERSION),
        "current_version": _version_label(payload.get("current_version") or "unknown"),
        "target_version": _version_label(payload.get("target_version") or "unknown"),
        "compatibility_state": _state(payload.get("compatibility_state")),
        "readiness_state": _state(payload.get("readiness_state")),
        "operator_action_required": bool(payload.get("operator_action_required", True)),
        "rollback_available": bool(payload.get("rollback_available", False)),
        "advisory_notes": sorted(str(item) for item in payload.get("advisory_notes") or []),
        **UPGRADE_READINESS_SAFETY_FLAGS,
    }


def export_upgrade_readiness(record: dict[str, Any]) -> str:
    return json.dumps(upgrade_readiness_to_dict(record), sort_keys=True)


def _impact_state(impact: dict[str, Any] | str | None, *, default_state: str) -> str:
    if impact is None:
        return _state(default_state)
    if isinstance(impact, str):
        return _state(impact)
    if isinstance(impact, dict):
        for key in ("state", "status", "readiness_state"):
            if impact.get(key):
                return _state(str(impact[key]))
        summary = impact.get("summary")
        if isinstance(summary, dict):
            return _impact_state(summary, default_state=default_state)
    return "unknown"


def _source_status(impact: dict[str, Any] | str | None) -> str:
    if impact is None:
        return "default"
    if isinstance(impact, str):
        return impact
    if isinstance(impact, dict):
        return str(impact.get("state") or impact.get("status") or impact.get("readiness_state") or "provided")
    return "unknown"


def _impact_summary(component: str, state: str) -> str:
    if state == "ready":
        return f"{component} impact is ready for preview."
    if state == "blocked":
        return f"{component} impact blocks upgrade readiness."
    if state == "unknown":
        return f"{component} impact is unknown and requires review."
    return f"{component} impact is degraded and requires review."


def _state(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    aliases = {"supported": "ready", "ok": "ready", "unavailable": "blocked", "unsupported": "blocked"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in UPGRADE_READINESS_STATES else "unknown"


def _version_label(value: Any) -> str:
    text = str(value or "unknown").strip()
    safe = "".join(char for char in text if char.isalnum() or char in {".", "-", "+"}).strip(".-+")
    return safe or "unknown"


def _version_tuple(value: str) -> tuple[int, int, int] | None:
    parts = _version_label(value).split(".")
    if len(parts) < 2:
        return None
    numbers: list[int] = []
    for part in parts[:3]:
        digits = "".join(char for char in part if char.isdigit())
        if digits == "":
            return None
        numbers.append(int(digits))
    while len(numbers) < 3:
        numbers.append(0)
    return tuple(numbers[:3])


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
