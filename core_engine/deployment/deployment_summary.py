from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.deployment.backup_plans import build_default_backup_plan_set
from core_engine.deployment.manifests import DEPLOYMENT_MANIFEST_SAFETY_FLAGS, build_deployment_manifest
from core_engine.deployment.restore_plans import build_default_restore_preview_set
from core_engine.deployment.runtime_profiles import build_deployment_runtime_profile
from core_engine.deployment.service_lifecycle import build_service_lifecycle_preview_plan
from core_engine.deployment.upgrade_readiness import build_upgrade_readiness_report


DEPLOYMENT_SUMMARY_RECORD_VERSION = 1

DEPLOYMENT_STATES = frozenset({"ready", "degraded", "blocked", "unknown"})

DEPLOYMENT_SUMMARY_SAFETY_FLAGS = {
    **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    "deployment_summary_only": True,
    "dry_run_only": True,
    "preview_only": True,
    "destructive_action": False,
    "deployment_executed": False,
    "service_installed": False,
    "service_started": False,
    "config_modified": False,
    "backup_created": False,
    "restore_executed": False,
    "migration_executed": False,
    "firewall_rules_changed": False,
    "credentials_stored": False,
}


def build_deployment_operator_summary(
    *,
    runtime_profile: dict[str, Any] | None = None,
    service_lifecycle: dict[str, Any] | None = None,
    deployment_manifest: dict[str, Any] | None = None,
    upgrade_readiness: dict[str, Any] | None = None,
    backup_plan_set: dict[str, Any] | None = None,
    restore_preview_set: dict[str, Any] | None = None,
    cross_platform_validation: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Compose deployment readiness records into one operator-safe summary."""
    timestamp = generated_at or _now()
    runtime = runtime_profile if runtime_profile is not None else build_deployment_runtime_profile("production", generated_at=timestamp)
    manifest = deployment_manifest if deployment_manifest is not None else build_deployment_manifest("production_preview", generated_at=timestamp)
    service = service_lifecycle if service_lifecycle is not None else build_service_lifecycle_preview_plan(
        service_name="portmap-production-preview",
        provider="linux-systemd",
        platform_info={"system": "Linux", "release": "linux-release-placeholder", "machine": "x86_64", "python_version": "3.11.5"},
        generated_at=timestamp,
    )
    upgrade = upgrade_readiness if upgrade_readiness is not None else build_upgrade_readiness_report(
        current_version="0.1.0",
        target_version="0.1.1",
        deployment_mode="production_preview",
        service_lifecycle_impact="ready",
        rollback_available=True,
        generated_at=timestamp,
    )
    backups = backup_plan_set if backup_plan_set is not None else build_default_backup_plan_set(generated_at=timestamp)
    restores = restore_preview_set if restore_preview_set is not None else build_default_restore_preview_set(generated_at=timestamp)
    rollups = {
        "production_runtime_profiles": build_component_rollup("production_runtime_profiles", runtime, generated_at=timestamp),
        "service_lifecycle_readiness": build_component_rollup("service_lifecycle_readiness", service, generated_at=timestamp),
        "deployment_manifests": build_component_rollup("deployment_manifests", manifest, generated_at=timestamp),
        "upgrade_migration_readiness": build_component_rollup("upgrade_migration_readiness", upgrade, generated_at=timestamp),
        "backup_restore_planning": build_component_rollup("backup_restore_planning", {"backup": backups, "restore": restores}, generated_at=timestamp),
        "cross_platform_compatibility": build_component_rollup("cross_platform_compatibility", cross_platform_validation, generated_at=timestamp),
    }
    state = summarize_deployment_state(rollups)
    readiness_score = calculate_readiness_score(rollups)
    checklist = build_release_readiness_checklist(rollups, generated_at=timestamp)
    actions = build_operator_required_actions(rollups, checklist, generated_at=timestamp)
    warnings = build_deployment_safety_warnings(rollups, generated_at=timestamp)
    summary = {
        "record_type": "deployment_operator_summary",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "deployment_summary_id": "deployment-summary-" + _digest(
            {
                "generated_at": timestamp,
                "state": state,
                "score": readiness_score,
                "rollups": {name: row["state"] for name, row in rollups.items()},
            }
        )[:16],
        "generated_at": timestamp,
        "deployment_state": state,
        "readiness_score": readiness_score,
        "component_rollups": dict(sorted(rollups.items())),
        "supported_components": sorted(name for name, row in rollups.items() if row["state"] == "ready"),
        "degraded_components": sorted(name for name, row in rollups.items() if row["state"] == "degraded"),
        "unavailable_components": sorted(name for name, row in rollups.items() if row["state"] in {"blocked", "unknown"}),
        "operator_required_actions": actions,
        "safety_warnings": warnings,
        "release_readiness_checklist": checklist,
        "advisory_notes": build_deployment_advisory_notes(state=state, readiness_score=readiness_score, rollups=rollups),
        "dry_run_only": True,
        "destructive_action": False,
        "export": build_deployment_summary_export_dict(state=state, readiness_score=readiness_score, rollups=rollups, generated_at=timestamp),
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }
    return summary


def build_component_rollup(component: str, record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    state = _component_state(record)
    return {
        "record_type": "deployment_component_rollup",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "component": component,
        "state": state,
        "source_record_type": str((record or {}).get("record_type") or "not-provided") if isinstance(record, dict) else "not-provided",
        "operator_review_required": state != "ready",
        "operator_summary": _component_summary(component, state),
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }


def summarize_deployment_state(rollups: dict[str, dict[str, Any]]) -> str:
    states = [str(row.get("state") or "unknown") for row in rollups.values()]
    if any(state == "blocked" for state in states):
        return "blocked"
    if any(state == "unknown" for state in states):
        return "unknown"
    if any(state == "degraded" for state in states):
        return "degraded"
    return "ready"


def calculate_readiness_score(rollups: dict[str, dict[str, Any]]) -> int:
    if not rollups:
        return 0
    weights = {"ready": 100, "degraded": 60, "blocked": 0, "unknown": 25}
    total = sum(weights.get(str(row.get("state") or "unknown"), 25) for row in rollups.values())
    return round(total / len(rollups))


def build_release_readiness_checklist(
    rollups: dict[str, dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    labels = {
        "production_runtime_profiles": "Confirm production runtime profile compatibility.",
        "service_lifecycle_readiness": "Review service lifecycle previews and permission requirements.",
        "deployment_manifests": "Review deployment manifests and platform placeholders.",
        "upgrade_migration_readiness": "Review upgrade, migration, rollback, and backup requirements.",
        "backup_restore_planning": "Review backup and restore plans before production use.",
        "cross_platform_compatibility": "Review macOS, Linux, Raspberry Pi, and Windows compatibility summaries.",
    }
    return [
        {
            "record_type": "deployment_release_checklist_item",
            "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
            "generated_at": timestamp,
            "check_id": name,
            "summary": labels.get(name, f"Review {name}."),
            "state": row["state"],
            "complete": row["state"] == "ready",
            "operator_review_required": row["state"] != "ready",
            **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
        }
        for name, row in sorted(rollups.items())
    ]


def build_operator_required_actions(
    rollups: dict[str, dict[str, Any]],
    checklist: list[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    actions = []
    for item in checklist:
        if item["complete"]:
            continue
        actions.append(
            {
                "record_type": "deployment_operator_required_action",
                "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
                "generated_at": timestamp,
                "component": item["check_id"],
                "state": item["state"],
                "action": f"Resolve or explicitly accept {item['state']} deployment readiness for {item['check_id']}.",
                "operator_review_required": True,
                **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
            }
        )
    if not actions:
        actions.append(
            {
                "record_type": "deployment_operator_required_action",
                "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
                "generated_at": timestamp,
                "component": "deployment",
                "state": "ready",
                "action": "No blocking deployment readiness actions in supplied dry-run summaries.",
                "operator_review_required": False,
                **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
            }
        )
    return actions


def build_deployment_safety_warnings(
    rollups: dict[str, dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    warnings = {
        "deployment_execution_disabled",
        "service_installation_disabled",
        "firewall_changes_disabled",
        "backup_restore_execution_disabled",
        "credential_storage_disabled",
    }
    for name, rollup in rollups.items():
        if rollup["state"] != "ready":
            warnings.add(f"{name}_{rollup['state']}")
    timestamp = generated_at or _now()
    return [
        {
            "record_type": "deployment_safety_warning",
            "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
            "generated_at": timestamp,
            "warning": warning,
            "operator_review_required": True,
            **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
        }
        for warning in sorted(warnings)
    ]


def build_deployment_advisory_notes(*, state: str, readiness_score: int, rollups: dict[str, dict[str, Any]]) -> list[str]:
    notes = {
        "Deployment operator summary is advisory and dry-run only.",
        "No services, deployments, migrations, backups, restores, firewall changes, or credential storage are performed.",
        "Use this summary to decide what an operator must review before real deployment work.",
    }
    if state != "ready":
        notes.add("Resolve degraded, blocked, or unknown components before production deployment.")
    if readiness_score < 80:
        notes.add("Readiness score is below release-review threshold.")
    return sorted(notes)


def build_deployment_summary_export_dict(
    *,
    state: str,
    readiness_score: int,
    rollups: dict[str, dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "deployment_operator_summary_export",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "deployment_state": state,
        "readiness_score": int(readiness_score),
        "component_states": {name: row["state"] for name, row in sorted(rollups.items())},
        "component_count": len(rollups),
        "dry_run_only": True,
        "destructive_action": False,
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }


def deployment_summary_to_dict(summary: dict[str, Any]) -> dict[str, Any]:
    payload = dict(summary or {})
    return {
        "record_type": str(payload.get("record_type") or "deployment_operator_summary"),
        "record_version": int(payload.get("record_version") or DEPLOYMENT_SUMMARY_RECORD_VERSION),
        "deployment_state": _state(payload.get("deployment_state")),
        "readiness_score": _score(payload.get("readiness_score")),
        "supported_components": _string_list(payload.get("supported_components") or []),
        "degraded_components": _string_list(payload.get("degraded_components") or []),
        "unavailable_components": _string_list(payload.get("unavailable_components") or []),
        "advisory_notes": _string_list(payload.get("advisory_notes") or []),
        "dry_run_only": True,
        "destructive_action": False,
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }


def export_deployment_summary(summary: dict[str, Any]) -> str:
    return json.dumps(deployment_summary_to_dict(summary), sort_keys=True)


def _component_state(record: dict[str, Any] | None) -> str:
    if not isinstance(record, dict) or not record:
        return "unknown"
    for key in ("deployment_state", "readiness_state", "state", "status"):
        if record.get(key):
            return _state(record[key])
    if isinstance(record.get("deployment_readiness"), dict):
        return _state(record["deployment_readiness"].get("state"))
    if isinstance(record.get("backup"), dict) and isinstance(record.get("restore"), dict):
        backup_ok = bool(record["backup"].get("plans") or record["backup"].get("backup_count"))
        restore_ok = bool(record["restore"].get("previews") or record["restore"].get("restore_count"))
        if not backup_ok and not restore_ok:
            return "unknown"
        return "ready" if backup_ok and restore_ok else "degraded"
    if "plans" in record or "previews" in record:
        return "ready"
    if "profile_name" in record:
        return "ready"
    return "unknown"


def _state(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    aliases = {"supported": "ready", "preview": "degraded", "unavailable": "blocked", "unsupported": "blocked"}
    normalized = aliases.get(normalized, normalized)
    return normalized if normalized in DEPLOYMENT_STATES else "unknown"


def _component_summary(component: str, state: str) -> str:
    if state == "ready":
        return f"{component} is ready in the supplied dry-run summary."
    if state == "blocked":
        return f"{component} blocks deployment readiness."
    if state == "unknown":
        return f"{component} is missing or unknown."
    return f"{component} is degraded and requires operator review."


def _score(value: Any) -> int:
    try:
        return max(0, min(100, int(value)))
    except (TypeError, ValueError):
        return 0


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
