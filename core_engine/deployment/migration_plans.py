from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.deployment.manifests import DEPLOYMENT_MANIFEST_SAFETY_FLAGS


MIGRATION_PLAN_RECORD_VERSION = 1

MIGRATION_TYPES = frozenset(
    {
        "config",
        "runtime_profile",
        "deployment_manifest",
        "historical_snapshot_schema",
        "retention_policy",
        "service_lifecycle_plan",
    }
)

MIGRATION_PLAN_SAFETY_FLAGS = {
    **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    "preview_only": True,
    "dry_run_only": True,
    "destructive_action": False,
    "migration_executed": False,
    "config_modified": False,
    "history_store_modified": False,
    "snapshots_rewritten": False,
    "snapshots_deleted": False,
    "service_installed": False,
    "credentials_generated": False,
}


def build_migration_preview(
    migration_type: str,
    *,
    migration_name: str | None = None,
    current_version: str = "0.1.0",
    target_version: str = "0.1.0",
    platform: str = "cross-platform",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a migration preview without executing migrations."""
    timestamp = generated_at or _now()
    normalized_type = _migration_type(migration_type)
    name = _migration_name(migration_name, normalized_type)
    return {
        "record_type": "deployment_migration_preview",
        "record_version": MIGRATION_PLAN_RECORD_VERSION,
        "migration_id": "migration-preview-" + _digest(
            {
                "migration_name": name,
                "migration_type": normalized_type,
                "current_version": current_version,
                "target_version": target_version,
                "generated_at": timestamp,
            }
        )[:16],
        "generated_at": timestamp,
        "migration_name": name,
        "migration_type": normalized_type,
        "current_version": _version_label(current_version),
        "target_version": _version_label(target_version),
        "platform": str(platform or "cross-platform"),
        "preview_only": True,
        "destructive_action": False,
        "required_backups": build_required_backup_list(normalized_type),
        "rollback_notes": build_rollback_notes(normalized_type),
        "validation_steps": build_validation_steps(normalized_type),
        "operator_steps": build_operator_steps(normalized_type),
        "safety_warnings": build_safety_warnings(normalized_type),
        "dashboard_status": build_migration_dashboard_record(name=name, migration_type=normalized_type, generated_at=timestamp),
        "api_status": build_migration_api_response(name=name, migration_type=normalized_type, generated_at=timestamp),
        "export": build_migration_export_dict(name=name, migration_type=normalized_type, generated_at=timestamp),
        **MIGRATION_PLAN_SAFETY_FLAGS,
    }


def build_default_migration_plan_set(
    *,
    current_version: str = "0.1.0",
    target_version: str = "0.1.0",
    platform: str = "cross-platform",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    previews = [
        build_migration_preview(
            migration_type,
            current_version=current_version,
            target_version=target_version,
            platform=platform,
            generated_at=timestamp,
        )
        for migration_type in sorted(MIGRATION_TYPES)
    ]
    return {
        "record_type": "deployment_migration_preview_set",
        "record_version": MIGRATION_PLAN_RECORD_VERSION,
        "migration_set_id": "migration-preview-set-" + _digest(
            {
                "generated_at": timestamp,
                "current_version": current_version,
                "target_version": target_version,
                "migration_types": [row["migration_type"] for row in previews],
            }
        )[:16],
        "generated_at": timestamp,
        "current_version": _version_label(current_version),
        "target_version": _version_label(target_version),
        "platform": str(platform or "cross-platform"),
        "migration_count": len(previews),
        "migrations": previews,
        "preview_only": True,
        "destructive_action": False,
        **MIGRATION_PLAN_SAFETY_FLAGS,
    }


def build_required_backup_list(migration_type: str) -> list[str]:
    common = {"runtime_export_summary", "deployment_manifest_export"}
    extras = {
        "config": {"configuration_snapshot"},
        "runtime_profile": {"runtime_profile_export"},
        "deployment_manifest": {"deployment_manifest_export"},
        "historical_snapshot_schema": {"historical_snapshot_export", "long_term_intelligence_summary"},
        "retention_policy": {"retention_policy_export", "resource_retention_summary"},
        "service_lifecycle_plan": {"service_lifecycle_preview_export"},
    }
    return sorted(common | extras.get(_migration_type(migration_type), set()))


def build_rollback_notes(migration_type: str) -> list[str]:
    label = _migration_type(migration_type)
    return [
        f"Keep the previous {label} metadata export until operator validation completes.",
        "Rollback is a manual operator workflow and is not executed by this preview.",
        "Verify backup references before any external migration process.",
    ]


def build_validation_steps(migration_type: str) -> list[str]:
    label = _migration_type(migration_type)
    return [
        f"Validate {label} preview structure with sanitized fixtures.",
        "Confirm export-safe dictionaries contain no private identifiers.",
        "Confirm no files, databases, services, or history stores were modified.",
    ]


def build_operator_steps(migration_type: str) -> list[str]:
    label = _migration_type(migration_type)
    return [
        f"Review {label} migration preview before upgrade.",
        "Confirm required backups exist in an operator-approved location.",
        "Record any external migration decision outside this dry-run preview.",
    ]


def build_safety_warnings(migration_type: str) -> list[str]:
    label = _migration_type(migration_type)
    warnings = {
        "preview_only",
        "destructive_action_disabled",
        "automatic_migration_disabled",
        "operator_review_required",
    }
    if label == "historical_snapshot_schema":
        warnings.add("snapshot_rewrite_disabled")
    if label == "service_lifecycle_plan":
        warnings.add("service_installation_disabled")
    return sorted(warnings)


def build_migration_dashboard_record(*, name: str, migration_type: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "migration_preview_dashboard",
        "record_version": MIGRATION_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "migration_name": name,
        "migration_type": migration_type,
        "state": "preview",
        "operator_review_required": True,
        **MIGRATION_PLAN_SAFETY_FLAGS,
    }


def build_migration_api_response(*, name: str, migration_type: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "migration_preview_api_response",
        "record_version": MIGRATION_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "migration_name": name,
        "migration_type": migration_type,
        "preview_only": True,
        "destructive_action": False,
        **MIGRATION_PLAN_SAFETY_FLAGS,
    }


def build_migration_export_dict(*, name: str, migration_type: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "migration_preview_export",
        "record_version": MIGRATION_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "migration_name": name,
        "migration_type": migration_type,
        "backup_count": len(build_required_backup_list(migration_type)),
        "preview_only": True,
        "destructive_action": False,
        **MIGRATION_PLAN_SAFETY_FLAGS,
    }


def migration_preview_to_dict(record: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record or {})
    migration_type = _migration_type(payload.get("migration_type") or "config")
    name = _migration_name(payload.get("migration_name"), migration_type)
    return {
        "record_type": str(payload.get("record_type") or "deployment_migration_preview"),
        "record_version": int(payload.get("record_version") or MIGRATION_PLAN_RECORD_VERSION),
        "migration_name": name,
        "migration_type": migration_type,
        "current_version": _version_label(payload.get("current_version") or "unknown"),
        "target_version": _version_label(payload.get("target_version") or "unknown"),
        "required_backups": _string_list(payload.get("required_backups") or []),
        "rollback_notes": _string_list(payload.get("rollback_notes") or []),
        "validation_steps": _string_list(payload.get("validation_steps") or []),
        "operator_steps": _string_list(payload.get("operator_steps") or []),
        "safety_warnings": _string_list(payload.get("safety_warnings") or []),
        "preview_only": True,
        "destructive_action": False,
        **MIGRATION_PLAN_SAFETY_FLAGS,
    }


def export_migration_preview(record: dict[str, Any]) -> str:
    return json.dumps(migration_preview_to_dict(record), sort_keys=True)


def _migration_type(value: Any) -> str:
    normalized = str(value or "config").strip().lower().replace("-", "_")
    if normalized not in MIGRATION_TYPES:
        raise ValueError(f"migration_type must be one of: {', '.join(sorted(MIGRATION_TYPES))}")
    return normalized


def _migration_name(value: Any, migration_type: str) -> str:
    text = str(value or migration_type).strip().lower().replace("_", "-")
    safe = "".join(char for char in text if char.isalnum() or char in {"-", "."}).strip(".-")
    return safe or migration_type.replace("_", "-")


def _version_label(value: Any) -> str:
    text = str(value or "unknown").strip()
    safe = "".join(char for char in text if char.isalnum() or char in {".", "-", "+"}).strip(".-+")
    return safe or "unknown"


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
