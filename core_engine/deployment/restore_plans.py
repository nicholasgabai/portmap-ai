from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.deployment.backup_plans import BACKUP_PLAN_SAFETY_FLAGS


RESTORE_PLAN_RECORD_VERSION = 1

RESTORE_TYPES = frozenset(
    {
        "config",
        "deployment_manifest",
        "runtime_profile",
        "historical_intelligence",
        "evidence_bundle",
    }
)

RESTORE_PLAN_SAFETY_FLAGS = {
    **BACKUP_PLAN_SAFETY_FLAGS,
    "restore_plan_only": True,
    "preview_only": True,
    "dry_run_only": True,
    "destructive_action": False,
    "restore_executed": False,
    "files_restored": False,
    "files_overwritten": False,
    "files_deleted": False,
    "history_store_modified": False,
    "snapshots_rewritten": False,
    "archive_extracted": False,
}


def build_restore_preview(
    restore_type: str,
    *,
    restore_name: str | None = None,
    source_class: str = "operator-approved-backup-reference",
    target_class: str = "operator-reviewed-local-target",
    source_available: bool = True,
    target_compatible: bool = True,
    conflict_hints: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a restore preview without restoring, overwriting, or deleting files."""
    timestamp = generated_at or _now()
    normalized_type = _restore_type(restore_type)
    name = _safe_name(restore_name or normalized_type)
    checks = build_restore_compatibility_checks(
        restore_type=normalized_type,
        source_available=source_available,
        target_compatible=target_compatible,
        generated_at=timestamp,
    )
    conflicts = build_restore_conflict_warnings(normalized_type, conflict_hints=conflict_hints, generated_at=timestamp)
    return {
        "record_type": "deployment_restore_preview",
        "record_version": RESTORE_PLAN_RECORD_VERSION,
        "restore_preview_id": "restore-preview-" + _digest(
            {
                "restore_name": name,
                "restore_type": normalized_type,
                "source_class": source_class,
                "target_class": target_class,
                "generated_at": timestamp,
            }
        )[:16],
        "generated_at": timestamp,
        "restore_name": name,
        "restore_type": normalized_type,
        "source_class": _class_label(source_class),
        "target_class": _class_label(target_class),
        "compatibility_checks": checks,
        "rollback_notes": build_restore_rollback_notes(normalized_type),
        "conflict_warnings": conflicts,
        "operator_steps": build_restore_operator_steps(normalized_type),
        "validation_steps": build_restore_validation_steps(normalized_type),
        "preview_only": True,
        "destructive_action": False,
        "dashboard_status": build_restore_dashboard_record(name=name, restore_type=normalized_type, state=_checks_state(checks), generated_at=timestamp),
        "api_status": build_restore_api_response(name=name, restore_type=normalized_type, state=_checks_state(checks), generated_at=timestamp),
        "export": build_restore_export_dict(name=name, restore_type=normalized_type, state=_checks_state(checks), conflict_count=len(conflicts), generated_at=timestamp),
        **RESTORE_PLAN_SAFETY_FLAGS,
    }


def build_default_restore_preview_set(*, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    previews = [build_restore_preview(restore_type, generated_at=timestamp) for restore_type in sorted(RESTORE_TYPES)]
    return {
        "record_type": "deployment_restore_preview_set",
        "record_version": RESTORE_PLAN_RECORD_VERSION,
        "restore_set_id": "restore-preview-set-" + _digest({"generated_at": timestamp, "restore_types": [row["restore_type"] for row in previews]})[:16],
        "generated_at": timestamp,
        "restore_count": len(previews),
        "restore_types": [row["restore_type"] for row in previews],
        "previews": previews,
        "preview_only": True,
        "destructive_action": False,
        **RESTORE_PLAN_SAFETY_FLAGS,
    }


def build_restore_compatibility_checks(
    *,
    restore_type: str,
    source_available: bool,
    target_compatible: bool,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    normalized_type = _restore_type(restore_type)
    rows = [
        ("source_available", "supported" if source_available else "blocked", "Backup source reference is available." if source_available else "Backup source reference is missing."),
        ("target_compatible", "supported" if target_compatible else "blocked", "Restore target class is compatible." if target_compatible else "Restore target class is incompatible."),
        ("manual_review", "degraded", "Manual operator review is required before any restore action."),
    ]
    if normalized_type == "historical_intelligence":
        rows.append(("payload_safety", "supported", "Historical restore preview excludes raw packet payloads and credentials."))
    return [
        {
            "record_type": "restore_compatibility_check",
            "record_version": RESTORE_PLAN_RECORD_VERSION,
            "generated_at": timestamp,
            "check_name": name,
            "state": state,
            "operator_summary": summary,
            **RESTORE_PLAN_SAFETY_FLAGS,
        }
        for name, state, summary in rows
    ]


def build_restore_conflict_warnings(
    restore_type: str,
    *,
    conflict_hints: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    normalized_type = _restore_type(restore_type)
    warnings = {"overwrite_disabled", "delete_disabled", "restore_execution_disabled"}
    warnings.update(str(item).strip().lower().replace(" ", "_") for item in conflict_hints or [] if str(item).strip())
    if normalized_type in {"config", "runtime_profile"}:
        warnings.add("active_configuration_conflict_possible")
    if normalized_type == "historical_intelligence":
        warnings.add("history_retention_conflict_possible")
    if normalized_type == "evidence_bundle":
        warnings.add("redaction_validation_required")
    timestamp = generated_at or _now()
    return [
        {
            "record_type": "restore_conflict_warning",
            "record_version": RESTORE_PLAN_RECORD_VERSION,
            "generated_at": timestamp,
            "warning": warning,
            "operator_review_required": True,
            **RESTORE_PLAN_SAFETY_FLAGS,
        }
        for warning in sorted(warnings)
    ]


def build_restore_rollback_notes(restore_type: str) -> list[str]:
    label = _restore_type(restore_type)
    return [
        f"Keep the current {label} metadata export until restore validation completes.",
        "Rollback remains a manual operator workflow and is not executed by this preview.",
        "Do not overwrite existing local records without an external operator-approved rollback plan.",
    ]


def build_restore_operator_steps(restore_type: str) -> list[str]:
    label = _restore_type(restore_type)
    return [
        f"Review the {label} restore preview and compatibility checks.",
        "Confirm backup source and restore target are operator-approved placeholders.",
        "Resolve conflict warnings before any external restore workflow.",
        "Perform any real restore manually outside this preview.",
    ]


def build_restore_validation_steps(restore_type: str) -> list[str]:
    label = _restore_type(restore_type)
    return [
        f"Validate {label} restore preview with sanitized fixtures.",
        "Confirm no files were restored, overwritten, deleted, or extracted.",
        "Confirm export-safe summaries contain no private identifiers.",
    ]


def build_restore_dashboard_record(*, name: str, restore_type: str, state: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "restore_preview_dashboard",
        "record_version": RESTORE_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "restore_name": name,
        "restore_type": restore_type,
        "state": state,
        "operator_review_required": True,
        **RESTORE_PLAN_SAFETY_FLAGS,
    }


def build_restore_api_response(*, name: str, restore_type: str, state: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "restore_preview_api_response",
        "record_version": RESTORE_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "restore_name": name,
        "restore_type": restore_type,
        "state": state,
        "preview_only": True,
        "destructive_action": False,
        **RESTORE_PLAN_SAFETY_FLAGS,
    }


def build_restore_export_dict(*, name: str, restore_type: str, state: str, conflict_count: int, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "restore_preview_export",
        "record_version": RESTORE_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "restore_name": name,
        "restore_type": restore_type,
        "state": state,
        "conflict_warning_count": int(conflict_count),
        "preview_only": True,
        "destructive_action": False,
        **RESTORE_PLAN_SAFETY_FLAGS,
    }


def restore_preview_to_dict(record: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record or {})
    restore_type = _restore_type(payload.get("restore_type") or "config")
    return {
        "record_type": str(payload.get("record_type") or "deployment_restore_preview"),
        "record_version": int(payload.get("record_version") or RESTORE_PLAN_RECORD_VERSION),
        "restore_name": _safe_name(payload.get("restore_name") or restore_type),
        "restore_type": restore_type,
        "source_class": _class_label(payload.get("source_class") or "operator-approved-backup-reference"),
        "target_class": _class_label(payload.get("target_class") or "operator-reviewed-local-target"),
        "rollback_notes": _string_list(payload.get("rollback_notes") or []),
        "operator_steps": _string_list(payload.get("operator_steps") or []),
        "validation_steps": _string_list(payload.get("validation_steps") or []),
        "preview_only": True,
        "destructive_action": False,
        **RESTORE_PLAN_SAFETY_FLAGS,
    }


def export_restore_preview(record: dict[str, Any]) -> str:
    return json.dumps(restore_preview_to_dict(record), sort_keys=True)


def _checks_state(checks: list[dict[str, Any]]) -> str:
    states = [str(row.get("state") or "unknown") for row in checks]
    if "blocked" in states:
        return "blocked"
    if "degraded" in states:
        return "degraded"
    if all(state == "supported" for state in states):
        return "supported"
    return "unknown"


def _restore_type(value: Any) -> str:
    normalized = str(value or "config").strip().lower().replace("-", "_")
    if normalized not in RESTORE_TYPES:
        raise ValueError(f"restore_type must be one of: {', '.join(sorted(RESTORE_TYPES))}")
    return normalized


def _class_label(value: Any) -> str:
    text = str(value or "operator-approved-reference").strip().lower().replace("_", "-")
    safe = "".join(char for char in text if char.isalnum() or char in {"-", "."}).strip(".-")
    return safe or "operator-approved-reference"


def _safe_name(value: Any) -> str:
    text = str(value or "restore-preview").strip().lower().replace("_", "-")
    safe = "".join(char for char in text if char.isalnum() or char in {"-", "."}).strip(".-")
    return safe or "restore-preview"


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
