from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.deployment.upgrade_readiness import UPGRADE_READINESS_SAFETY_FLAGS


BACKUP_PLAN_RECORD_VERSION = 1

BACKUP_TYPES = frozenset(
    {
        "configuration",
        "deployment_manifest",
        "runtime_export",
        "historical_intelligence",
        "operator_evidence_bundle",
    }
)

BACKUP_PLAN_SAFETY_FLAGS = {
    **UPGRADE_READINESS_SAFETY_FLAGS,
    "backup_plan_only": True,
    "dry_run_only": True,
    "preview_only": True,
    "destructive_action": False,
    "backup_created": False,
    "files_copied": False,
    "archive_created": False,
    "runtime_artifacts_compressed": False,
    "credentials_copied": False,
    "secrets_stored": False,
    "restore_executed": False,
    "files_overwritten": False,
    "files_deleted": False,
}


def build_backup_plan(
    backup_type: str,
    *,
    backup_name: str | None = None,
    destination_class: str = "operator-approved-local-export",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a backup plan record without creating backups or archives."""
    timestamp = generated_at or _now()
    normalized_type = _backup_type(backup_type)
    name = _safe_name(backup_name or normalized_type)
    template = _backup_templates()[normalized_type]
    plan = {
        "record_type": "deployment_backup_plan",
        "record_version": BACKUP_PLAN_RECORD_VERSION,
        "backup_plan_id": "backup-plan-" + _digest(
            {
                "backup_name": name,
                "backup_type": normalized_type,
                "destination_class": destination_class,
                "generated_at": timestamp,
            }
        )[:16],
        "generated_at": timestamp,
        "backup_name": name,
        "backup_type": normalized_type,
        "included_components": sorted(template["included_components"]),
        "excluded_components": sorted(template["excluded_components"]),
        "destination_class": _destination_class(destination_class),
        "retention_recommendation": template["retention_recommendation"],
        "encryption_recommended": bool(template["encryption_recommended"]),
        "operator_steps": build_backup_operator_steps(normalized_type),
        "validation_steps": build_backup_validation_steps(normalized_type),
        "dry_run_only": True,
        "destructive_action": False,
        "advisory_notes": build_backup_advisory_notes(normalized_type),
        "dashboard_status": build_backup_dashboard_record(name=name, backup_type=normalized_type, generated_at=timestamp),
        "api_status": build_backup_api_response(name=name, backup_type=normalized_type, generated_at=timestamp),
        "export": build_backup_export_dict(name=name, backup_type=normalized_type, generated_at=timestamp),
        **BACKUP_PLAN_SAFETY_FLAGS,
    }
    return plan


def build_default_backup_plan_set(*, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    plans = [build_backup_plan(backup_type, generated_at=timestamp) for backup_type in sorted(BACKUP_TYPES)]
    return {
        "record_type": "deployment_backup_plan_set",
        "record_version": BACKUP_PLAN_RECORD_VERSION,
        "backup_set_id": "backup-plan-set-" + _digest({"generated_at": timestamp, "backup_types": [row["backup_type"] for row in plans]})[:16],
        "generated_at": timestamp,
        "backup_count": len(plans),
        "backup_types": [row["backup_type"] for row in plans],
        "plans": plans,
        "dry_run_only": True,
        "destructive_action": False,
        **BACKUP_PLAN_SAFETY_FLAGS,
    }


def build_backup_operator_steps(backup_type: str) -> list[str]:
    label = _backup_type(backup_type)
    return [
        f"Review the {label} backup plan and included components.",
        "Select an operator-approved local destination outside committed source files.",
        "Confirm excluded components prevent credentials, logs, caches, databases, and runtime artifacts from being copied.",
        "Perform any real backup manually outside this dry-run plan.",
    ]


def build_backup_validation_steps(backup_type: str) -> list[str]:
    label = _backup_type(backup_type)
    return [
        f"Validate {label} backup metadata with sanitized fixtures.",
        "Confirm exported summaries contain no private identifiers.",
        "Confirm no archive, copy, delete, overwrite, or restore operation was performed.",
    ]


def build_backup_advisory_notes(backup_type: str) -> list[str]:
    label = _backup_type(backup_type)
    notes = {
        "Backup planning is metadata-only and does not copy files.",
        "Encryption is recommended for operator-created backup media.",
        "Credentials, secrets, raw logs, cache files, databases, and runtime artifacts remain excluded.",
    }
    if label == "historical_intelligence":
        notes.add("Historical intelligence backups should include metadata summaries, not raw packet payloads or browsing history.")
    if label == "operator_evidence_bundle":
        notes.add("Evidence bundle backups should preserve redaction and placeholder validation results.")
    return sorted(notes)


def build_backup_dashboard_record(*, name: str, backup_type: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "backup_plan_dashboard",
        "record_version": BACKUP_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "backup_name": name,
        "backup_type": backup_type,
        "state": "preview",
        "operator_review_required": True,
        **BACKUP_PLAN_SAFETY_FLAGS,
    }


def build_backup_api_response(*, name: str, backup_type: str, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "backup_plan_api_response",
        "record_version": BACKUP_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "backup_name": name,
        "backup_type": backup_type,
        "dry_run_only": True,
        "destructive_action": False,
        **BACKUP_PLAN_SAFETY_FLAGS,
    }


def build_backup_export_dict(*, name: str, backup_type: str, generated_at: str | None = None) -> dict[str, Any]:
    template = _backup_templates()[_backup_type(backup_type)]
    return {
        "record_type": "backup_plan_export",
        "record_version": BACKUP_PLAN_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "backup_name": name,
        "backup_type": backup_type,
        "included_component_count": len(template["included_components"]),
        "excluded_component_count": len(template["excluded_components"]),
        "encryption_recommended": bool(template["encryption_recommended"]),
        "dry_run_only": True,
        "destructive_action": False,
        **BACKUP_PLAN_SAFETY_FLAGS,
    }


def backup_plan_to_dict(record: dict[str, Any]) -> dict[str, Any]:
    payload = dict(record or {})
    backup_type = _backup_type(payload.get("backup_type") or "configuration")
    return {
        "record_type": str(payload.get("record_type") or "deployment_backup_plan"),
        "record_version": int(payload.get("record_version") or BACKUP_PLAN_RECORD_VERSION),
        "backup_name": _safe_name(payload.get("backup_name") or backup_type),
        "backup_type": backup_type,
        "included_components": _string_list(payload.get("included_components") or []),
        "excluded_components": _string_list(payload.get("excluded_components") or []),
        "destination_class": _destination_class(payload.get("destination_class") or "operator-approved-local-export"),
        "retention_recommendation": str(payload.get("retention_recommendation") or ""),
        "encryption_recommended": bool(payload.get("encryption_recommended", True)),
        "operator_steps": _string_list(payload.get("operator_steps") or []),
        "validation_steps": _string_list(payload.get("validation_steps") or []),
        "advisory_notes": _string_list(payload.get("advisory_notes") or []),
        "dry_run_only": True,
        "destructive_action": False,
        **BACKUP_PLAN_SAFETY_FLAGS,
    }


def export_backup_plan(record: dict[str, Any]) -> str:
    return json.dumps(backup_plan_to_dict(record), sort_keys=True)


def _backup_templates() -> dict[str, dict[str, Any]]:
    excluded = {
        "credentials",
        "secrets",
        "raw_packet_payloads",
        "runtime_logs",
        "screenshots",
        "cache_files",
        "local_databases",
        "temporary_files",
    }
    return {
        "configuration": {
            "included_components": ["runtime_profile_summary", "deployment_settings_summary", "safe_path_placeholders"],
            "excluded_components": excluded,
            "retention_recommendation": "Keep until next validated configuration backup is created.",
            "encryption_recommended": True,
        },
        "deployment_manifest": {
            "included_components": ["deployment_manifest_export", "node_profile_summary", "service_provider_summary"],
            "excluded_components": excluded | {"real_install_paths"},
            "retention_recommendation": "Keep with matching release and upgrade-readiness records.",
            "encryption_recommended": True,
        },
        "runtime_export": {
            "included_components": ["runtime_summary", "health_summary", "review_summary", "export_digest"],
            "excluded_components": excluded | {"raw_runtime_artifacts"},
            "retention_recommendation": "Keep according to local evidence retention policy.",
            "encryption_recommended": True,
        },
        "historical_intelligence": {
            "included_components": ["historical_snapshot_summaries", "baseline_rollups", "topology_evolution_rollups", "retention_summary"],
            "excluded_components": excluded | {"raw_browsing_history", "raw_dns_payloads"},
            "retention_recommendation": "Use bounded historical retention appropriate for the deployment profile.",
            "encryption_recommended": True,
        },
        "operator_evidence_bundle": {
            "included_components": ["redacted_evidence_manifest", "review_records", "digest_summary", "placeholder_validation"],
            "excluded_components": excluded | {"unredacted_evidence"},
            "retention_recommendation": "Keep only for the operator-approved evidence review window.",
            "encryption_recommended": True,
        },
    }


def _backup_type(value: Any) -> str:
    normalized = str(value or "configuration").strip().lower().replace("-", "_")
    if normalized not in BACKUP_TYPES:
        raise ValueError(f"backup_type must be one of: {', '.join(sorted(BACKUP_TYPES))}")
    return normalized


def _destination_class(value: Any) -> str:
    text = str(value or "operator-approved-local-export").strip().lower().replace("_", "-")
    safe = "".join(char for char in text if char.isalnum() or char in {"-", "."}).strip(".-")
    return safe or "operator-approved-local-export"


def _safe_name(value: Any) -> str:
    text = str(value or "backup-plan").strip().lower().replace("_", "-")
    safe = "".join(char for char in text if char.isalnum() or char in {"-", "."}).strip(".-")
    return safe or "backup-plan"


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
