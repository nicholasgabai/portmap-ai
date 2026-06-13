from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.governance.audit_events import GOVERNANCE_SAFETY_FLAGS, sanitize_notes
from core_engine.scaling.bus_envelopes import digest, now_timestamp, safe_float, safe_int, sanitize_reference, sanitize_token


LOG_ROTATION_RECORD_VERSION = 1
LOG_ROTATION_STATES = {
    "ready",
    "rotation_recommended",
    "retention_pressure",
    "degraded",
    "unavailable",
    "unknown",
}
LOG_FAMILIES = {"master", "worker", "audit", "export", "runtime", "tui", "unknown"}


@dataclass(frozen=True)
class DailyLogRotationReadinessRecord:
    rotation_id: str
    generated_at: str
    rotation_state: str
    log_family: str
    current_log_reference: str
    rotation_period: str
    retention_days: int
    max_file_size_mb: float
    estimated_log_count: int
    retention_preview: dict[str, Any] = field(default_factory=dict)
    compression_preview: dict[str, Any] = field(default_factory=dict)
    deletion_preview: dict[str, Any] = field(default_factory=dict)
    validation_summary: dict[str, Any] = field(default_factory=dict)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "daily_log_rotation_readiness",
            "record_version": LOG_ROTATION_RECORD_VERSION,
            "rotation_id": sanitize_reference(self.rotation_id),
            "generated_at": str(self.generated_at or ""),
            "rotation_state": normalize_log_rotation_state(self.rotation_state),
            "log_family": normalize_log_family(self.log_family),
            "current_log_reference": sanitize_reference(self.current_log_reference) or "log-unknown",
            "rotation_period": normalize_rotation_period(self.rotation_period),
            "retention_days": max(0, int(self.retention_days or 0)),
            "max_file_size_mb": round(max(0.0, float(self.max_file_size_mb or 0.0)), 3),
            "estimated_log_count": max(0, int(self.estimated_log_count or 0)),
            "retention_preview": dict(self.retention_preview),
            "compression_preview": dict(self.compression_preview),
            "deletion_preview": dict(self.deletion_preview),
            "validation_summary": dict(self.validation_summary),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **GOVERNANCE_SAFETY_FLAGS,
        }


def build_daily_log_rotation_readiness(
    *,
    rotation_id: Any = "",
    generated_at: Any = None,
    rotation_state: Any = "",
    log_family: Any = "unknown",
    current_log_reference: Any = "log-unknown",
    rotation_period: Any = "daily",
    retention_days: Any = 14,
    max_file_size_mb: Any = 64,
    estimated_log_count: Any = 0,
    retention_preview: dict[str, Any] | None = None,
    compression_preview: dict[str, Any] | None = None,
    deletion_preview: dict[str, Any] | None = None,
    validation_summary: dict[str, Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> DailyLogRotationReadinessRecord:
    timestamp = str(generated_at or now_timestamp())
    family = normalize_log_family(log_family)
    retention = safe_int(retention_days)
    size_mb = safe_float(max_file_size_mb)
    log_count = safe_int(estimated_log_count)
    retention_row = retention_preview or build_retention_preview(retention_days=retention, estimated_log_count=log_count)
    compression_row = compression_preview or build_compression_preview(log_family=family)
    deletion_row = deletion_preview or build_deletion_preview(retention_days=retention)
    validation = validation_summary or build_rotation_validation_summary(
        rotation_period=rotation_period,
        retention_days=retention,
        max_file_size_mb=size_mb,
        estimated_log_count=log_count,
        advisory_notes=advisory_notes,
    )
    state = normalize_log_rotation_state(rotation_state) if rotation_state else infer_rotation_state(
        retention_days=retention,
        max_file_size_mb=size_mb,
        estimated_log_count=log_count,
    )
    safe_id = sanitize_reference(rotation_id)
    if not safe_id:
        safe_id = "log-rotation-" + digest(
            {
                "generated_at": timestamp,
                "log_family": family,
                "current_log_reference": sanitize_reference(current_log_reference),
                "rotation_period": normalize_rotation_period(rotation_period),
            }
        )[:16]
    return DailyLogRotationReadinessRecord(
        rotation_id=safe_id,
        generated_at=timestamp,
        rotation_state=state,
        log_family=family,
        current_log_reference=sanitize_reference(current_log_reference) or "log-unknown",
        rotation_period=normalize_rotation_period(rotation_period),
        retention_days=retention,
        max_file_size_mb=size_mb,
        estimated_log_count=log_count,
        retention_preview=retention_row,
        compression_preview=compression_row,
        deletion_preview=deletion_row,
        validation_summary=validation,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def normalize_log_rotation_readiness(value: Any) -> DailyLogRotationReadinessRecord:
    if isinstance(value, DailyLogRotationReadinessRecord):
        return value
    if not isinstance(value, dict):
        return build_daily_log_rotation_readiness(
            rotation_state="degraded",
            advisory_notes=["invalid rotation readiness generated from malformed input"],
        )
    try:
        return build_daily_log_rotation_readiness(
            rotation_id=value.get("rotation_id", ""),
            generated_at=value.get("generated_at"),
            rotation_state=value.get("rotation_state", ""),
            log_family=value.get("log_family", "unknown"),
            current_log_reference=value.get("current_log_reference", ""),
            rotation_period=value.get("rotation_period", "daily"),
            retention_days=value.get("retention_days", 14),
            max_file_size_mb=value.get("max_file_size_mb", 64),
            estimated_log_count=value.get("estimated_log_count", 0),
            retention_preview=value.get("retention_preview") if isinstance(value.get("retention_preview"), dict) else None,
            compression_preview=value.get("compression_preview") if isinstance(value.get("compression_preview"), dict) else None,
            deletion_preview=value.get("deletion_preview") if isinstance(value.get("deletion_preview"), dict) else None,
            validation_summary=value.get("validation_summary") if isinstance(value.get("validation_summary"), dict) else None,
        )
    except Exception as exc:
        return build_daily_log_rotation_readiness(rotation_state="degraded", advisory_notes=[str(exc)])


def build_retention_preview(*, retention_days: int, estimated_log_count: int) -> dict[str, Any]:
    return {
        "record_type": "log_retention_preview",
        "retention_days": max(0, retention_days),
        "estimated_log_count": max(0, estimated_log_count),
        "retention_action": "review_retention_policy" if estimated_log_count > max(1, retention_days * 2) else "retain_preview",
        "deletion_performed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **GOVERNANCE_SAFETY_FLAGS,
    }


def build_compression_preview(*, log_family: Any) -> dict[str, Any]:
    return {
        "record_type": "log_compression_preview",
        "log_family": normalize_log_family(log_family),
        "compression_recommended": True,
        "compression_performed": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **GOVERNANCE_SAFETY_FLAGS,
    }


def build_deletion_preview(*, retention_days: int) -> dict[str, Any]:
    return {
        "record_type": "log_deletion_preview",
        "retention_days": max(0, retention_days),
        "deletion_recommended": retention_days > 0,
        "deletion_performed": False,
        "advisory_only": True,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **GOVERNANCE_SAFETY_FLAGS,
    }


def build_rotation_validation_summary(
    *,
    rotation_period: Any,
    retention_days: int,
    max_file_size_mb: float,
    estimated_log_count: int,
    advisory_notes: Iterable[Any] | None = None,
) -> dict[str, Any]:
    notes = sanitize_notes(advisory_notes or ["daily rotation readiness only; no files are moved, compressed, or deleted"])
    return {
        "record_type": "log_rotation_validation_summary",
        "rotation_period": normalize_rotation_period(rotation_period),
        "retention_days_valid": retention_days > 0,
        "max_file_size_valid": max_file_size_mb > 0,
        "estimated_log_count": max(0, estimated_log_count),
        "advisory_notes": notes,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **GOVERNANCE_SAFETY_FLAGS,
    }


def infer_rotation_state(*, retention_days: int, max_file_size_mb: float, estimated_log_count: int) -> str:
    if retention_days <= 0 or max_file_size_mb <= 0:
        return "degraded"
    if estimated_log_count > retention_days * 3:
        return "retention_pressure"
    if estimated_log_count > retention_days:
        return "rotation_recommended"
    return "ready"


def normalize_log_rotation_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in LOG_ROTATION_STATES else "unknown"


def normalize_log_family(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in LOG_FAMILIES else "unknown"


def normalize_rotation_period(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in {"daily", "weekly", "manual", "unknown"} else "daily"


def deterministic_log_rotation_json(record: DailyLogRotationReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, DailyLogRotationReadinessRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "LOG_FAMILIES",
    "LOG_ROTATION_STATES",
    "DailyLogRotationReadinessRecord",
    "build_compression_preview",
    "build_daily_log_rotation_readiness",
    "build_deletion_preview",
    "build_retention_preview",
    "deterministic_log_rotation_json",
    "infer_rotation_state",
    "normalize_log_family",
    "normalize_log_rotation_readiness",
    "normalize_log_rotation_state",
    "normalize_rotation_period",
]
