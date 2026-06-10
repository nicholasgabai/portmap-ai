from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    normalize_source_mode,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)


RETENTION_TIER_RECORD_VERSION = 1
RETENTION_TIER_TYPES = {"hot", "warm", "cold", "archive_preview", "unknown"}
COMPACTION_POLICIES = {"none", "summarize", "sample", "rollup", "drop_preview", "unknown"}
RETENTION_TIER_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "live_database_dependency": False,
    "storage_written": False,
    "data_deleted": False,
    "compaction_executed": False,
    "destructive_storage_action": False,
}


class RetentionTierError(ValueError):
    """Raised when a retention tier cannot be represented safely."""


@dataclass(frozen=True)
class RetentionTierRecord:
    tier_id: str
    tier_name: str
    tier_type: str
    max_records: int
    max_bytes: int
    retention_window_seconds: int
    priority: int
    compaction_policy: str
    export_policy: str
    source_mode: str
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "retention_tier",
            "record_version": RETENTION_TIER_RECORD_VERSION,
            "tier_id": sanitize_reference(self.tier_id),
            "tier_name": sanitize_text(self.tier_name) or "Unnamed retention tier",
            "tier_type": normalize_tier_type(self.tier_type),
            "max_records": bounded_int(self.max_records),
            "max_bytes": bounded_int(self.max_bytes),
            "retention_window_seconds": bounded_int(self.retention_window_seconds),
            "priority": bounded_priority(self.priority),
            "compaction_policy": normalize_compaction_policy(self.compaction_policy),
            "export_policy": sanitize_token(self.export_policy) or "summary_only",
            "source_mode": mode,
            "data_source": mode,
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **RETENTION_TIER_SAFETY_FLAGS,
        }


def build_retention_tier(
    *,
    tier_id: Any = "",
    tier_name: Any = "",
    tier_type: Any = "unknown",
    max_records: Any = 0,
    max_bytes: Any = 0,
    retention_window_seconds: Any = 0,
    priority: Any = 100,
    compaction_policy: Any = "unknown",
    export_policy: Any = "summary_only",
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> RetentionTierRecord:
    normalized_type = normalize_tier_type(tier_type)
    normalized_policy = normalize_compaction_policy(compaction_policy)
    notes = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    if bounded_int(max_records) == 0 and bounded_int(max_bytes) == 0:
        notes.append("retention tier has no positive record or byte capacity")
    if normalized_policy == "drop_preview":
        notes.append("drop preview is advisory only; no data deletion is performed")
    notes.append("retention tier is metadata-only; no filesystem or database writes")
    safe_name = sanitize_text(tier_name) or f"{normalized_type} retention tier"
    safe_id = sanitize_reference(tier_id)
    if not safe_id:
        safe_id = "retention-tier-" + digest(
            {
                "tier_name": safe_name,
                "tier_type": normalized_type,
                "max_records": bounded_int(max_records),
                "max_bytes": bounded_int(max_bytes),
                "retention_window_seconds": bounded_int(retention_window_seconds),
                "priority": bounded_priority(priority),
                "compaction_policy": normalized_policy,
                "source_mode": normalize_source_mode(source_mode),
            }
        )[:16]
    return RetentionTierRecord(
        tier_id=safe_id,
        tier_name=safe_name,
        tier_type=normalized_type,
        max_records=bounded_int(max_records),
        max_bytes=bounded_int(max_bytes),
        retention_window_seconds=bounded_int(retention_window_seconds),
        priority=bounded_priority(priority),
        compaction_policy=normalized_policy,
        export_policy=sanitize_token(export_policy) or "summary_only",
        source_mode=normalize_source_mode(source_mode),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_retention_tier(value: Any, *, source_mode: Any = "unknown") -> RetentionTierRecord:
    if isinstance(value, RetentionTierRecord):
        return value
    if not isinstance(value, dict):
        return build_retention_tier(
            tier_name="Invalid retention tier",
            tier_type="unknown",
            max_records=0,
            max_bytes=0,
            retention_window_seconds=0,
            priority=999,
            compaction_policy="unknown",
            source_mode=source_mode,
            advisory_notes=["invalid retention tier generated from malformed input"],
        )
    try:
        return build_retention_tier(
            tier_id=value.get("tier_id", ""),
            tier_name=value.get("tier_name", value.get("name", "")),
            tier_type=value.get("tier_type", value.get("type", "unknown")),
            max_records=value.get("max_records", 0),
            max_bytes=value.get("max_bytes", 0),
            retention_window_seconds=value.get("retention_window_seconds", value.get("window_seconds", 0)),
            priority=value.get("priority", 100),
            compaction_policy=value.get("compaction_policy", "unknown"),
            export_policy=value.get("export_policy", "summary_only"),
            source_mode=value.get("source_mode", value.get("data_source", source_mode)),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_retention_tier(
            tier_name="Invalid retention tier",
            tier_type="unknown",
            source_mode=source_mode,
            advisory_notes=[str(exc)],
        )


def default_retention_tiers(*, source_mode: Any = "unknown") -> list[RetentionTierRecord]:
    mode = normalize_source_mode(source_mode)
    return [
        build_retention_tier(
            tier_name="Hot telemetry metadata",
            tier_type="hot",
            max_records=50_000,
            max_bytes=64_000_000,
            retention_window_seconds=86_400,
            priority=10,
            compaction_policy="none",
            export_policy="summary_only",
            source_mode=mode,
        ),
        build_retention_tier(
            tier_name="Warm telemetry rollups",
            tier_type="warm",
            max_records=250_000,
            max_bytes=256_000_000,
            retention_window_seconds=604_800,
            priority=30,
            compaction_policy="summarize",
            export_policy="summary_only",
            source_mode=mode,
        ),
        build_retention_tier(
            tier_name="Cold telemetry samples",
            tier_type="cold",
            max_records=500_000,
            max_bytes=512_000_000,
            retention_window_seconds=2_592_000,
            priority=60,
            compaction_policy="sample",
            export_policy="count_only",
            source_mode=mode,
        ),
        build_retention_tier(
            tier_name="Archive preview metadata",
            tier_type="archive_preview",
            max_records=1_000_000,
            max_bytes=1_024_000_000,
            retention_window_seconds=7_776_000,
            priority=90,
            compaction_policy="rollup",
            export_policy="hash_only",
            source_mode=mode,
        ),
    ]


def normalize_tier_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in RETENTION_TIER_TYPES else "unknown"


def normalize_compaction_policy(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in COMPACTION_POLICIES else "unknown"


def bounded_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except Exception:
        return 0


def bounded_priority(value: Any) -> int:
    try:
        return max(0, min(999, int(value)))
    except Exception:
        return 999


def retention_tier_summary(tiers: list[RetentionTierRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    normalized = [normalize_retention_tier(tier).to_dict() for tier in tiers]
    type_counts: dict[str, int] = {}
    compaction_counts: dict[str, int] = {}
    for row in normalized:
        type_counts[row["tier_type"]] = type_counts.get(row["tier_type"], 0) + 1
        compaction_counts[row["compaction_policy"]] = compaction_counts.get(row["compaction_policy"], 0) + 1
    return {
        "tier_count": len(normalized),
        "type_counts": dict(sorted(type_counts.items())),
        "compaction_policy_counts": dict(sorted(compaction_counts.items())),
        "total_record_capacity": sum(row["max_records"] for row in normalized),
        "total_byte_capacity": sum(row["max_bytes"] for row in normalized),
        "preview_only": True,
        "destructive_action": False,
        "generated_at": now_timestamp(),
    }


def deterministic_retention_json(record: RetentionTierRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, RetentionTierRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "COMPACTION_POLICIES",
    "RETENTION_TIER_TYPES",
    "RetentionTierError",
    "RetentionTierRecord",
    "bounded_int",
    "bounded_priority",
    "build_retention_tier",
    "default_retention_tiers",
    "deterministic_retention_json",
    "normalize_compaction_policy",
    "normalize_retention_tier",
    "normalize_tier_type",
    "retention_tier_summary",
]
