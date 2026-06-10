from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    normalize_source_mode,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
)
from core_engine.scaling.retention_tiers import (
    RetentionTierRecord,
    bounded_int,
    default_retention_tiers,
    normalize_retention_tier,
    retention_tier_summary,
)


STORAGE_ENGINE_RECORD_VERSION = 1
STORAGE_STATES = {"ready", "degraded", "pressure", "over_capacity", "unavailable", "unknown"}
PRESSURE_STATES = {"normal", "elevated", "pressure", "over_capacity", "unavailable", "unknown"}
STORAGE_ENGINE_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "live_database_dependency": False,
    "runtime_data_written": False,
    "filesystem_written": False,
    "data_deleted": False,
    "compaction_executed": False,
    "destructive_storage_action": False,
}


@dataclass(frozen=True)
class StorageEngineSummary:
    storage_engine_id: str
    generated_at: str
    storage_state: str
    total_record_capacity: int
    total_byte_capacity: int
    estimated_current_records: int
    estimated_current_bytes: int
    utilization_ratio: float
    pressure_state: str
    write_capacity_summary: dict[str, Any] = field(default_factory=dict)
    read_capacity_summary: dict[str, Any] = field(default_factory=dict)
    compaction_preview: dict[str, Any] = field(default_factory=dict)
    retention_tiers: list[dict[str, Any]] = field(default_factory=list)
    advisory_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "storage_engine_summary",
            "record_version": STORAGE_ENGINE_RECORD_VERSION,
            "storage_engine_id": sanitize_reference(self.storage_engine_id),
            "generated_at": str(self.generated_at or ""),
            "storage_state": normalize_storage_state(self.storage_state),
            "total_record_capacity": bounded_int(self.total_record_capacity),
            "total_byte_capacity": bounded_int(self.total_byte_capacity),
            "estimated_current_records": bounded_int(self.estimated_current_records),
            "estimated_current_bytes": bounded_int(self.estimated_current_bytes),
            "utilization_ratio": round(clamp_float(self.utilization_ratio), 4),
            "pressure_state": normalize_pressure_state(self.pressure_state),
            "write_capacity_summary": sanitize_summary_dict(self.write_capacity_summary),
            "read_capacity_summary": sanitize_summary_dict(self.read_capacity_summary),
            "compaction_preview": sanitize_summary_dict(self.compaction_preview),
            "retention_tiers": list(self.retention_tiers),
            "advisory_recommendations": [sanitize_text(item) for item in self.advisory_recommendations],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **STORAGE_ENGINE_SAFETY_FLAGS,
        }


def build_storage_engine_summary(
    retention_tiers: Iterable[RetentionTierRecord | dict[str, Any] | Any] | None = None,
    *,
    telemetry_bus_summaries: Iterable[dict[str, Any] | Any] | None = None,
    estimated_current_records: Any = None,
    estimated_current_bytes: Any = None,
    avg_record_bytes: Any = 1024,
    generated_at: str | None = None,
    storage_engine_id: str | None = None,
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> StorageEngineSummary:
    timestamp = generated_at or now_timestamp()
    mode = normalize_source_mode(source_mode)
    tiers = list(default_retention_tiers(source_mode=mode) if retention_tiers is None else retention_tiers)
    normalized_tiers = [normalize_retention_tier(tier, source_mode=mode).to_dict() for tier in tiers]
    tier_summary = retention_tier_summary(normalized_tiers)
    total_records = tier_summary["total_record_capacity"]
    total_bytes = tier_summary["total_byte_capacity"]
    bus_summary = summarize_telemetry_bus_inputs(telemetry_bus_summaries)
    record_estimate = bounded_int(estimated_current_records)
    if estimated_current_records is None:
        record_estimate = bus_summary["estimated_records"]
    byte_estimate = bounded_int(estimated_current_bytes)
    if estimated_current_bytes is None:
        byte_estimate = max(record_estimate * max(1, bounded_int(avg_record_bytes)), bus_summary["estimated_bytes"])
    utilization = calculate_utilization(
        total_record_capacity=total_records,
        total_byte_capacity=total_bytes,
        estimated_current_records=record_estimate,
        estimated_current_bytes=byte_estimate,
    )
    pressure = pressure_state_from_utilization(utilization, has_capacity=bool(total_records or total_bytes))
    state = storage_state_from_pressure(pressure, normalized_tiers=normalized_tiers, bus_summary=bus_summary)
    write_summary = build_write_capacity_summary(
        total_record_capacity=total_records,
        estimated_current_records=record_estimate,
        bus_summary=bus_summary,
        utilization_ratio=utilization,
    )
    read_summary = build_read_capacity_summary(
        normalized_tiers=normalized_tiers,
        utilization_ratio=utilization,
        bus_summary=bus_summary,
    )
    compaction = build_compaction_preview(normalized_tiers, utilization_ratio=utilization, pressure_state=pressure)
    recommendations = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    recommendations.extend(recommendations_for_state(state, pressure, compaction))
    summary_id = storage_engine_id or "storage-engine-" + digest(
        {
            "generated_at": timestamp,
            "total_record_capacity": total_records,
            "total_byte_capacity": total_bytes,
            "estimated_current_records": record_estimate,
            "estimated_current_bytes": byte_estimate,
            "tier_ids": [row.get("tier_id") for row in normalized_tiers],
            "bus_summary": bus_summary,
        }
    )[:16]
    return StorageEngineSummary(
        storage_engine_id=summary_id,
        generated_at=timestamp,
        storage_state=state,
        total_record_capacity=total_records,
        total_byte_capacity=total_bytes,
        estimated_current_records=record_estimate,
        estimated_current_bytes=byte_estimate,
        utilization_ratio=utilization,
        pressure_state=pressure,
        write_capacity_summary=write_summary,
        read_capacity_summary=read_summary,
        compaction_preview=compaction,
        retention_tiers=normalized_tiers,
        advisory_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_storage_engine_summary(*, generated_at: str | None = None) -> StorageEngineSummary:
    return build_storage_engine_summary([], generated_at=generated_at)


def summarize_telemetry_bus_inputs(summaries: Iterable[dict[str, Any] | Any] | None) -> dict[str, Any]:
    rows = [item.to_dict() if hasattr(item, "to_dict") else item for item in list(summaries or [])]
    valid_rows = [row for row in rows if isinstance(row, dict)]
    malformed_count = len(rows) - len(valid_rows)
    queue_depth = sum(bounded_int(row.get("queue_depth", 0)) for row in valid_rows)
    max_queue_depth = sum(bounded_int(row.get("max_queue_depth", 0)) for row in valid_rows)
    dropped_count = sum(bounded_int(row.get("dropped_count", 0)) for row in valid_rows)
    retry_pending_count = sum(bounded_int(row.get("retry_pending_count", 0)) for row in valid_rows)
    topic_counts: dict[str, int] = {}
    for row in valid_rows:
        for topic, count in (row.get("topic_counts") or {}).items():
            safe_topic = sanitize_reference(topic) or "unknown"
            topic_counts[safe_topic] = topic_counts.get(safe_topic, 0) + bounded_int(count)
    return {
        "summary_count": len(valid_rows),
        "malformed_count": malformed_count,
        "estimated_records": queue_depth,
        "estimated_bytes": queue_depth * 1024,
        "queue_depth": queue_depth,
        "max_queue_depth": max_queue_depth,
        "dropped_count": dropped_count,
        "retry_pending_count": retry_pending_count,
        "topic_counts": dict(sorted(topic_counts.items())),
    }


def calculate_utilization(
    *,
    total_record_capacity: Any,
    total_byte_capacity: Any,
    estimated_current_records: Any,
    estimated_current_bytes: Any,
) -> float:
    record_capacity = bounded_int(total_record_capacity)
    byte_capacity = bounded_int(total_byte_capacity)
    record_ratio = bounded_int(estimated_current_records) / record_capacity if record_capacity else 0.0
    byte_ratio = bounded_int(estimated_current_bytes) / byte_capacity if byte_capacity else 0.0
    return round(max(record_ratio, byte_ratio), 6)


def pressure_state_from_utilization(utilization_ratio: Any, *, has_capacity: bool = True) -> str:
    if not has_capacity:
        return "unavailable"
    ratio = clamp_float(utilization_ratio)
    if ratio >= 1.0:
        return "over_capacity"
    if ratio >= 0.85:
        return "pressure"
    if ratio >= 0.65:
        return "elevated"
    return "normal"


def storage_state_from_pressure(
    pressure_state: str,
    *,
    normalized_tiers: list[dict[str, Any]],
    bus_summary: dict[str, Any],
) -> str:
    if not normalized_tiers:
        return "unavailable"
    if bus_summary.get("malformed_count", 0):
        return "degraded"
    if any(row.get("tier_type") == "unknown" for row in normalized_tiers):
        return "degraded"
    if pressure_state == "over_capacity":
        return "over_capacity"
    if pressure_state == "pressure":
        return "pressure"
    if pressure_state == "elevated":
        return "degraded"
    if pressure_state == "unavailable":
        return "unavailable"
    return "ready"


def build_write_capacity_summary(
    *,
    total_record_capacity: int,
    estimated_current_records: int,
    bus_summary: dict[str, Any],
    utilization_ratio: float,
) -> dict[str, Any]:
    remaining = max(0, bounded_int(total_record_capacity) - bounded_int(estimated_current_records))
    return {
        "estimated_remaining_records": remaining,
        "queue_depth_input": bounded_int(bus_summary.get("queue_depth", 0)),
        "retry_pending_count": bounded_int(bus_summary.get("retry_pending_count", 0)),
        "dropped_by_bound_count": bounded_int(bus_summary.get("dropped_count", 0)),
        "utilization_ratio": round(clamp_float(utilization_ratio), 4),
        "write_preview_only": True,
        "runtime_data_written": False,
    }


def build_read_capacity_summary(
    *,
    normalized_tiers: list[dict[str, Any]],
    utilization_ratio: float,
    bus_summary: dict[str, Any],
) -> dict[str, Any]:
    readable_tiers = [
        {
            "tier_id": sanitize_reference(row.get("tier_id", "")),
            "tier_type": sanitize_reference(row.get("tier_type", "unknown")),
            "export_policy": sanitize_reference(row.get("export_policy", "summary_only")),
            "priority": bounded_int(row.get("priority", 0)),
        }
        for row in sorted(normalized_tiers, key=lambda item: (bounded_int(item.get("priority", 999)), str(item.get("tier_id", ""))))
    ]
    return {
        "readable_tier_count": len(readable_tiers),
        "read_order_preview": readable_tiers,
        "topic_counts": bus_summary.get("topic_counts", {}),
        "utilization_ratio": round(clamp_float(utilization_ratio), 4),
        "read_preview_only": True,
        "database_dependency_required": False,
    }


def build_compaction_preview(
    normalized_tiers: list[dict[str, Any]],
    *,
    utilization_ratio: float,
    pressure_state: str,
) -> dict[str, Any]:
    actions = []
    for row in normalized_tiers:
        policy = row.get("compaction_policy", "unknown")
        if policy in {"summarize", "sample", "rollup", "drop_preview"}:
            actions.append(
                {
                    "tier_id": sanitize_reference(row.get("tier_id", "")),
                    "tier_type": sanitize_reference(row.get("tier_type", "unknown")),
                    "policy": sanitize_reference(policy),
                    "preview_reason": _compaction_reason(policy, pressure_state),
                    "destructive_action": False,
                }
            )
    recommended = pressure_state in {"pressure", "over_capacity"} and bool(actions)
    return {
        "recommended": recommended,
        "action_count": len(actions),
        "actions": actions,
        "utilization_ratio": round(clamp_float(utilization_ratio), 4),
        "pressure_state": normalize_pressure_state(pressure_state),
        "preview_only": True,
        "compaction_executed": False,
        "data_deleted": False,
    }


def recommendations_for_state(storage_state: str, pressure_state: str, compaction_preview: dict[str, Any]) -> list[str]:
    if storage_state == "unavailable":
        return ["define bounded retention tiers before enabling high-volume storage readiness"]
    if storage_state == "over_capacity":
        return ["review retention bounds and compaction previews before accepting more telemetry"]
    if storage_state == "pressure":
        return ["review warm/cold tier rollups and bus queue pressure before scaling intake"]
    if storage_state == "degraded":
        return ["review malformed inputs or elevated utilization before deployment scaling"]
    if compaction_preview.get("recommended"):
        return ["review compaction preview; no data mutation has been performed"]
    return ["storage readiness is advisory and metadata-only"]


def normalize_storage_state(value: Any) -> str:
    safe_value = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return safe_value if safe_value in STORAGE_STATES else "unknown"


def normalize_pressure_state(value: Any) -> str:
    safe_value = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return safe_value if safe_value in PRESSURE_STATES else "unknown"


def sanitize_summary_dict(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    safe: dict[str, Any] = {}
    for key, item in value.items():
        safe_key = sanitize_reference(key)
        if not safe_key:
            continue
        if isinstance(item, dict):
            safe[safe_key] = sanitize_summary_dict(item)
        elif isinstance(item, list):
            safe[safe_key] = [sanitize_summary_dict(entry) if isinstance(entry, dict) else sanitize_text(entry) for entry in item[:32]]
        elif isinstance(item, (int, float, bool)) or item is None:
            safe[safe_key] = item
        else:
            safe[safe_key] = sanitize_text(item)
    return safe


def clamp_float(value: Any) -> float:
    try:
        return max(0.0, float(value))
    except Exception:
        return 0.0


def deterministic_storage_json(summary: StorageEngineSummary | dict[str, Any]) -> str:
    payload = summary.to_dict() if isinstance(summary, StorageEngineSummary) else summary
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _compaction_reason(policy: str, pressure_state: str) -> str:
    if policy == "drop_preview":
        return "drop preview only; no deletion will run"
    if pressure_state in {"pressure", "over_capacity"}:
        return "storage pressure preview"
    return "retention-tier planning preview"


__all__ = [
    "PRESSURE_STATES",
    "STORAGE_STATES",
    "StorageEngineSummary",
    "build_compaction_preview",
    "build_read_capacity_summary",
    "build_storage_engine_summary",
    "build_write_capacity_summary",
    "calculate_utilization",
    "deterministic_storage_json",
    "empty_storage_engine_summary",
    "normalize_pressure_state",
    "normalize_storage_state",
    "pressure_state_from_utilization",
    "sanitize_summary_dict",
    "storage_state_from_pressure",
    "summarize_telemetry_bus_inputs",
]
