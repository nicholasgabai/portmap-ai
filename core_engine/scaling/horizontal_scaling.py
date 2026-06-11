from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
)
from core_engine.scaling.retention_tiers import bounded_int
from core_engine.scaling.storage_engine import sanitize_summary_dict, summarize_telemetry_bus_inputs
from core_engine.scaling.worker_groups import (
    WorkerGroupRecord,
    default_worker_groups,
    normalize_worker_group,
    worker_group_distribution,
)


HORIZONTAL_SCALING_RECORD_VERSION = 1
SCALING_STATES = {"ready", "growth_ready", "capacity_pressure", "degraded", "unavailable", "unknown"}
HORIZONTAL_SCALING_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "infrastructure_provisioned": False,
    "cluster_created": False,
    "cloud_api_called": False,
    "runtime_worker_count_modified": False,
    "telemetry_routing_modified": False,
    "orchestration_executed": False,
}


@dataclass(frozen=True)
class HorizontalScalingSummary:
    scaling_id: str
    generated_at: str
    scaling_state: str
    cluster_size: int
    recommended_cluster_size: int
    worker_groups: list[dict[str, Any]] = field(default_factory=list)
    shard_count: int = 0
    partition_count: int = 0
    capacity_summary: dict[str, Any] = field(default_factory=dict)
    storage_summary: dict[str, Any] = field(default_factory=dict)
    telemetry_bus_summary: dict[str, Any] = field(default_factory=dict)
    utilization_ratio: float = 0.0
    scaling_recommendations: list[str] = field(default_factory=list)
    fanout_readiness: dict[str, Any] = field(default_factory=dict)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "horizontal_scaling_summary",
            "record_version": HORIZONTAL_SCALING_RECORD_VERSION,
            "scaling_id": sanitize_reference(self.scaling_id),
            "generated_at": str(self.generated_at or ""),
            "scaling_state": normalize_scaling_state(self.scaling_state),
            "cluster_size": bounded_int(self.cluster_size),
            "recommended_cluster_size": bounded_int(self.recommended_cluster_size),
            "worker_groups": list(self.worker_groups),
            "shard_count": bounded_int(self.shard_count),
            "partition_count": bounded_int(self.partition_count),
            "capacity_summary": sanitize_summary_dict(self.capacity_summary),
            "storage_summary": sanitize_summary_dict(self.storage_summary),
            "telemetry_bus_summary": sanitize_summary_dict(self.telemetry_bus_summary),
            "utilization_ratio": round(non_negative_float(self.utilization_ratio), 4),
            "scaling_recommendations": [sanitize_text(item) for item in self.scaling_recommendations],
            "fanout_readiness": sanitize_summary_dict(self.fanout_readiness),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **HORIZONTAL_SCALING_SAFETY_FLAGS,
        }


def build_horizontal_scaling_summary(
    worker_groups: Iterable[WorkerGroupRecord | dict[str, Any] | Any] | None = None,
    *,
    telemetry_bus_summaries: Iterable[dict[str, Any] | Any] | None = None,
    storage_summaries: Iterable[dict[str, Any] | Any] | None = None,
    generated_at: str | None = None,
    scaling_id: str | None = None,
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> HorizontalScalingSummary:
    timestamp = generated_at or now_timestamp()
    groups = list(default_worker_groups(source_mode=source_mode) if worker_groups is None else worker_groups)
    group_rows = [normalize_worker_group(group).to_dict() for group in groups]
    distribution = worker_group_distribution(group_rows)
    bus_summary = summarize_telemetry_bus_inputs(telemetry_bus_summaries)
    storage_summary = summarize_storage_inputs(storage_summaries)
    utilization = max(
        _ratio(bus_summary.get("queue_depth", 0), bus_summary.get("max_queue_depth", 0)),
        non_negative_float(storage_summary.get("max_utilization_ratio", 0.0)),
    )
    cluster_size = distribution["worker_count"]
    recommended_size = recommended_cluster_size(
        cluster_size=cluster_size,
        max_cluster_size=distribution["max_worker_count"],
        utilization_ratio=utilization,
        degraded_group_count=distribution["health_state_counts"].get("degraded", 0) + distribution["health_state_counts"].get("unknown", 0),
        unavailable_group_count=distribution["health_state_counts"].get("unavailable", 0),
    )
    shard_count = plan_shard_count(cluster_size=cluster_size, utilization_ratio=utilization, storage_summary=storage_summary)
    partition_count = plan_partition_count(shard_count=shard_count, bus_summary=bus_summary, storage_summary=storage_summary)
    capacity_summary = build_capacity_summary(
        distribution=distribution,
        cluster_size=cluster_size,
        recommended_cluster_size=recommended_size,
        shard_count=shard_count,
        partition_count=partition_count,
        bus_summary=bus_summary,
        storage_summary=storage_summary,
        utilization_ratio=utilization,
    )
    fanout = build_fanout_readiness(group_rows, bus_summary=bus_summary)
    state = scaling_state_from_inputs(
        cluster_size=cluster_size,
        recommended_cluster_size=recommended_size,
        utilization_ratio=utilization,
        distribution=distribution,
        storage_summary=storage_summary,
        bus_summary=bus_summary,
    )
    recommendations = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    recommendations.extend(recommendations_for_scaling_state(state, recommended_size, cluster_size, fanout))
    summary_id = scaling_id or "horizontal-scaling-" + digest(
        {
            "generated_at": timestamp,
            "group_ids": [row.get("group_id") for row in group_rows],
            "cluster_size": cluster_size,
            "recommended_cluster_size": recommended_size,
            "shard_count": shard_count,
            "partition_count": partition_count,
            "bus_summary": bus_summary,
            "storage_summary": storage_summary,
        }
    )[:16]
    return HorizontalScalingSummary(
        scaling_id=summary_id,
        generated_at=timestamp,
        scaling_state=state,
        cluster_size=cluster_size,
        recommended_cluster_size=recommended_size,
        worker_groups=group_rows,
        shard_count=shard_count,
        partition_count=partition_count,
        capacity_summary=capacity_summary,
        storage_summary=storage_summary,
        telemetry_bus_summary=bus_summary,
        utilization_ratio=utilization,
        scaling_recommendations=recommendations,
        fanout_readiness=fanout,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_horizontal_scaling_summary(*, generated_at: str | None = None) -> HorizontalScalingSummary:
    return build_horizontal_scaling_summary([], generated_at=generated_at)


def summarize_storage_inputs(summaries: Iterable[dict[str, Any] | Any] | None) -> dict[str, Any]:
    rows = [item.to_dict() if hasattr(item, "to_dict") else item for item in list(summaries or [])]
    valid_rows = [row for row in rows if isinstance(row, dict)]
    malformed_count = len(rows) - len(valid_rows)
    state_counts: dict[str, int] = {}
    tier_count = 0
    max_utilization = 0.0
    total_record_capacity = 0
    estimated_current_records = 0
    for row in valid_rows:
        state = sanitize_reference(row.get("storage_state", "unknown")) or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
        tier_count += len(row.get("retention_tiers") or [])
        max_utilization = max(max_utilization, non_negative_float(row.get("utilization_ratio", 0.0)))
        total_record_capacity += bounded_int(row.get("total_record_capacity", 0))
        estimated_current_records += bounded_int(row.get("estimated_current_records", 0))
    return {
        "summary_count": len(valid_rows),
        "malformed_count": malformed_count,
        "state_counts": dict(sorted(state_counts.items())),
        "tier_count": tier_count,
        "max_utilization_ratio": round(max_utilization, 4),
        "total_record_capacity": total_record_capacity,
        "estimated_current_records": estimated_current_records,
        "preview_only": True,
        "destructive_action": False,
    }


def recommended_cluster_size(
    *,
    cluster_size: Any,
    max_cluster_size: Any,
    utilization_ratio: Any,
    degraded_group_count: Any = 0,
    unavailable_group_count: Any = 0,
) -> int:
    current = bounded_int(cluster_size)
    maximum = bounded_int(max_cluster_size)
    if current <= 0:
        return 1 if maximum else 0
    added = 0
    ratio = non_negative_float(utilization_ratio)
    if ratio >= 1.0:
        added = max(2, math.ceil(current * 0.5))
    elif ratio >= 0.85:
        added = max(1, math.ceil(current * 0.25))
    elif ratio >= 0.65:
        added = 1
    added += bounded_int(degraded_group_count)
    added += bounded_int(unavailable_group_count)
    recommended = current + added
    return min(maximum, recommended) if maximum else recommended


def plan_shard_count(*, cluster_size: Any, utilization_ratio: Any, storage_summary: dict[str, Any]) -> int:
    current = max(1, bounded_int(cluster_size))
    storage_factor = 1 if bounded_int(storage_summary.get("tier_count", 0)) else 0
    pressure_factor = 2 if non_negative_float(utilization_ratio) >= 0.85 else 1
    return max(1, math.ceil(current / 2) * pressure_factor + storage_factor)


def plan_partition_count(*, shard_count: Any, bus_summary: dict[str, Any], storage_summary: dict[str, Any]) -> int:
    topic_count = len(bus_summary.get("topic_counts") or {})
    tier_count = bounded_int(storage_summary.get("tier_count", 0))
    return max(1, bounded_int(shard_count) * max(1, topic_count) + tier_count)


def build_capacity_summary(
    *,
    distribution: dict[str, Any],
    cluster_size: int,
    recommended_cluster_size: int,
    shard_count: int,
    partition_count: int,
    bus_summary: dict[str, Any],
    storage_summary: dict[str, Any],
    utilization_ratio: float,
) -> dict[str, Any]:
    return {
        "worker_distribution": distribution,
        "current_cluster_size": cluster_size,
        "recommended_cluster_size": recommended_cluster_size,
        "available_worker_slots": max(0, bounded_int(distribution.get("max_worker_count", 0)) - cluster_size),
        "shard_count_preview": bounded_int(shard_count),
        "partition_count_preview": bounded_int(partition_count),
        "bus_queue_depth": bounded_int(bus_summary.get("queue_depth", 0)),
        "bus_dropped_count": bounded_int(bus_summary.get("dropped_count", 0)),
        "storage_max_utilization_ratio": round(non_negative_float(storage_summary.get("max_utilization_ratio", 0.0)), 4),
        "utilization_ratio": round(non_negative_float(utilization_ratio), 4),
        "preview_only": True,
        "infrastructure_provisioned": False,
    }


def build_fanout_readiness(group_rows: list[dict[str, Any]], *, bus_summary: dict[str, Any]) -> dict[str, Any]:
    active_groups = [row for row in group_rows if row.get("health_state") in {"healthy", "degraded"} and row.get("worker_count", 0) > 0]
    collector_count = sum(row.get("worker_count", 0) for row in active_groups if row.get("group_type") == "collector")
    analysis_count = sum(row.get("worker_count", 0) for row in active_groups if row.get("group_type") == "analysis")
    topic_count = len(bus_summary.get("topic_counts") or {})
    ready = bool(active_groups) and collector_count > 0 and analysis_count > 0
    return {
        "fanout_ready": ready,
        "active_group_count": len(active_groups),
        "collector_worker_count": collector_count,
        "analysis_worker_count": analysis_count,
        "topic_count": topic_count,
        "fanout_preview_only": True,
        "telemetry_routing_modified": False,
    }


def scaling_state_from_inputs(
    *,
    cluster_size: int,
    recommended_cluster_size: int,
    utilization_ratio: float,
    distribution: dict[str, Any],
    storage_summary: dict[str, Any],
    bus_summary: dict[str, Any],
) -> str:
    health_counts = distribution.get("health_state_counts", {})
    if health_counts.get("unavailable", 0) or health_counts.get("unknown", 0):
        return "degraded"
    if storage_summary.get("malformed_count", 0) or bus_summary.get("malformed_count", 0):
        return "degraded"
    if cluster_size <= 0:
        return "unavailable"
    if storage_summary.get("state_counts", {}).get("unavailable", 0):
        return "degraded"
    if non_negative_float(utilization_ratio) >= 0.85:
        return "capacity_pressure"
    if recommended_cluster_size > cluster_size:
        return "growth_ready"
    return "ready"


def recommendations_for_scaling_state(state: str, recommended_size: int, cluster_size: int, fanout: dict[str, Any]) -> list[str]:
    if state == "unavailable":
        return ["define at least one bounded worker group before scaling readiness"]
    if state == "degraded":
        return ["review degraded worker, storage, or telemetry bus inputs before scaling"]
    if state == "capacity_pressure":
        return [f"preview cluster growth from {cluster_size} to {recommended_size} workers before intake expansion"]
    if state == "growth_ready":
        return [f"capacity preview recommends {recommended_size} workers; no provisioning has been performed"]
    if not fanout.get("fanout_ready"):
        return ["review collector and analysis worker distribution before fanout"]
    return ["horizontal scaling readiness is advisory and metadata-only"]


def normalize_scaling_state(value: Any) -> str:
    safe_value = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return safe_value if safe_value in SCALING_STATES else "unknown"


def non_negative_float(value: Any) -> float:
    try:
        return max(0.0, float(value))
    except Exception:
        return 0.0


def _ratio(numerator: Any, denominator: Any) -> float:
    safe_denominator = bounded_int(denominator)
    if safe_denominator <= 0:
        return 0.0
    return round(bounded_int(numerator) / safe_denominator, 6)


def deterministic_scaling_json(summary: HorizontalScalingSummary | dict[str, Any]) -> str:
    payload = summary.to_dict() if isinstance(summary, HorizontalScalingSummary) else summary
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "SCALING_STATES",
    "HorizontalScalingSummary",
    "build_capacity_summary",
    "build_fanout_readiness",
    "build_horizontal_scaling_summary",
    "deterministic_scaling_json",
    "empty_horizontal_scaling_summary",
    "normalize_scaling_state",
    "plan_partition_count",
    "plan_shard_count",
    "recommended_cluster_size",
    "scaling_state_from_inputs",
    "summarize_storage_inputs",
]
