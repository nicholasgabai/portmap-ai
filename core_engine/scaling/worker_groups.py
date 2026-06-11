from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    normalize_source_mode,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)
from core_engine.scaling.retention_tiers import bounded_int


WORKER_GROUP_RECORD_VERSION = 1
WORKER_GROUP_TYPES = {"collector", "analysis", "visualization", "intelligence", "relay_preview", "unknown"}
WORKER_GROUP_HEALTH_STATES = {"healthy", "degraded", "unavailable", "unknown"}
WORKER_GROUP_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "runtime_worker_count_modified": False,
    "telemetry_routing_modified": False,
    "infrastructure_provisioned": False,
    "cloud_dependency_required": False,
    "cluster_created": False,
}


@dataclass(frozen=True)
class WorkerGroupRecord:
    group_id: str
    group_name: str
    group_type: str
    worker_count: int
    max_worker_count: int
    source_modes: list[str] = field(default_factory=list)
    health_state: str = "unknown"
    capacity_weight: float = 1.0
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        modes = normalize_source_modes(self.source_modes)
        max_workers = bounded_worker_count(self.max_worker_count)
        workers = min(bounded_worker_count(self.worker_count), max_workers) if max_workers else 0
        return {
            "record_type": "worker_group",
            "record_version": WORKER_GROUP_RECORD_VERSION,
            "group_id": sanitize_reference(self.group_id),
            "group_name": sanitize_text(self.group_name) or "Unnamed worker group",
            "group_type": normalize_group_type(self.group_type),
            "worker_count": workers,
            "max_worker_count": max_workers,
            "source_modes": modes,
            "health_state": normalize_health_state(self.health_state),
            "capacity_weight": round(bounded_capacity_weight(self.capacity_weight), 4),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **WORKER_GROUP_SAFETY_FLAGS,
        }


def build_worker_group(
    *,
    group_id: Any = "",
    group_name: Any = "",
    group_type: Any = "unknown",
    worker_count: Any = 0,
    max_worker_count: Any = 0,
    source_modes: Iterable[Any] | None = None,
    health_state: Any = "unknown",
    capacity_weight: Any = 1.0,
    advisory_notes: list[Any] | None = None,
) -> WorkerGroupRecord:
    normalized_type = normalize_group_type(group_type)
    modes = normalize_source_modes(source_modes or ["unknown"])
    max_workers = bounded_worker_count(max_worker_count)
    workers = bounded_worker_count(worker_count)
    if max_workers and workers > max_workers:
        workers = max_workers
    notes = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    if max_workers == 0:
        notes.append("worker group has no positive max worker capacity")
    if normalized_type == "relay_preview":
        notes.append("relay worker group is readiness metadata only; no relay is started")
    notes.append("worker group is preview-only; runtime worker counts are unchanged")
    safe_name = sanitize_text(group_name) or f"{normalized_type} worker group"
    safe_id = sanitize_reference(group_id)
    if not safe_id:
        safe_id = "worker-group-" + digest(
            {
                "group_name": safe_name,
                "group_type": normalized_type,
                "worker_count": workers,
                "max_worker_count": max_workers,
                "source_modes": modes,
                "health_state": normalize_health_state(health_state),
                "capacity_weight": bounded_capacity_weight(capacity_weight),
            }
        )[:16]
    return WorkerGroupRecord(
        group_id=safe_id,
        group_name=safe_name,
        group_type=normalized_type,
        worker_count=workers,
        max_worker_count=max_workers,
        source_modes=modes,
        health_state=normalize_health_state(health_state),
        capacity_weight=bounded_capacity_weight(capacity_weight),
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_worker_group(value: Any) -> WorkerGroupRecord:
    if isinstance(value, WorkerGroupRecord):
        return value
    if not isinstance(value, dict):
        return build_worker_group(
            group_name="Invalid worker group",
            group_type="unknown",
            worker_count=0,
            max_worker_count=0,
            source_modes=["unknown"],
            health_state="unknown",
            advisory_notes=["invalid worker group generated from malformed input"],
        )
    try:
        return build_worker_group(
            group_id=value.get("group_id", ""),
            group_name=value.get("group_name", value.get("name", "")),
            group_type=value.get("group_type", value.get("type", "unknown")),
            worker_count=value.get("worker_count", 0),
            max_worker_count=value.get("max_worker_count", 0),
            source_modes=value.get("source_modes") if isinstance(value.get("source_modes"), list) else [value.get("source_mode", "unknown")],
            health_state=value.get("health_state", value.get("state", "unknown")),
            capacity_weight=value.get("capacity_weight", 1.0),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_worker_group(
            group_name="Invalid worker group",
            group_type="unknown",
            health_state="unknown",
            advisory_notes=[str(exc)],
        )


def default_worker_groups(*, source_mode: Any = "unknown") -> list[WorkerGroupRecord]:
    mode = normalize_source_mode(source_mode)
    return [
        build_worker_group(
            group_name="Collector workers",
            group_type="collector",
            worker_count=1,
            max_worker_count=4,
            source_modes=[mode],
            health_state="healthy",
            capacity_weight=1.0,
        ),
        build_worker_group(
            group_name="Analysis workers",
            group_type="analysis",
            worker_count=1,
            max_worker_count=4,
            source_modes=[mode],
            health_state="healthy",
            capacity_weight=1.25,
        ),
        build_worker_group(
            group_name="Visualization workers",
            group_type="visualization",
            worker_count=1,
            max_worker_count=3,
            source_modes=[mode],
            health_state="healthy",
            capacity_weight=0.75,
        ),
        build_worker_group(
            group_name="Intelligence workers",
            group_type="intelligence",
            worker_count=1,
            max_worker_count=3,
            source_modes=[mode],
            health_state="healthy",
            capacity_weight=1.5,
        ),
    ]


def worker_group_distribution(groups: Iterable[WorkerGroupRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_worker_group(group).to_dict() for group in list(groups or [])]
    type_counts: dict[str, int] = {}
    health_counts: dict[str, int] = {}
    source_modes: set[str] = set()
    for row in rows:
        type_counts[row["group_type"]] = type_counts.get(row["group_type"], 0) + row["worker_count"]
        health_counts[row["health_state"]] = health_counts.get(row["health_state"], 0) + 1
        source_modes.update(row.get("source_modes", []))
    return {
        "group_count": len(rows),
        "worker_count": sum(row["worker_count"] for row in rows),
        "max_worker_count": sum(row["max_worker_count"] for row in rows),
        "type_worker_counts": dict(sorted(type_counts.items())),
        "health_state_counts": dict(sorted(health_counts.items())),
        "source_modes": sorted(source_modes) or ["unknown"],
        "capacity_weight_total": round(sum(float(row["capacity_weight"]) * row["worker_count"] for row in rows), 4),
        "preview_only": True,
        "destructive_action": False,
    }


def normalize_group_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in WORKER_GROUP_TYPES else "unknown"


def normalize_health_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in WORKER_GROUP_HEALTH_STATES else "unknown"


def normalize_source_modes(values: Iterable[Any]) -> list[str]:
    modes = {normalize_source_mode(value) for value in values}
    modes = {mode for mode in modes if mode}
    return sorted(modes) or ["unknown"]


def bounded_worker_count(value: Any) -> int:
    return min(10_000, bounded_int(value))


def bounded_capacity_weight(value: Any) -> float:
    try:
        return max(0.0, min(100.0, float(value)))
    except Exception:
        return 0.0


def deterministic_worker_group_json(record: WorkerGroupRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, WorkerGroupRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "WORKER_GROUP_HEALTH_STATES",
    "WORKER_GROUP_TYPES",
    "WorkerGroupRecord",
    "bounded_capacity_weight",
    "bounded_worker_count",
    "build_worker_group",
    "default_worker_groups",
    "deterministic_worker_group_json",
    "normalize_group_type",
    "normalize_health_state",
    "normalize_source_modes",
    "normalize_worker_group",
    "worker_group_distribution",
]
