from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
)
from core_engine.scaling.horizontal_scaling import summarize_storage_inputs
from core_engine.scaling.resource_budgets import (
    ResourceBudgetRecord,
    default_resource_budgets,
    normalize_resource_budget,
    resource_budget_totals,
)
from core_engine.scaling.retention_tiers import bounded_int
from core_engine.scaling.storage_engine import sanitize_summary_dict, summarize_telemetry_bus_inputs


RESOURCE_OPTIMIZATION_RECORD_VERSION = 1
OPTIMIZATION_STATES = {"optimized", "growth_ready", "constrained", "degraded", "unavailable", "unknown"}
RESOURCE_OPTIMIZATION_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "telemetry_throttled": False,
    "sampling_changed": False,
    "runtime_behavior_modified": False,
    "worker_count_modified": False,
    "collection_logic_changed": False,
    "infrastructure_changed": False,
    "cloud_resource_created": False,
}


@dataclass(frozen=True)
class ResourceOptimizationSummary:
    optimization_id: str
    generated_at: str
    optimization_state: str
    resource_budgets: list[dict[str, Any]] = field(default_factory=list)
    cpu_utilization_ratio: float = 0.0
    memory_utilization_ratio: float = 0.0
    storage_utilization_ratio: float = 0.0
    telemetry_utilization_ratio: float = 0.0
    worker_utilization_ratio: float = 0.0
    adaptive_sampling_preview: dict[str, Any] = field(default_factory=dict)
    load_shedding_preview: dict[str, Any] = field(default_factory=dict)
    scaling_summary: dict[str, Any] = field(default_factory=dict)
    storage_summary: dict[str, Any] = field(default_factory=dict)
    telemetry_bus_summary: dict[str, Any] = field(default_factory=dict)
    optimization_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "resource_optimization_summary",
            "record_version": RESOURCE_OPTIMIZATION_RECORD_VERSION,
            "optimization_id": sanitize_reference(self.optimization_id),
            "generated_at": str(self.generated_at or ""),
            "optimization_state": normalize_optimization_state(self.optimization_state),
            "resource_budgets": list(self.resource_budgets),
            "cpu_utilization_ratio": round(non_negative_float(self.cpu_utilization_ratio), 4),
            "memory_utilization_ratio": round(non_negative_float(self.memory_utilization_ratio), 4),
            "storage_utilization_ratio": round(non_negative_float(self.storage_utilization_ratio), 4),
            "telemetry_utilization_ratio": round(non_negative_float(self.telemetry_utilization_ratio), 4),
            "worker_utilization_ratio": round(non_negative_float(self.worker_utilization_ratio), 4),
            "adaptive_sampling_preview": sanitize_summary_dict(self.adaptive_sampling_preview),
            "load_shedding_preview": sanitize_summary_dict(self.load_shedding_preview),
            "scaling_summary": sanitize_summary_dict(self.scaling_summary),
            "storage_summary": sanitize_summary_dict(self.storage_summary),
            "telemetry_bus_summary": sanitize_summary_dict(self.telemetry_bus_summary),
            "optimization_recommendations": [sanitize_text(item) for item in self.optimization_recommendations],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **RESOURCE_OPTIMIZATION_SAFETY_FLAGS,
        }


def build_resource_optimization_summary(
    resource_budgets: Iterable[ResourceBudgetRecord | dict[str, Any] | Any] | None = None,
    *,
    telemetry_bus_summaries: Iterable[dict[str, Any] | Any] | None = None,
    storage_summaries: Iterable[dict[str, Any] | Any] | None = None,
    scaling_summaries: Iterable[dict[str, Any] | Any] | None = None,
    cpu_used_percent: Any = 0.0,
    memory_used_mb: Any = 0,
    storage_used_mb: Any = None,
    telemetry_events_per_minute: Any = None,
    worker_count: Any = None,
    generated_at: str | None = None,
    optimization_id: str | None = None,
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> ResourceOptimizationSummary:
    timestamp = generated_at or now_timestamp()
    budgets = list(default_resource_budgets(source_mode=source_mode) if resource_budgets is None else resource_budgets)
    budget_rows = [normalize_resource_budget(budget).to_dict() for budget in budgets]
    budget_totals = resource_budget_totals(budget_rows)
    bus_summary = summarize_telemetry_bus_inputs(telemetry_bus_summaries)
    storage_summary = summarize_storage_inputs(storage_summaries)
    scaling_summary = summarize_scaling_inputs(scaling_summaries)
    storage_used = bounded_int(storage_used_mb)
    if storage_used_mb is None:
        storage_used = bytes_to_mb(storage_summary.get("estimated_current_records", 0) * 1024)
    telemetry_used = bounded_int(telemetry_events_per_minute)
    if telemetry_events_per_minute is None:
        telemetry_used = bounded_int(bus_summary.get("queue_depth", 0))
    workers_used = bounded_int(worker_count)
    if worker_count is None:
        workers_used = bounded_int(scaling_summary.get("cluster_size", 0))
    cpu_ratio = utilization_ratio(cpu_used_percent, budget_totals.get("cpu_budget_percent", 0))
    memory_ratio = utilization_ratio(memory_used_mb, budget_totals.get("memory_budget_mb", 0))
    storage_ratio = max(
        utilization_ratio(storage_used, budget_totals.get("storage_budget_mb", 0)),
        non_negative_float(storage_summary.get("max_utilization_ratio", 0.0)),
    )
    telemetry_ratio = max(
        utilization_ratio(telemetry_used, budget_totals.get("telemetry_budget_per_minute", 0)),
        _ratio(bus_summary.get("queue_depth", 0), bus_summary.get("max_queue_depth", 0)),
    )
    worker_ratio = max(
        utilization_ratio(workers_used, budget_totals.get("worker_budget_count", 0)),
        non_negative_float(scaling_summary.get("max_utilization_ratio", 0.0)),
    )
    ratios = {
        "cpu": cpu_ratio,
        "memory": memory_ratio,
        "storage": storage_ratio,
        "telemetry": telemetry_ratio,
        "worker": worker_ratio,
    }
    adaptive_preview = build_adaptive_sampling_preview(ratios=ratios, telemetry_bus_summary=bus_summary)
    shedding_preview = build_load_shedding_preview(ratios=ratios, scaling_summary=scaling_summary, storage_summary=storage_summary)
    state = optimization_state_from_inputs(
        ratios=ratios,
        budget_count=budget_totals["budget_count"],
        bus_summary=bus_summary,
        storage_summary=storage_summary,
        scaling_summary=scaling_summary,
    )
    recommendations = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    recommendations.extend(recommendations_for_optimization_state(state, ratios, adaptive_preview, shedding_preview))
    summary_id = optimization_id or "resource-optimization-" + digest(
        {
            "generated_at": timestamp,
            "budget_ids": [row.get("budget_id") for row in budget_rows],
            "ratios": ratios,
            "bus_summary": bus_summary,
            "storage_summary": storage_summary,
            "scaling_summary": scaling_summary,
        }
    )[:16]
    return ResourceOptimizationSummary(
        optimization_id=summary_id,
        generated_at=timestamp,
        optimization_state=state,
        resource_budgets=budget_rows,
        cpu_utilization_ratio=cpu_ratio,
        memory_utilization_ratio=memory_ratio,
        storage_utilization_ratio=storage_ratio,
        telemetry_utilization_ratio=telemetry_ratio,
        worker_utilization_ratio=worker_ratio,
        adaptive_sampling_preview=adaptive_preview,
        load_shedding_preview=shedding_preview,
        scaling_summary=scaling_summary,
        storage_summary=storage_summary,
        telemetry_bus_summary=bus_summary,
        optimization_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_resource_optimization_summary(*, generated_at: str | None = None) -> ResourceOptimizationSummary:
    return build_resource_optimization_summary([], generated_at=generated_at)


def summarize_scaling_inputs(summaries: Iterable[dict[str, Any] | Any] | None) -> dict[str, Any]:
    rows = [item.to_dict() if hasattr(item, "to_dict") else item for item in list(summaries or [])]
    valid_rows = [row for row in rows if isinstance(row, dict)]
    malformed_count = len(rows) - len(valid_rows)
    state_counts: dict[str, int] = {}
    cluster_size = 0
    recommended_cluster_size = 0
    max_utilization = 0.0
    for row in valid_rows:
        state = sanitize_reference(row.get("scaling_state", "unknown")) or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
        cluster_size += bounded_int(row.get("cluster_size", 0))
        recommended_cluster_size += bounded_int(row.get("recommended_cluster_size", 0))
        max_utilization = max(max_utilization, non_negative_float(row.get("utilization_ratio", 0.0)))
    return {
        "summary_count": len(valid_rows),
        "malformed_count": malformed_count,
        "state_counts": dict(sorted(state_counts.items())),
        "cluster_size": cluster_size,
        "recommended_cluster_size": recommended_cluster_size,
        "max_cluster_size": max(cluster_size, recommended_cluster_size),
        "max_utilization_ratio": round(max_utilization, 4),
        "preview_only": True,
        "destructive_action": False,
    }


def build_adaptive_sampling_preview(*, ratios: dict[str, float], telemetry_bus_summary: dict[str, Any]) -> dict[str, Any]:
    highest_ratio = max((non_negative_float(value) for value in ratios.values()), default=0.0)
    recommended = highest_ratio >= 0.75 or bounded_int(telemetry_bus_summary.get("dropped_count", 0)) > 0
    return {
        "recommended": recommended,
        "reason": "resource pressure preview" if recommended else "within budget preview",
        "highest_utilization_ratio": round(highest_ratio, 4),
        "telemetry_queue_depth": bounded_int(telemetry_bus_summary.get("queue_depth", 0)),
        "dropped_by_bound_count": bounded_int(telemetry_bus_summary.get("dropped_count", 0)),
        "sampling_changed": False,
        "collection_logic_changed": False,
        "preview_only": True,
    }


def build_load_shedding_preview(
    *,
    ratios: dict[str, float],
    scaling_summary: dict[str, Any],
    storage_summary: dict[str, Any],
) -> dict[str, Any]:
    highest_ratio = max((non_negative_float(value) for value in ratios.values()), default=0.0)
    recommended = highest_ratio >= 0.9 or bool(storage_summary.get("state_counts", {}).get("over_capacity", 0))
    return {
        "recommended": recommended,
        "reason": "capacity pressure preview" if recommended else "load shedding not recommended",
        "highest_utilization_ratio": round(highest_ratio, 4),
        "scaling_state_counts": scaling_summary.get("state_counts", {}),
        "storage_state_counts": storage_summary.get("state_counts", {}),
        "telemetry_throttled": False,
        "runtime_behavior_modified": False,
        "preview_only": True,
    }


def optimization_state_from_inputs(
    *,
    ratios: dict[str, float],
    budget_count: int,
    bus_summary: dict[str, Any],
    storage_summary: dict[str, Any],
    scaling_summary: dict[str, Any],
) -> str:
    if budget_count <= 0:
        return "unavailable"
    if bus_summary.get("malformed_count", 0) or storage_summary.get("malformed_count", 0) or scaling_summary.get("malformed_count", 0):
        return "degraded"
    if storage_summary.get("state_counts", {}).get("unavailable", 0):
        return "degraded"
    if scaling_summary.get("state_counts", {}).get("degraded", 0):
        return "degraded"
    highest_ratio = max((non_negative_float(value) for value in ratios.values()), default=0.0)
    if highest_ratio >= 0.9:
        return "constrained"
    if highest_ratio >= 0.65:
        return "growth_ready"
    return "optimized"


def recommendations_for_optimization_state(
    state: str,
    ratios: dict[str, float],
    adaptive_preview: dict[str, Any],
    shedding_preview: dict[str, Any],
) -> list[str]:
    if state == "unavailable":
        return ["define at least one resource budget before optimization readiness"]
    if state == "degraded":
        return ["review malformed or degraded telemetry, storage, or scaling inputs before optimization"]
    if state == "constrained":
        return ["review capacity limits and load-shedding preview; no runtime throttling has been applied"]
    if adaptive_preview.get("recommended"):
        return ["review adaptive sampling preview; no sampling change has been applied"]
    if shedding_preview.get("recommended"):
        return ["review load-shedding preview; no telemetry throttling has been applied"]
    if max((non_negative_float(value) for value in ratios.values()), default=0.0) >= 0.65:
        return ["resource budget has growth headroom but should be reviewed before larger deployment"]
    return ["resource optimization readiness is advisory and metadata-only"]


def utilization_ratio(used: Any, budget: Any) -> float:
    safe_budget = non_negative_float(budget)
    if safe_budget <= 0:
        return 0.0
    return round(non_negative_float(used) / safe_budget, 6)


def bytes_to_mb(value: Any) -> int:
    return bounded_int(non_negative_float(value) / 1_000_000)


def normalize_optimization_state(value: Any) -> str:
    safe_value = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return safe_value if safe_value in OPTIMIZATION_STATES else "unknown"


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


def deterministic_resource_optimization_json(summary: ResourceOptimizationSummary | dict[str, Any]) -> str:
    payload = summary.to_dict() if isinstance(summary, ResourceOptimizationSummary) else summary
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "OPTIMIZATION_STATES",
    "ResourceOptimizationSummary",
    "build_adaptive_sampling_preview",
    "build_load_shedding_preview",
    "build_resource_optimization_summary",
    "bytes_to_mb",
    "deterministic_resource_optimization_json",
    "empty_resource_optimization_summary",
    "normalize_optimization_state",
    "optimization_state_from_inputs",
    "recommendations_for_optimization_state",
    "summarize_scaling_inputs",
    "utilization_ratio",
]
