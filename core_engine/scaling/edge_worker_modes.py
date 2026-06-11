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
from core_engine.scaling.edge_profiles import (
    EdgeProfileRecord,
    default_edge_profiles,
    edge_profile_summary,
    normalize_edge_profile,
)
from core_engine.scaling.horizontal_scaling import summarize_storage_inputs
from core_engine.scaling.resource_optimization import summarize_scaling_inputs
from core_engine.scaling.retention_tiers import bounded_int
from core_engine.scaling.storage_engine import sanitize_summary_dict, summarize_telemetry_bus_inputs


EDGE_WORKER_MODE_RECORD_VERSION = 1
EDGE_STATES = {"ready", "edge_ready", "degraded", "offline_capable", "unavailable", "unknown"}
EDGE_WORKER_MODE_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "worker_deployed": False,
    "runtime_behavior_modified": False,
    "telemetry_collection_changed": False,
    "worker_count_modified": False,
    "telemetry_routing_modified": False,
    "deployment_action_executed": False,
    "infrastructure_provisioned": False,
    "cloud_resource_created": False,
    "relay_created": False,
}


@dataclass(frozen=True)
class EdgeWorkerModeSummary:
    edge_mode_id: str
    generated_at: str
    edge_state: str
    edge_profiles: list[dict[str, Any]] = field(default_factory=list)
    offline_readiness: dict[str, Any] = field(default_factory=dict)
    degraded_readiness: dict[str, Any] = field(default_factory=dict)
    gateway_readiness: dict[str, Any] = field(default_factory=dict)
    branch_readiness: dict[str, Any] = field(default_factory=dict)
    telemetry_bus_summary: dict[str, Any] = field(default_factory=dict)
    storage_summary: dict[str, Any] = field(default_factory=dict)
    scaling_summary: dict[str, Any] = field(default_factory=dict)
    optimization_summary: dict[str, Any] = field(default_factory=dict)
    deployment_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "edge_worker_mode_summary",
            "record_version": EDGE_WORKER_MODE_RECORD_VERSION,
            "edge_mode_id": sanitize_reference(self.edge_mode_id),
            "generated_at": str(self.generated_at or ""),
            "edge_state": normalize_edge_state(self.edge_state),
            "edge_profiles": list(self.edge_profiles),
            "offline_readiness": sanitize_summary_dict(self.offline_readiness),
            "degraded_readiness": sanitize_summary_dict(self.degraded_readiness),
            "gateway_readiness": sanitize_summary_dict(self.gateway_readiness),
            "branch_readiness": sanitize_summary_dict(self.branch_readiness),
            "telemetry_bus_summary": sanitize_summary_dict(self.telemetry_bus_summary),
            "storage_summary": sanitize_summary_dict(self.storage_summary),
            "scaling_summary": sanitize_summary_dict(self.scaling_summary),
            "optimization_summary": sanitize_summary_dict(self.optimization_summary),
            "deployment_recommendations": [sanitize_text(item) for item in self.deployment_recommendations],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **EDGE_WORKER_MODE_SAFETY_FLAGS,
        }


def build_edge_worker_mode_summary(
    edge_profiles: Iterable[EdgeProfileRecord | dict[str, Any] | Any] | None = None,
    *,
    telemetry_bus_summaries: Iterable[dict[str, Any] | Any] | None = None,
    storage_summaries: Iterable[dict[str, Any] | Any] | None = None,
    scaling_summaries: Iterable[dict[str, Any] | Any] | None = None,
    optimization_summaries: Iterable[dict[str, Any] | Any] | None = None,
    generated_at: str | None = None,
    edge_mode_id: str | None = None,
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> EdgeWorkerModeSummary:
    timestamp = generated_at or now_timestamp()
    profiles = list(default_edge_profiles(source_mode=source_mode) if edge_profiles is None else edge_profiles)
    profile_rows = [normalize_edge_profile(profile).to_dict() for profile in profiles]
    profile_summary = edge_profile_summary(profile_rows)
    bus_summary = summarize_telemetry_bus_inputs(telemetry_bus_summaries)
    storage_summary = summarize_storage_inputs(storage_summaries)
    scaling_summary = summarize_scaling_inputs(scaling_summaries)
    optimization_summary = summarize_optimization_inputs(optimization_summaries)
    offline = build_offline_readiness(profile_rows, bus_summary=bus_summary, storage_summary=storage_summary)
    degraded = build_degraded_readiness(profile_rows, optimization_summary=optimization_summary, storage_summary=storage_summary)
    gateway = build_gateway_readiness(profile_rows, bus_summary=bus_summary, scaling_summary=scaling_summary)
    branch = build_branch_readiness(profile_rows, optimization_summary=optimization_summary, scaling_summary=scaling_summary)
    state = edge_state_from_inputs(
        profile_summary=profile_summary,
        bus_summary=bus_summary,
        storage_summary=storage_summary,
        scaling_summary=scaling_summary,
        optimization_summary=optimization_summary,
        offline_readiness=offline,
        gateway_readiness=gateway,
        branch_readiness=branch,
    )
    recommendations = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    recommendations.extend(recommendations_for_edge_state(state, offline, degraded, gateway, branch))
    summary_id = edge_mode_id or "edge-mode-" + digest(
        {
            "generated_at": timestamp,
            "profile_ids": [row.get("profile_id") for row in profile_rows],
            "profile_summary": profile_summary,
            "bus_summary": bus_summary,
            "storage_summary": storage_summary,
            "scaling_summary": scaling_summary,
            "optimization_summary": optimization_summary,
        }
    )[:16]
    return EdgeWorkerModeSummary(
        edge_mode_id=summary_id,
        generated_at=timestamp,
        edge_state=state,
        edge_profiles=profile_rows,
        offline_readiness=offline,
        degraded_readiness=degraded,
        gateway_readiness=gateway,
        branch_readiness=branch,
        telemetry_bus_summary=bus_summary,
        storage_summary=storage_summary,
        scaling_summary=scaling_summary,
        optimization_summary=optimization_summary,
        deployment_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_edge_worker_mode_summary(*, generated_at: str | None = None) -> EdgeWorkerModeSummary:
    return build_edge_worker_mode_summary([], generated_at=generated_at)


def summarize_optimization_inputs(summaries: Iterable[dict[str, Any] | Any] | None) -> dict[str, Any]:
    rows = [item.to_dict() if hasattr(item, "to_dict") else item for item in list(summaries or [])]
    valid_rows = [row for row in rows if isinstance(row, dict)]
    malformed_count = len(rows) - len(valid_rows)
    state_counts: dict[str, int] = {}
    max_utilization = 0.0
    for row in valid_rows:
        state = sanitize_reference(row.get("optimization_state", "unknown")) or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
        max_utilization = max(
            max_utilization,
            _max_ratio(
                row.get("cpu_utilization_ratio", 0.0),
                row.get("memory_utilization_ratio", 0.0),
                row.get("storage_utilization_ratio", 0.0),
                row.get("telemetry_utilization_ratio", 0.0),
                row.get("worker_utilization_ratio", 0.0),
            ),
        )
    return {
        "summary_count": len(valid_rows),
        "malformed_count": malformed_count,
        "state_counts": dict(sorted(state_counts.items())),
        "max_utilization_ratio": round(max_utilization, 4),
        "preview_only": True,
        "destructive_action": False,
    }


def build_offline_readiness(profile_rows: list[dict[str, Any]], *, bus_summary: dict[str, Any], storage_summary: dict[str, Any]) -> dict[str, Any]:
    offline_profiles = [row for row in profile_rows if row.get("offline_supported")]
    ready = bool(offline_profiles)
    return {
        "offline_ready": ready,
        "offline_supported_profile_count": len(offline_profiles),
        "queue_depth": bounded_int(bus_summary.get("queue_depth", 0)),
        "storage_tier_count": bounded_int(storage_summary.get("tier_count", 0)),
        "offline_preview_only": True,
        "runtime_behavior_modified": False,
    }


def build_degraded_readiness(
    profile_rows: list[dict[str, Any]],
    *,
    optimization_summary: dict[str, Any],
    storage_summary: dict[str, Any],
) -> dict[str, Any]:
    degraded_profiles = [row for row in profile_rows if row.get("degraded_supported")]
    pressure = (
        optimization_summary.get("state_counts", {}).get("constrained", 0)
        or storage_summary.get("state_counts", {}).get("pressure", 0)
        or storage_summary.get("state_counts", {}).get("over_capacity", 0)
    )
    return {
        "degraded_ready": bool(degraded_profiles),
        "degraded_supported_profile_count": len(degraded_profiles),
        "pressure_detected": bool(pressure),
        "max_optimization_utilization_ratio": round(_safe_float(optimization_summary.get("max_utilization_ratio", 0.0)), 4),
        "degraded_preview_only": True,
        "collection_logic_changed": False,
    }


def build_gateway_readiness(profile_rows: list[dict[str, Any]], *, bus_summary: dict[str, Any], scaling_summary: dict[str, Any]) -> dict[str, Any]:
    gateway_profiles = [row for row in profile_rows if row.get("profile_type") == "gateway_collector"]
    return {
        "gateway_ready": bool(gateway_profiles),
        "gateway_profile_count": len(gateway_profiles),
        "topic_count": len(bus_summary.get("topic_counts") or {}),
        "recommended_cluster_size": bounded_int(scaling_summary.get("recommended_cluster_size", 0)),
        "gateway_preview_only": True,
        "telemetry_routing_modified": False,
    }


def build_branch_readiness(profile_rows: list[dict[str, Any]], *, optimization_summary: dict[str, Any], scaling_summary: dict[str, Any]) -> dict[str, Any]:
    branch_profiles = [row for row in profile_rows if row.get("profile_type") == "branch_collector"]
    return {
        "branch_ready": bool(branch_profiles),
        "branch_profile_count": len(branch_profiles),
        "optimization_state_counts": optimization_summary.get("state_counts", {}),
        "scaling_state_counts": scaling_summary.get("state_counts", {}),
        "branch_preview_only": True,
        "deployment_action_executed": False,
    }


def edge_state_from_inputs(
    *,
    profile_summary: dict[str, Any],
    bus_summary: dict[str, Any],
    storage_summary: dict[str, Any],
    scaling_summary: dict[str, Any],
    optimization_summary: dict[str, Any],
    offline_readiness: dict[str, Any],
    gateway_readiness: dict[str, Any],
    branch_readiness: dict[str, Any],
) -> str:
    if profile_summary.get("profile_count", 0) <= 0:
        return "unavailable"
    if profile_summary.get("type_counts", {}).get("unknown", 0) or profile_summary.get("device_class_counts", {}).get("unknown", 0):
        return "degraded"
    if bus_summary.get("malformed_count", 0) or storage_summary.get("malformed_count", 0):
        return "degraded"
    if scaling_summary.get("malformed_count", 0) or optimization_summary.get("malformed_count", 0):
        return "degraded"
    if optimization_summary.get("state_counts", {}).get("degraded", 0):
        return "degraded"
    if offline_readiness.get("offline_ready") and not (gateway_readiness.get("gateway_ready") or branch_readiness.get("branch_ready")):
        return "offline_capable"
    if gateway_readiness.get("gateway_ready") or branch_readiness.get("branch_ready"):
        return "edge_ready"
    return "ready"


def recommendations_for_edge_state(
    state: str,
    offline_readiness: dict[str, Any],
    degraded_readiness: dict[str, Any],
    gateway_readiness: dict[str, Any],
    branch_readiness: dict[str, Any],
) -> list[str]:
    if state == "unavailable":
        return ["define at least one edge profile before edge readiness"]
    if state == "degraded":
        return ["review malformed or unsupported edge, storage, scaling, or optimization inputs before deployment planning"]
    if gateway_readiness.get("gateway_ready"):
        return ["gateway collector readiness is preview-only; routing and collection are unchanged"]
    if branch_readiness.get("branch_ready"):
        return ["branch collector readiness is preview-only; no deployment action has been executed"]
    if offline_readiness.get("offline_ready"):
        return ["offline operation is supported by profile metadata; runtime behavior is unchanged"]
    if degraded_readiness.get("degraded_ready"):
        return ["degraded operation is supported by profile metadata; collection logic is unchanged"]
    return ["edge worker mode readiness is advisory and metadata-only"]


def normalize_edge_state(value: Any) -> str:
    safe_value = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return safe_value if safe_value in EDGE_STATES else "unknown"


def _max_ratio(*values: Any) -> float:
    return max((_safe_float(value) for value in values), default=0.0)


def _safe_float(value: Any) -> float:
    try:
        return max(0.0, float(value))
    except Exception:
        return 0.0


def deterministic_edge_worker_mode_json(summary: EdgeWorkerModeSummary | dict[str, Any]) -> str:
    payload = summary.to_dict() if isinstance(summary, EdgeWorkerModeSummary) else summary
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "EDGE_STATES",
    "EdgeWorkerModeSummary",
    "build_branch_readiness",
    "build_degraded_readiness",
    "build_edge_worker_mode_summary",
    "build_gateway_readiness",
    "build_offline_readiness",
    "deterministic_edge_worker_mode_json",
    "edge_state_from_inputs",
    "empty_edge_worker_mode_summary",
    "normalize_edge_state",
    "recommendations_for_edge_state",
    "summarize_optimization_inputs",
]
