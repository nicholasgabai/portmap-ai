from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import BUS_ENVELOPE_SAFETY_FLAGS, digest, now_timestamp, sanitize_reference, sanitize_text
from core_engine.scaling.edge_worker_modes import summarize_optimization_inputs
from core_engine.scaling.horizontal_scaling import summarize_storage_inputs
from core_engine.scaling.relay_sessions import (
    RelaySessionRecord,
    default_relay_sessions,
    normalize_relay_session,
    relay_session_summary,
)
from core_engine.scaling.resource_optimization import summarize_scaling_inputs
from core_engine.scaling.retention_tiers import bounded_int
from core_engine.scaling.storage_engine import sanitize_summary_dict, summarize_telemetry_bus_inputs


CLOUD_RELAY_RECORD_VERSION = 1
RELAY_READINESS_STATES = {"ready", "relay_ready", "capacity_constrained", "degraded", "unavailable", "unknown"}
CLOUD_RELAY_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "cloud_resource_created": False,
    "relay_infrastructure_created": False,
    "network_connection_opened": False,
    "telemetry_forwarded": False,
    "saas_control_plane_enabled": False,
    "runtime_behavior_modified": False,
    "telemetry_routing_modified": False,
    "provisioning_executed": False,
}


@dataclass(frozen=True)
class CloudRelayReadinessSummary:
    relay_id: str
    generated_at: str
    relay_readiness_state: str
    relay_sessions: list[dict[str, Any]] = field(default_factory=list)
    telemetry_bus_summary: dict[str, Any] = field(default_factory=dict)
    storage_summary: dict[str, Any] = field(default_factory=dict)
    scaling_summary: dict[str, Any] = field(default_factory=dict)
    optimization_summary: dict[str, Any] = field(default_factory=dict)
    edge_summary: dict[str, Any] = field(default_factory=dict)
    routing_preview: dict[str, Any] = field(default_factory=dict)
    capacity_preview: dict[str, Any] = field(default_factory=dict)
    tenant_isolation_preview: dict[str, Any] = field(default_factory=dict)
    relay_recommendations: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "cloud_relay_readiness_summary",
            "record_version": CLOUD_RELAY_RECORD_VERSION,
            "relay_id": sanitize_reference(self.relay_id),
            "generated_at": str(self.generated_at or ""),
            "relay_readiness_state": normalize_relay_readiness_state(self.relay_readiness_state),
            "relay_sessions": list(self.relay_sessions),
            "telemetry_bus_summary": sanitize_summary_dict(self.telemetry_bus_summary),
            "storage_summary": sanitize_summary_dict(self.storage_summary),
            "scaling_summary": sanitize_summary_dict(self.scaling_summary),
            "optimization_summary": sanitize_summary_dict(self.optimization_summary),
            "edge_summary": sanitize_summary_dict(self.edge_summary),
            "routing_preview": sanitize_summary_dict(self.routing_preview),
            "capacity_preview": sanitize_summary_dict(self.capacity_preview),
            "tenant_isolation_preview": sanitize_summary_dict(self.tenant_isolation_preview),
            "relay_recommendations": [sanitize_text(item) for item in self.relay_recommendations],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **CLOUD_RELAY_SAFETY_FLAGS,
        }


def build_cloud_relay_readiness_summary(
    relay_sessions: Iterable[RelaySessionRecord | dict[str, Any] | Any] | None = None,
    *,
    telemetry_bus_summaries: Iterable[dict[str, Any] | Any] | None = None,
    storage_summaries: Iterable[dict[str, Any] | Any] | None = None,
    scaling_summaries: Iterable[dict[str, Any] | Any] | None = None,
    optimization_summaries: Iterable[dict[str, Any] | Any] | None = None,
    edge_summaries: Iterable[dict[str, Any] | Any] | None = None,
    generated_at: str | None = None,
    relay_id: str | None = None,
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> CloudRelayReadinessSummary:
    timestamp = generated_at or now_timestamp()
    sessions = list(default_relay_sessions(source_mode=source_mode) if relay_sessions is None else relay_sessions)
    session_rows = [normalize_relay_session(session).to_dict() for session in sessions]
    session_summary = relay_session_summary(session_rows)
    bus_summary = summarize_telemetry_bus_inputs(telemetry_bus_summaries)
    storage_summary = summarize_storage_inputs(storage_summaries)
    scaling_summary = summarize_scaling_inputs(scaling_summaries)
    optimization_summary = summarize_optimization_inputs(optimization_summaries)
    edge_summary = summarize_edge_inputs(edge_summaries)
    routing = build_routing_preview(session_rows, bus_summary=bus_summary, edge_summary=edge_summary)
    capacity = build_capacity_preview(
        session_summary=session_summary,
        bus_summary=bus_summary,
        storage_summary=storage_summary,
        scaling_summary=scaling_summary,
        optimization_summary=optimization_summary,
        edge_summary=edge_summary,
    )
    tenant = build_tenant_isolation_preview(session_rows)
    state = relay_state_from_inputs(
        session_summary=session_summary,
        bus_summary=bus_summary,
        storage_summary=storage_summary,
        scaling_summary=scaling_summary,
        optimization_summary=optimization_summary,
        edge_summary=edge_summary,
        capacity_preview=capacity,
    )
    recommendations = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    recommendations.extend(recommendations_for_relay_state(state, routing, capacity, tenant))
    summary_id = relay_id or "cloud-relay-" + digest(
        {
            "generated_at": timestamp,
            "session_ids": [row.get("relay_session_id") for row in session_rows],
            "session_summary": session_summary,
            "bus_summary": bus_summary,
            "storage_summary": storage_summary,
            "scaling_summary": scaling_summary,
            "optimization_summary": optimization_summary,
            "edge_summary": edge_summary,
        }
    )[:16]
    return CloudRelayReadinessSummary(
        relay_id=summary_id,
        generated_at=timestamp,
        relay_readiness_state=state,
        relay_sessions=session_rows,
        telemetry_bus_summary=bus_summary,
        storage_summary=storage_summary,
        scaling_summary=scaling_summary,
        optimization_summary=optimization_summary,
        edge_summary=edge_summary,
        routing_preview=routing,
        capacity_preview=capacity,
        tenant_isolation_preview=tenant,
        relay_recommendations=recommendations,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_cloud_relay_readiness_summary(*, generated_at: str | None = None) -> CloudRelayReadinessSummary:
    return build_cloud_relay_readiness_summary([], generated_at=generated_at)


def summarize_edge_inputs(summaries: Iterable[dict[str, Any] | Any] | None) -> dict[str, Any]:
    rows = [item.to_dict() if hasattr(item, "to_dict") else item for item in list(summaries or [])]
    valid_rows = [row for row in rows if isinstance(row, dict)]
    malformed_count = len(rows) - len(valid_rows)
    state_counts: dict[str, int] = {}
    gateway_ready = 0
    branch_ready = 0
    for row in valid_rows:
        state = sanitize_reference(row.get("edge_state", "unknown")) or "unknown"
        state_counts[state] = state_counts.get(state, 0) + 1
        if row.get("gateway_readiness", {}).get("gateway_ready"):
            gateway_ready += 1
        if row.get("branch_readiness", {}).get("branch_ready"):
            branch_ready += 1
    return {
        "summary_count": len(valid_rows),
        "malformed_count": malformed_count,
        "state_counts": dict(sorted(state_counts.items())),
        "gateway_ready_count": gateway_ready,
        "branch_ready_count": branch_ready,
        "preview_only": True,
        "destructive_action": False,
    }


def build_routing_preview(session_rows: list[dict[str, Any]], *, bus_summary: dict[str, Any], edge_summary: dict[str, Any]) -> dict[str, Any]:
    routing_scopes = sorted({sanitize_reference(row.get("routing_scope", "")) for row in session_rows if sanitize_reference(row.get("routing_scope", ""))})
    return {
        "routing_scope_count": len(routing_scopes),
        "routing_scopes": routing_scopes,
        "topic_count": len(bus_summary.get("topic_counts") or {}),
        "gateway_ready_count": bounded_int(edge_summary.get("gateway_ready_count", 0)),
        "branch_ready_count": bounded_int(edge_summary.get("branch_ready_count", 0)),
        "routing_preview_only": True,
        "telemetry_routing_modified": False,
        "network_connection_opened": False,
        "telemetry_forwarded": False,
    }


def build_capacity_preview(
    *,
    session_summary: dict[str, Any],
    bus_summary: dict[str, Any],
    storage_summary: dict[str, Any],
    scaling_summary: dict[str, Any],
    optimization_summary: dict[str, Any],
    edge_summary: dict[str, Any],
) -> dict[str, Any]:
    estimated_nodes = bounded_int(session_summary.get("estimated_nodes", 0))
    estimated_topics = bounded_int(session_summary.get("estimated_topics", 0))
    queue_depth = bounded_int(bus_summary.get("queue_depth", 0))
    storage_utilization = _safe_float(storage_summary.get("max_utilization_ratio", 0.0))
    optimization_utilization = _safe_float(optimization_summary.get("max_utilization_ratio", 0.0))
    scaling_utilization = _safe_float(scaling_summary.get("max_utilization_ratio", 0.0))
    utilization = max(_ratio(queue_depth, max(estimated_topics, 1) * 100), storage_utilization, optimization_utilization, scaling_utilization)
    return {
        "estimated_nodes": estimated_nodes,
        "estimated_topics": estimated_topics,
        "queue_depth": queue_depth,
        "edge_summary_count": bounded_int(edge_summary.get("summary_count", 0)),
        "utilization_ratio": round(utilization, 4),
        "capacity_constrained": utilization >= 0.85,
        "capacity_preview_only": True,
        "cloud_resource_created": False,
        "relay_infrastructure_created": False,
    }


def build_tenant_isolation_preview(session_rows: list[dict[str, Any]]) -> dict[str, Any]:
    tenant_scopes = sorted({sanitize_reference(row.get("tenant_scope", "")) for row in session_rows if sanitize_reference(row.get("tenant_scope", ""))})
    enterprise_scope = any(row.get("relay_type") in {"enterprise_preview", "hybrid_preview"} for row in session_rows)
    return {
        "tenant_scope_count": len(tenant_scopes),
        "tenant_scopes": tenant_scopes,
        "enterprise_scope_preview": enterprise_scope,
        "tenant_isolation_ready": bool(tenant_scopes),
        "tenant_safe_routing_preview_only": True,
        "saas_control_plane_enabled": False,
        "private_identifier_exported": False,
    }


def relay_state_from_inputs(
    *,
    session_summary: dict[str, Any],
    bus_summary: dict[str, Any],
    storage_summary: dict[str, Any],
    scaling_summary: dict[str, Any],
    optimization_summary: dict[str, Any],
    edge_summary: dict[str, Any],
    capacity_preview: dict[str, Any],
) -> str:
    if session_summary.get("session_count", 0) <= 0:
        return "unavailable"
    if session_summary.get("type_counts", {}).get("unknown", 0) or session_summary.get("state_counts", {}).get("unknown", 0):
        return "degraded"
    if session_summary.get("state_counts", {}).get("degraded", 0) or session_summary.get("state_counts", {}).get("unavailable", 0):
        return "degraded"
    if any(summary.get("malformed_count", 0) for summary in [bus_summary, storage_summary, scaling_summary, optimization_summary, edge_summary]):
        return "degraded"
    if optimization_summary.get("state_counts", {}).get("degraded", 0) or edge_summary.get("state_counts", {}).get("degraded", 0):
        return "degraded"
    if capacity_preview.get("capacity_constrained"):
        return "capacity_constrained"
    if any(key in session_summary.get("type_counts", {}) for key in ["regional_preview", "enterprise_preview", "hybrid_preview"]):
        return "relay_ready"
    return "ready"


def recommendations_for_relay_state(
    state: str,
    routing_preview: dict[str, Any],
    capacity_preview: dict[str, Any],
    tenant_isolation_preview: dict[str, Any],
) -> list[str]:
    if state == "unavailable":
        return ["define at least one relay session before relay readiness"]
    if state == "degraded":
        return ["review degraded relay, telemetry, storage, scaling, optimization, or edge inputs before relay planning"]
    if state == "capacity_constrained":
        return ["review relay capacity preview; no cloud resources or relay infrastructure have been created"]
    if not tenant_isolation_preview.get("tenant_isolation_ready"):
        return ["review tenant isolation preview before enterprise relay planning"]
    if routing_preview.get("routing_scope_count", 0):
        return ["relay routing preview is advisory only; no network connection or forwarding is enabled"]
    return ["cloud relay readiness is metadata-only and preview-only"]


def normalize_relay_readiness_state(value: Any) -> str:
    safe_value = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return safe_value if safe_value in RELAY_READINESS_STATES else "unknown"


def _ratio(numerator: Any, denominator: Any) -> float:
    safe_denominator = bounded_int(denominator)
    if safe_denominator <= 0:
        return 0.0
    return round(bounded_int(numerator) / safe_denominator, 6)


def _safe_float(value: Any) -> float:
    try:
        return max(0.0, float(value))
    except Exception:
        return 0.0


def deterministic_cloud_relay_json(summary: CloudRelayReadinessSummary | dict[str, Any]) -> str:
    payload = summary.to_dict() if isinstance(summary, CloudRelayReadinessSummary) else summary
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "RELAY_READINESS_STATES",
    "CloudRelayReadinessSummary",
    "build_capacity_preview",
    "build_cloud_relay_readiness_summary",
    "build_routing_preview",
    "build_tenant_isolation_preview",
    "deterministic_cloud_relay_json",
    "empty_cloud_relay_readiness_summary",
    "normalize_relay_readiness_state",
    "relay_state_from_inputs",
    "summarize_edge_inputs",
]
