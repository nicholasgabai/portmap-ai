from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS
from core_engine.telemetry.topology_correlation import (
    DEFAULT_MAX_LIVE_EDGES,
    DEFAULT_MAX_LIVE_NODES,
    LIVE_TOPOLOGY_RECORD_VERSION,
    build_protocol_aware_topology_summary,
    build_temporal_topology_summary,
    build_topology_health_summary,
    build_topology_update_record,
    correlate_topology_drift,
    deterministic_live_topology_json,
    infer_live_node_relationships,
)
from core_engine.topology.graph import build_topology_graph


def build_live_topology(
    *,
    flows: Iterable[dict[str, Any]],
    protocol_records: Iterable[dict[str, Any]] | None = None,
    baseline_graph: dict[str, Any] | None = None,
    cluster_node_id: str = "local-node",
    federation_scope: str = "local",
    previous_update_digests: Iterable[str] | None = None,
    max_nodes: int = DEFAULT_MAX_LIVE_NODES,
    max_edges: int = DEFAULT_MAX_LIVE_EDGES,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    relationship = infer_live_node_relationships(
        flows,
        protocol_records=protocol_records,
        generated_at=timestamp,
        max_nodes=max_nodes,
        max_edges=max_edges,
    )
    graph = build_topology_graph(assets=relationship["nodes"], topology_edges=relationship["edges"], generated_at=timestamp)
    protocol_summary = build_protocol_aware_topology_summary(graph=graph, flows=flows, protocol_records=protocol_records, generated_at=timestamp)
    drift = correlate_topology_drift(baseline_graph=baseline_graph, current_graph=graph, generated_at=timestamp)
    temporal = build_temporal_topology_summary(flows, generated_at=timestamp)
    update = build_topology_update_record(graph, previous_update_digests=previous_update_digests, generated_at=timestamp)
    cluster = build_cluster_federation_topology_summary(
        graph=graph,
        relationship_inference=relationship,
        cluster_node_id=cluster_node_id,
        federation_scope=federation_scope,
        generated_at=timestamp,
    )
    health = build_topology_health_summary(graph=graph, drift=drift, relationship_inference=relationship, generated_at=timestamp)
    dashboard = build_live_topology_dashboard_record(graph=graph, protocol_summary=protocol_summary, drift=drift, health=health, cluster_summary=cluster, generated_at=timestamp)
    api = build_live_topology_api_response(graph=graph, protocol_summary=protocol_summary, drift=drift, temporal_summary=temporal, health=health, dashboard=dashboard, cluster_summary=cluster, generated_at=timestamp)
    return {
        "record_type": "live_topology",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": timestamp,
        "relationship_inference": relationship,
        "nodes": relationship["nodes"],
        "topology_edges": relationship["edges"],
        "graph": graph,
        "protocol_summary": protocol_summary,
        "drift_correlation": drift,
        "temporal_summary": temporal,
        "topology_update": update,
        "cluster_federation_summary": cluster,
        "health_summary": health,
        "dashboard_status": dashboard,
        "api_status": api,
        **_safety_fields(),
    }


def build_cluster_federation_topology_summary(
    *,
    graph: dict[str, Any],
    relationship_inference: dict[str, Any],
    cluster_node_id: str = "local-node",
    federation_scope: str = "local",
    generated_at: str | None = None,
) -> dict[str, Any]:
    source_nodes = set()
    for edge in relationship_inference.get("edges") or []:
        source_nodes.update(str(item) for item in edge.get("source_node_ids") or [] if item)
    if not source_nodes:
        source_nodes.add(cluster_node_id)
    return {
        "record_type": "cluster_federation_live_topology_summary",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "cluster_node_id": cluster_node_id,
        "federation_scope": federation_scope,
        "source_node_ids": sorted(source_nodes),
        "federation_aware": federation_scope != "local" or len(source_nodes) > 1,
        "node_count": int(graph.get("node_count") or 0),
        "edge_count": int(graph.get("edge_count") or 0),
        "truncated_node_count": int(relationship_inference.get("truncated_node_count") or 0),
        "truncated_edge_count": int(relationship_inference.get("truncated_edge_count") or 0),
        **_safety_fields(),
    }


def build_live_topology_dashboard_record(
    *,
    graph: dict[str, Any],
    protocol_summary: dict[str, Any],
    drift: dict[str, Any],
    health: dict[str, Any],
    cluster_summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    nodes = sorted(graph.get("nodes") or [], key=lambda item: str(item.get("asset_id") or ""))
    edges = sorted(graph.get("edges") or [], key=lambda item: (str(item.get("source_asset") or ""), str(item.get("target_asset") or "")))
    return {
        "record_type": "live_topology_dashboard",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "panel": "live_topology",
        "status": str(health.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "node_count": int(graph.get("node_count") or 0),
            "edge_count": int(graph.get("edge_count") or 0),
            "added_edge_count": int(drift.get("added_edge_count") or 0),
            "protocol_anomaly_count": int(protocol_summary.get("protocol_anomaly_count") or 0),
            "federation_aware": bool(cluster_summary.get("federation_aware")),
        },
        "nodes": [
            {
                "asset_id": row.get("asset_id"),
                "label": row.get("label"),
                "role": row.get("category"),
                "service_count": row.get("service_count"),
                "confidence": row.get("confidence"),
            }
            for row in nodes
        ],
        "edges": [
            {
                "source_asset": row.get("source_asset"),
                "target_asset": row.get("target_asset"),
                "relationship_type": row.get("relationship_type"),
                "protocol": row.get("protocol_service_label") or row.get("protocol"),
                "observation_count": row.get("observation_count"),
                "confidence": row.get("confidence"),
            }
            for row in edges
        ],
        "warnings": list(health.get("warnings") or []),
        "recommended_review": str(health.get("status") or "") == "review_required",
        **_safety_fields(),
    }


def build_live_topology_api_response(
    *,
    graph: dict[str, Any],
    protocol_summary: dict[str, Any],
    drift: dict[str, Any],
    temporal_summary: dict[str, Any],
    health: dict[str, Any],
    dashboard: dict[str, Any],
    cluster_summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "live_topology_api",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "status": str(health.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "graph": dict(graph),
        "protocol_summary": dict(protocol_summary),
        "drift_correlation": dict(drift),
        "temporal_summary": dict(temporal_summary),
        "health_summary": dict(health),
        "cluster_federation_summary": dict(cluster_summary),
        "dashboard": dict(dashboard),
        **_safety_fields(),
    }


def deterministic_live_topology_record_json(record: dict[str, Any]) -> str:
    return deterministic_live_topology_json(record)


def _safety_fields() -> dict[str, Any]:
    return {
        **TELEMETRY_SAFETY_FLAGS,
        "payload_bytes_stored": 0,
        "traffic_injected": False,
        "automatic_blocking": False,
        "parallel_topology_schema_created": False,
    }


def _now() -> str:
    return datetime.now(UTC).isoformat()
