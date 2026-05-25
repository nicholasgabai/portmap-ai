from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.flows import flow_to_topology_edge
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS
from core_engine.topology.graph import summarize_topology


LIVE_TOPOLOGY_RECORD_VERSION = 1
DEFAULT_MAX_LIVE_NODES = 128
DEFAULT_MAX_LIVE_EDGES = 256


def correlate_flow_topology_edges(
    flows: Iterable[dict[str, Any]],
    *,
    protocol_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_edges: int = DEFAULT_MAX_LIVE_EDGES,
) -> dict[str, Any]:
    """Convert reconstructed metadata-only flows into topology edge records."""
    timestamp = generated_at or _now()
    protocol_index = _protocol_records_by_flow_ref(protocol_records)
    merged: dict[tuple[str, str, str, str], dict[str, Any]] = {}
    skipped = 0
    for flow in _rows(flows):
        edge = dict(flow.get("topology_edge") if isinstance(flow.get("topology_edge"), dict) else flow_to_topology_edge(flow))
        if not edge.get("source_asset") or not edge.get("target_asset"):
            skipped += 1
            continue
        protocol = _protocol_label(flow, protocol_index.get(str(flow.get("flow_id") or "")))
        edge["protocol"] = protocol
        edge["protocol_service_label"] = protocol
        edge["source_refs"] = _source_refs(flow, edge)
        edge["source_node_ids"] = sorted(str(item) for item in flow.get("source_node_ids") or [] if item)
        edge["confidence"] = _edge_confidence(edge, protocol_index.get(str(flow.get("flow_id") or "")))
        edge["generated_at"] = timestamp
        edge.update(_safety_fields())
        key = (
            str(edge.get("source_asset") or edge.get("src") or ""),
            str(edge.get("target_asset") or edge.get("dst") or ""),
            str(edge.get("relationship_type") or "observed_flow"),
            str(edge.get("protocol") or "unknown"),
        )
        existing = merged.setdefault(key, _base_edge(edge))
        existing["flow_count"] += int(edge.get("flow_count") or 1)
        existing["observation_count"] += int(edge.get("observation_count") or 0)
        existing["byte_count"] += int(edge.get("byte_count") or 0)
        existing["confidence"] = max(float(existing.get("confidence") or 0.0), float(edge.get("confidence") or 0.0))
        existing["flow_refs"].append(str(flow.get("flow_id") or edge.get("flow_ref") or ""))
        existing["source_refs"].extend(str(ref) for ref in edge.get("source_refs") or [] if ref)
        existing["source_node_ids"].extend(str(node) for node in edge.get("source_node_ids") or [] if node)

    all_edges = [_final_edge(row, timestamp) for row in merged.values()]
    all_edges.sort(key=lambda item: (item["source_asset"], item["target_asset"], item["protocol"]))
    bounded = all_edges[: max(0, int(max_edges))]
    return {
        "record_type": "flow_topology_edge_correlation",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": timestamp,
        "edge_count": len(bounded),
        "unbounded_edge_count": len(all_edges),
        "truncated_edge_count": max(0, len(all_edges) - len(bounded)),
        "skipped_flow_count": skipped,
        "edges": bounded,
        **_safety_fields(),
    }


def infer_live_node_relationships(
    flows: Iterable[dict[str, Any]],
    *,
    protocol_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_nodes: int = DEFAULT_MAX_LIVE_NODES,
    max_edges: int = DEFAULT_MAX_LIVE_EDGES,
) -> dict[str, Any]:
    """Infer live node records and relationships from flow and protocol summaries."""
    timestamp = generated_at or _now()
    edge_report = correlate_flow_topology_edges(flows, protocol_records=protocol_records, generated_at=timestamp, max_edges=max_edges)
    nodes: dict[str, dict[str, Any]] = {}
    for flow in _rows(flows):
        service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
        for endpoint_name in ("initiator", "responder"):
            endpoint = flow.get(endpoint_name) if isinstance(flow.get(endpoint_name), dict) else {}
            node_id = str(endpoint.get("ip") or "")
            if not node_id:
                continue
            node = nodes.setdefault(node_id, _new_node(node_id, timestamp))
            node["flow_refs"].append(str(flow.get("flow_id") or ""))
            node["source_refs"].extend(str(ref) for ref in flow.get("source_refs") or [] if ref)
            node["source_node_ids"].extend(str(item) for item in flow.get("source_node_ids") or [] if item)
            peer = flow.get("responder") if endpoint_name == "initiator" else flow.get("initiator")
            peer_endpoint = peer if isinstance(peer, dict) else {}
            node["peer_ids"].append(str(peer_endpoint.get("ip") or ""))
            node[f"{endpoint_name}_flow_count"] += 1
            if endpoint_name == "responder":
                service_name = str(service.get("service_name") or "unknown")
                service_port = service.get("service_port")
                if service_name != "unknown":
                    node["services"].append(service_name)
                if service_port is not None:
                    node["service_ports"].append(int(service_port))
    roles = infer_node_roles(nodes.values(), edge_report["edges"], flows, protocol_records=protocol_records, generated_at=timestamp)
    node_records = [_final_node(node, roles.get(node_id, {}), timestamp) for node_id, node in nodes.items()]
    node_records.sort(key=lambda item: item["asset_id"])
    bounded_nodes = node_records[: max(0, int(max_nodes))]
    return {
        "record_type": "live_node_relationship_inference",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": timestamp,
        "node_count": len(bounded_nodes),
        "edge_count": len(edge_report["edges"]),
        "unbounded_node_count": len(node_records),
        "truncated_node_count": max(0, len(node_records) - len(bounded_nodes)),
        "truncated_edge_count": int(edge_report.get("truncated_edge_count") or 0),
        "nodes": bounded_nodes,
        "edges": edge_report["edges"],
        "bounds": {
            "max_nodes": int(max_nodes),
            "max_edges": int(max_edges),
            "node_growth_bounded": len(node_records) <= int(max_nodes),
            "edge_growth_bounded": int(edge_report.get("truncated_edge_count") or 0) == 0,
        },
        "warnings": _bound_warnings(len(node_records), int(edge_report.get("unbounded_edge_count") or 0), max_nodes, max_edges),
        **_safety_fields(),
    }


def infer_node_roles(
    nodes: Iterable[dict[str, Any]],
    edges: Iterable[dict[str, Any]],
    flows: Iterable[dict[str, Any]],
    *,
    protocol_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, dict[str, Any]]:
    timestamp = generated_at or _now()
    protocol_index = _protocol_records_by_flow_ref(protocol_records)
    roles: dict[str, dict[str, Any]] = {}
    flow_rows = _rows(flows)
    for node in _rows(nodes):
        node_id = str(node.get("asset_id") or "")
        protocols = set()
        services = set(str(item) for item in node.get("services") or [] if item)
        for flow in flow_rows:
            is_responder = str((flow.get("responder") or {}).get("ip") or "") == node_id
            is_initiator = str((flow.get("initiator") or {}).get("ip") or "") == node_id
            if not is_responder and not is_initiator:
                continue
            protocol = str((protocol_index.get(str(flow.get("flow_id") or "")) or {}).get("protocol") or "")
            if protocol and is_responder:
                protocols.add(protocol)
        role = "observed_node"
        if "dns" in services or "dns" in protocols:
            role = "name_service"
        elif {"http", "https", "http-alt", "https-alt"} & services or {"http", "tls"} & protocols:
            role = "web_service" if int(node.get("responder_flow_count") or 0) else "client"
        elif int(node.get("initiator_flow_count") or 0) and int(node.get("responder_flow_count") or 0):
            role = "mixed"
        elif int(node.get("responder_flow_count") or 0):
            role = "service_provider"
        elif int(node.get("initiator_flow_count") or 0):
            role = "client"
        roles[node_id] = {
            "record_type": "live_node_role_inference",
            "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
            "generated_at": timestamp,
            "asset_id": node_id,
            "role": role,
            "services": sorted(services),
            "protocols": sorted(protocols),
            "confidence": _role_confidence(role, node),
            **_safety_fields(),
        }
    return roles


def build_protocol_aware_topology_summary(
    *,
    graph: dict[str, Any],
    flows: Iterable[dict[str, Any]],
    protocol_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    base = summarize_topology(graph)
    records = _rows(protocol_records)
    return {
        "record_type": "protocol_aware_topology_summary",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": timestamp,
        "topology": base,
        "flow_count": len(_rows(flows)),
        "protocol_metadata_count": len(records),
        "by_protocol": _count_by(records, "protocol"),
        "by_role": _count_by(_rows(graph.get("nodes")), "category"),
        "protocol_anomaly_count": sum(len(row.get("protocol_anomalies") or []) for row in records),
        "highest_protocol_confidence": round(max((float(row.get("confidence") or 0.0) for row in records), default=0.0), 3),
        **_safety_fields(),
    }


def correlate_topology_drift(
    *,
    baseline_graph: dict[str, Any] | None,
    current_graph: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not baseline_graph:
        return {
            "record_type": "live_topology_drift_correlation",
            "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
            "generated_at": timestamp,
            "status": "no_baseline",
            "baseline_present": False,
            "added_node_count": 0,
            "removed_node_count": 0,
            "added_edge_count": 0,
            "removed_edge_count": 0,
            "added_nodes": [],
            "removed_nodes": [],
            "added_edges": [],
            "removed_edges": [],
            "operator_summary": "No baseline topology graph was provided for drift comparison.",
            **_safety_fields(),
        }
    baseline = baseline_graph if isinstance(baseline_graph, dict) else {"nodes": [], "edges": []}
    baseline_nodes = {_node_key(row) for row in _rows(baseline.get("nodes"))}
    current_nodes = {_node_key(row) for row in _rows(current_graph.get("nodes"))}
    baseline_edges = {_graph_edge_key(row) for row in _rows(baseline.get("edges"))}
    current_edges = {_graph_edge_key(row) for row in _rows(current_graph.get("edges"))}
    added_nodes = sorted(current_nodes - baseline_nodes)
    removed_nodes = sorted(baseline_nodes - current_nodes)
    added_edges = sorted(current_edges - baseline_edges)
    removed_edges = sorted(baseline_edges - current_edges)
    status = "review_required" if added_nodes or removed_nodes or added_edges or removed_edges else "stable"
    return {
        "record_type": "live_topology_drift_correlation",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": timestamp,
        "status": status,
        "baseline_present": bool(baseline_graph),
        "added_node_count": len(added_nodes),
        "removed_node_count": len(removed_nodes),
        "added_edge_count": len(added_edges),
        "removed_edge_count": len(removed_edges),
        "added_nodes": added_nodes,
        "removed_nodes": removed_nodes,
        "added_edges": added_edges,
        "removed_edges": removed_edges,
        "operator_summary": "Live topology changed relative to baseline." if status == "review_required" else "Live topology matches the provided baseline.",
        **_safety_fields(),
    }


def build_temporal_topology_summary(
    flows: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(flows)
    first_seen = min((str(row.get("first_seen") or "") for row in rows if row.get("first_seen")), default=None)
    last_seen = max((str(row.get("last_seen") or "") for row in rows if row.get("last_seen")), default=None)
    return {
        "record_type": "temporal_live_topology_summary",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "flow_count": len(rows),
        "persistent_flow_count": sum(1 for row in rows if row.get("ephemeral_or_persistent") == "persistent"),
        "ephemeral_flow_count": sum(1 for row in rows if row.get("ephemeral_or_persistent") == "ephemeral"),
        "by_transport": _count_by(rows, "transport_protocol"),
        **_safety_fields(),
    }


def build_topology_update_record(
    graph: dict[str, Any],
    *,
    previous_update_digests: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    digest = "sha256:" + _digest(
        {
            "nodes": sorted(_node_key(row) for row in _rows(graph.get("nodes"))),
            "edges": sorted(_graph_edge_key(row) for row in _rows(graph.get("edges"))),
        }
    )
    previous = {str(item) for item in previous_update_digests or [] if item}
    classification = "duplicate" if digest in previous else "accepted"
    return {
        "record_type": "replay_safe_topology_update",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": timestamp,
        "update_digest": digest,
        "classification": classification,
        "accepted_count": 1 if classification == "accepted" else 0,
        "duplicate_count": 1 if classification == "duplicate" else 0,
        "replay_checked": True,
        "node_count": len(_rows(graph.get("nodes"))),
        "edge_count": len(_rows(graph.get("edges"))),
        **_safety_fields(),
    }


def build_topology_health_summary(
    *,
    graph: dict[str, Any],
    drift: dict[str, Any],
    relationship_inference: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    warnings = list(relationship_inference.get("warnings") or [])
    if drift.get("status") == "review_required":
        warnings.append("topology_drift_detected")
    status = "review_required" if warnings else "ok"
    return {
        "record_type": "live_topology_health_summary",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "node_count": int(graph.get("node_count") or 0),
        "edge_count": int(graph.get("edge_count") or 0),
        "warnings": sorted(set(str(item) for item in warnings if item)),
        "operator_summary": "Live topology needs operator review." if status == "review_required" else "Live topology correlation is within configured bounds.",
        **_safety_fields(),
    }


def deterministic_live_topology_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _base_edge(edge: dict[str, Any]) -> dict[str, Any]:
    return {
        "record_type": "topology_edge",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "edge_id": edge.get("edge_id") or "edge-" + _digest(edge)[:16],
        "source_asset": str(edge.get("source_asset") or edge.get("src") or ""),
        "target_asset": str(edge.get("target_asset") or edge.get("dst") or ""),
        "src": str(edge.get("source_asset") or edge.get("src") or ""),
        "dst": str(edge.get("target_asset") or edge.get("dst") or ""),
        "relationship_type": str(edge.get("relationship_type") or "observed_flow"),
        "protocol": str(edge.get("protocol") or "unknown"),
        "protocol_service_label": str(edge.get("protocol") or "unknown"),
        "flow_count": 0,
        "observation_count": 0,
        "byte_count": 0,
        "confidence": float(edge.get("confidence") or 0.0),
        "flow_refs": [],
        "source_refs": [],
        "source_node_ids": [],
        **_safety_fields(),
    }


def _final_edge(edge: dict[str, Any], generated_at: str) -> dict[str, Any]:
    refs = sorted(set(str(item) for item in edge.get("source_refs") or [] if item))
    flow_refs = sorted(set(str(item) for item in edge.get("flow_refs") or [] if item))
    nodes = sorted(set(str(item) for item in edge.get("source_node_ids") or [] if item))
    material = {key: edge.get(key) for key in ("source_asset", "target_asset", "relationship_type", "protocol")}
    return {
        **edge,
        "edge_id": "edge-" + _digest(material)[:16],
        "flow_refs": flow_refs,
        "source_refs": refs,
        "source_node_ids": nodes,
        "confidence": round(float(edge.get("confidence") or 0.0), 3),
        "generated_at": generated_at,
        **_safety_fields(),
    }


def _new_node(node_id: str, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": "live_topology_node",
        "record_version": LIVE_TOPOLOGY_RECORD_VERSION,
        "asset_id": node_id,
        "label": node_id,
        "category": "observed_node",
        "generated_at": generated_at,
        "initiator_flow_count": 0,
        "responder_flow_count": 0,
        "service_ports": [],
        "services": [],
        "peer_ids": [],
        "flow_refs": [],
        "source_refs": [],
        "source_node_ids": [],
        "confidence": 0.55,
        **_safety_fields(),
    }


def _final_node(node: dict[str, Any], role: dict[str, Any], generated_at: str) -> dict[str, Any]:
    services = sorted(set(str(item) for item in node.get("services") or [] if item))
    ports = sorted(set(int(item) for item in node.get("service_ports") or [] if item is not None))
    peers = sorted(set(str(item) for item in node.get("peer_ids") or [] if item))
    category = str(role.get("role") or node.get("category") or "observed_node")
    return {
        **node,
        "category": category,
        "role": category,
        "service_count": len(services),
        "service_ports": ports,
        "services": services,
        "peer_ids": peers,
        "relationship_count": len(peers),
        "flow_refs": sorted(set(str(item) for item in node.get("flow_refs") or [] if item)),
        "source_refs": sorted(set(str(item) for item in node.get("source_refs") or [] if item)),
        "source_node_ids": sorted(set(str(item) for item in node.get("source_node_ids") or [] if item)),
        "confidence": round(float(role.get("confidence") or node.get("confidence") or 0.0), 3),
        "generated_at": generated_at,
        **_safety_fields(),
    }


def _protocol_records_by_flow_ref(records: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    return {str(row.get("flow_ref") or ""): dict(row) for row in _rows(records) if row.get("flow_ref")}


def _protocol_label(flow: dict[str, Any], protocol_record: dict[str, Any] | None) -> str:
    service = flow.get("service_association") if isinstance(flow.get("service_association"), dict) else {}
    transport = str(flow.get("transport_protocol") or "unknown")
    protocol = str((protocol_record or {}).get("protocol") or "").lower()
    if protocol and protocol != "unknown":
        return f"{transport}/{protocol}"
    service_name = str(service.get("service_name") or "unknown")
    return f"{transport}/{service_name}" if service_name != "unknown" else transport


def _edge_confidence(edge: dict[str, Any], protocol_record: dict[str, Any] | None) -> float:
    base = float(edge.get("confidence") or 0.0)
    if not protocol_record:
        return round(base, 3)
    protocol_confidence = float(protocol_record.get("confidence") or 0.0)
    return round(min(1.0, max(base, (base + protocol_confidence) / 2)), 3)


def _role_confidence(role: str, node: dict[str, Any]) -> float:
    if role in {"name_service", "web_service"}:
        return 0.88
    if int(node.get("responder_flow_count") or 0) or int(node.get("initiator_flow_count") or 0):
        return 0.72
    return 0.45


def _source_refs(flow: dict[str, Any], edge: dict[str, Any]) -> list[str]:
    refs = set(str(item) for item in flow.get("source_refs") or [] if item)
    if flow.get("flow_id"):
        refs.add(f"flow:{flow['flow_id']}")
    if edge.get("source_ref"):
        refs.add(f"edge:{edge['source_ref']}")
    return sorted(refs)


def _node_key(row: dict[str, Any]) -> str:
    return str(row.get("asset_id") or row.get("node_id") or row.get("label") or "")


def _graph_edge_key(row: dict[str, Any]) -> str:
    return "|".join(
        [
            str(row.get("source_asset") or row.get("src") or ""),
            str(row.get("target_asset") or row.get("dst") or ""),
            str(row.get("relationship_type") or ""),
            str(row.get("protocol_service_label") or row.get("protocol") or ""),
        ]
    )


def _bound_warnings(node_count: int, edge_count: int, max_nodes: int, max_edges: int) -> list[str]:
    warnings = []
    if node_count > int(max_nodes):
        warnings.append("node_limit_reached")
    if edge_count > int(max_edges):
        warnings.append("edge_limit_reached")
    return warnings


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _safety_fields() -> dict[str, Any]:
    return {
        **TELEMETRY_SAFETY_FLAGS,
        "payload_bytes_stored": 0,
        "traffic_injected": False,
        "automatic_blocking": False,
        "parallel_topology_schema_created": False,
    }


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
