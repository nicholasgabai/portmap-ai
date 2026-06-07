from __future__ import annotations

from hashlib import sha256
from typing import Any, Iterable

from core_engine.visualization.asset_classifier import classify_asset, score_asset_confidence
from core_engine.visualization.topology_models import (
    TOPOLOGY_VISUAL_SAFETY_FLAGS,
    TopologyEdge,
    TopologyGraph,
    TopologyNode,
    TopologyVisualizationError,
    clamp_score,
    normalize_asset_category,
    normalize_source_mode,
    now_timestamp,
)


DEFAULT_MAX_NODES = 128
DEFAULT_MAX_EDGES = 256


def observation_to_node(
    observation: dict[str, Any],
    *,
    endpoint: str = "local",
    generated_at: str | None = None,
) -> TopologyNode:
    if not isinstance(observation, dict):
        raise TopologyVisualizationError("observation must be an object")
    timestamp = generated_at or now_timestamp()
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or "unknown")
    node_class = _endpoint_class(observation, endpoint=endpoint)
    role_hint = _role_hint(observation, endpoint=endpoint)
    asset_category = classify_asset({**observation, "endpoint_class": node_class, "role_hint": role_hint})
    confidence = score_node_confidence(observation, endpoint=endpoint, asset_category=asset_category)
    node_id = "visual-node-" + _digest(
        {
            "endpoint": endpoint,
            "node_class": node_class,
            "role_hint": role_hint,
            "asset_category": asset_category,
            "source_mode": mode,
            "port_bucket": _port_bucket(_port_for_endpoint(observation, endpoint=endpoint)),
        }
    )[:16]
    return TopologyNode(
        node_id=node_id,
        label=_node_label(asset_category, node_class, role_hint),
        asset_category=asset_category,
        node_class=node_class,
        role_hint=role_hint,
        source_mode=mode,
        first_seen=str(observation.get("first_seen") or observation.get("observed_at") or timestamp),
        last_seen=str(observation.get("last_seen") or observation.get("observed_at") or timestamp),
        observation_count=max(1, int(observation.get("observation_count") or 1)),
        confidence_score=confidence,
        advisory_notes=_node_notes(asset_category, node_class, mode),
    )


def flow_to_edge(
    flow: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> TopologyEdge:
    if not isinstance(flow, dict):
        raise TopologyVisualizationError("flow must be an object")
    timestamp = generated_at or now_timestamp()
    source_node = observation_to_node(flow, endpoint=_source_endpoint(flow), generated_at=timestamp)
    target_node = observation_to_node(flow, endpoint=_target_endpoint(flow), generated_at=timestamp)
    mode = normalize_source_mode(flow.get("source_mode") or flow.get("data_source") or "unknown")
    protocol = _safe_token(flow.get("protocol") or flow.get("transport") or flow.get("transport_protocol") or "unknown")
    service_hint = _safe_token(flow.get("service_hint") or flow.get("service") or flow.get("service_attribution") or "unknown")
    relationship_type = _relationship_type(flow)
    count = max(1, int(flow.get("observation_count") or flow.get("packet_count") or 1))
    confidence = score_edge_confidence(flow)
    edge_id = "visual-edge-" + _digest(
        {
            "source_node_id": source_node.node_id,
            "target_node_id": target_node.node_id,
            "relationship_type": relationship_type,
            "protocol": protocol,
            "service_hint": service_hint,
            "source_mode": mode,
        }
    )[:16]
    return TopologyEdge(
        edge_id=edge_id,
        source_node_id=source_node.node_id,
        target_node_id=target_node.node_id,
        relationship_type=relationship_type,
        flow_reference=_safe_reference(flow.get("flow_reference") or flow.get("flow_id") or flow.get("session_reference") or flow.get("session_id")),
        protocol=protocol,
        service_hint=service_hint,
        source_mode=mode,
        observation_count=count,
        weight=score_edge_weight(flow, observation_count=count),
        confidence_score=confidence,
        advisory_notes=_edge_notes(protocol, service_hint, mode),
    )


def build_topology_graph(
    observations: Iterable[dict[str, Any]] | None = None,
    flows: Iterable[dict[str, Any]] | None = None,
    *,
    generated_at: str | None = None,
    label: str = "visual-topology",
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
) -> TopologyGraph:
    timestamp = generated_at or now_timestamp()
    if observations is not None and not _is_iterable(observations):
        raise TopologyVisualizationError("observations must be iterable")
    if flows is not None and not _is_iterable(flows):
        raise TopologyVisualizationError("flows must be iterable")

    nodes: list[TopologyNode] = []
    edges: list[TopologyEdge] = []
    for row in observations or []:
        if not isinstance(row, dict):
            continue
        nodes.append(observation_to_node(row, endpoint="local", generated_at=timestamp))
        if _has_remote_side(row):
            nodes.append(observation_to_node(row, endpoint="remote", generated_at=timestamp))
    for row in flows or []:
        if not isinstance(row, dict):
            continue
        nodes.append(observation_to_node(row, endpoint="local", generated_at=timestamp))
        if _has_remote_side(row):
            nodes.append(observation_to_node(row, endpoint="remote", generated_at=timestamp))
        edges.append(flow_to_edge(row, generated_at=timestamp))

    deduped_nodes, nodes_truncated = deduplicate_nodes(nodes, max_nodes=max_nodes)
    deduped_edges, edges_truncated = aggregate_edges(edges, max_edges=max_edges)
    summary = summarize_topology_graph(deduped_nodes, deduped_edges, generated_at=timestamp)
    summary["nodes_truncated"] = nodes_truncated
    summary["edges_truncated"] = edges_truncated
    return TopologyGraph(
        graph_id="visual-graph-" + _digest({"label": label, "generated_at": timestamp, "nodes": [node.node_id for node in deduped_nodes], "edges": [edge.edge_id for edge in deduped_edges]})[:16],
        generated_at=timestamp,
        nodes=deduped_nodes,
        edges=deduped_edges,
        summary=summary,
        limits={"max_nodes": max_nodes, "max_edges": max_edges, "nodes_truncated": nodes_truncated, "edges_truncated": edges_truncated},
        advisory_notes=["visualization model only", "graph growth is bounded", "no live network action is performed"],
    )


def deduplicate_nodes(nodes: Iterable[TopologyNode], *, max_nodes: int = DEFAULT_MAX_NODES) -> tuple[list[TopologyNode], bool]:
    grouped: dict[str, TopologyNode] = {}
    for node in nodes or []:
        if not isinstance(node, TopologyNode):
            continue
        existing = grouped.get(node.node_id)
        if existing is None:
            grouped[node.node_id] = node
            continue
        grouped[node.node_id] = TopologyNode(
            node_id=node.node_id,
            label=existing.label,
            asset_category=existing.asset_category if existing.asset_category != "UNKNOWN" else node.asset_category,
            node_class=existing.node_class,
            role_hint=existing.role_hint,
            source_mode=existing.source_mode,
            first_seen=min(existing.first_seen, node.first_seen),
            last_seen=max(existing.last_seen, node.last_seen),
            observation_count=existing.observation_count + node.observation_count,
            confidence_score=max(existing.confidence_score, node.confidence_score),
            advisory_notes=sorted(set(existing.advisory_notes + node.advisory_notes)),
        )
    rows = sorted(grouped.values(), key=lambda item: item.node_id)
    return rows[: max(0, int(max_nodes))], len(rows) > max(0, int(max_nodes))


def aggregate_edges(edges: Iterable[TopologyEdge], *, max_edges: int = DEFAULT_MAX_EDGES) -> tuple[list[TopologyEdge], bool]:
    grouped: dict[str, TopologyEdge] = {}
    for edge in edges or []:
        if not isinstance(edge, TopologyEdge):
            continue
        existing = grouped.get(edge.edge_id)
        if existing is None:
            grouped[edge.edge_id] = edge
            continue
        grouped[edge.edge_id] = TopologyEdge(
            edge_id=edge.edge_id,
            source_node_id=edge.source_node_id,
            target_node_id=edge.target_node_id,
            relationship_type=edge.relationship_type,
            flow_reference=existing.flow_reference or edge.flow_reference,
            protocol=edge.protocol,
            service_hint=edge.service_hint,
            source_mode=edge.source_mode,
            observation_count=existing.observation_count + edge.observation_count,
            weight=clamp_score(existing.weight + edge.weight / 2),
            confidence_score=max(existing.confidence_score, edge.confidence_score),
            advisory_notes=sorted(set(existing.advisory_notes + edge.advisory_notes)),
        )
    rows = sorted(grouped.values(), key=lambda item: item.edge_id)
    return rows[: max(0, int(max_edges))], len(rows) > max(0, int(max_edges))


def summarize_topology_graph(nodes: Iterable[TopologyNode], edges: Iterable[TopologyEdge], *, generated_at: str | None = None) -> dict[str, Any]:
    node_rows = [node.to_dict() for node in nodes or [] if isinstance(node, TopologyNode)]
    edge_rows = [edge.to_dict() for edge in edges or [] if isinstance(edge, TopologyEdge)]
    return {
        "record_type": "visual_topology_summary",
        "record_version": 1,
        "generated_at": generated_at or now_timestamp(),
        "node_count": len(node_rows),
        "edge_count": len(edge_rows),
        "asset_categories": sorted({row["asset_category"] for row in node_rows}) or ["UNKNOWN"],
        "source_modes": sorted({row["source_mode"] for row in node_rows + edge_rows}) or ["unknown"],
        "average_node_confidence": _average(node_rows, "confidence_score"),
        "average_edge_confidence": _average(edge_rows, "confidence_score"),
        "bounded": True,
        **TOPOLOGY_VISUAL_SAFETY_FLAGS,
    }


def score_node_confidence(observation: dict[str, Any], *, endpoint: str, asset_category: str) -> float:
    score = score_asset_confidence(observation, asset_category=asset_category) * 0.65
    if _endpoint_class(observation, endpoint=endpoint) != "unknown":
        score += 0.15
    if _port_for_endpoint(observation, endpoint=endpoint) is not None:
        score += 0.08
    if observation.get("source_mode") or observation.get("data_source"):
        score += 0.05
    if observation.get("first_seen") or observation.get("last_seen") or observation.get("observed_at"):
        score += 0.04
    return clamp_score(score)


def score_edge_confidence(flow: dict[str, Any]) -> float:
    score = 0.25
    if flow.get("flow_reference") or flow.get("flow_id") or flow.get("session_id"):
        score += 0.12
    if flow.get("protocol") or flow.get("transport") or flow.get("transport_protocol"):
        score += 0.15
    if flow.get("local_port") or flow.get("remote_port"):
        score += 0.12
    if flow.get("service_hint") or flow.get("service") or flow.get("service_attribution"):
        score += 0.12
    if _has_remote_side(flow):
        score += 0.14
    if flow.get("relationship_strength") is not None:
        score += min(0.1, float(flow.get("relationship_strength") or 0.0) * 0.1)
    return clamp_score(score)


def score_edge_weight(flow: dict[str, Any], *, observation_count: int) -> float:
    score = min(0.5, max(1, observation_count) * 0.05)
    score += float(flow.get("relationship_strength") or flow.get("recurrence_score") or 0.0) * 0.35
    if flow.get("session_state") in {"recurring", "active"} or flow.get("relationship_state") in {"recurring", "active"}:
        score += 0.15
    return clamp_score(score)


def _source_endpoint(flow: dict[str, Any]) -> str:
    direction = str(flow.get("flow_direction") or flow.get("direction") or "").lower()
    return "remote" if direction == "inbound" else "local"


def _target_endpoint(flow: dict[str, Any]) -> str:
    direction = str(flow.get("flow_direction") or flow.get("direction") or "").lower()
    return "local" if direction == "inbound" else "remote"


def _endpoint_class(observation: dict[str, Any], *, endpoint: str) -> str:
    keys = (
        ("local_node_class", "local_endpoint_class", "local_address_class", "node_class", "endpoint_class")
        if endpoint == "local"
        else ("remote_node_class", "remote_endpoint_class", "remote_address_class", "target_node_class", "endpoint_class")
    )
    for key in keys:
        value = observation.get(key)
        if value:
            return _safe_token(value)
    return "unknown"


def _role_hint(observation: dict[str, Any], *, endpoint: str) -> str:
    keys = (
        ("local_role", "source_role", "node_role", "role_hint", "service_hint", "service")
        if endpoint == "local"
        else ("remote_role", "target_role", "role_hint", "service_hint", "service")
    )
    for key in keys:
        value = observation.get(key)
        if value:
            return _safe_token(value)
    return "unknown"


def _port_for_endpoint(observation: dict[str, Any], *, endpoint: str) -> int | None:
    key = "local_port" if endpoint == "local" else "remote_port"
    try:
        port = int(observation.get(key) or observation.get("port") or 0)
    except (TypeError, ValueError):
        return None
    return port if 0 < port <= 65535 else None


def _port_bucket(port: int | None) -> str:
    if port is None:
        return "unknown"
    if port < 1024:
        return "system"
    if port < 49152:
        return "registered"
    return "ephemeral"


def _has_remote_side(row: dict[str, Any]) -> bool:
    return any(row.get(key) is not None for key in ("remote_port", "remote_endpoint_class", "remote_address_class", "remote_node_class", "target_node_class"))


def _relationship_type(flow: dict[str, Any]) -> str:
    value = flow.get("relationship_type") or flow.get("session_classification") or flow.get("session_state") or "flow_observed"
    return _safe_token(value)


def _node_label(asset_category: str, node_class: str, role_hint: str) -> str:
    category = normalize_asset_category(asset_category).lower()
    node_class = _safe_token(node_class)
    role_hint = _safe_token(role_hint)
    if role_hint != "unknown":
        return f"{category}:{role_hint}"
    return f"{category}:{node_class}"


def _node_notes(asset_category: str, node_class: str, source_mode: str) -> list[str]:
    notes = ["visual node uses sanitized metadata only", f"source mode is {source_mode}"]
    if asset_category == "UNKNOWN" or node_class == "unknown":
        notes.append("asset classification is low confidence or unavailable")
    return notes


def _edge_notes(protocol: str, service_hint: str, source_mode: str) -> list[str]:
    notes = ["visual edge is derived from flow metadata only", f"source mode is {source_mode}"]
    if protocol == "unknown" or service_hint == "unknown":
        notes.append("protocol or service hint is incomplete")
    return notes


def _average(rows: list[dict[str, Any]], key: str) -> float:
    if not rows:
        return 0.0
    return clamp_score(sum(float(row.get(key) or 0.0) for row in rows) / len(rows))


def _safe_token(value: Any) -> str:
    token = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    allowed = [char for char in token if char.isalnum() or char == "_"]
    return "".join(allowed)[:64] or "unknown"


def _safe_reference(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return "".join(char for char in text if char.isalnum() or char in {"-", "_", ":"})[:96]


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()


def _is_iterable(value: Any) -> bool:
    try:
        iter(value)
    except TypeError:
        return False
    return not isinstance(value, (str, bytes))
