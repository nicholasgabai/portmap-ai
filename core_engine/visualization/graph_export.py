from __future__ import annotations

import json
from typing import Any

from core_engine.visualization.topology_models import TopologyGraph, deterministic_topology_json


def export_graph_json(graph: TopologyGraph | dict[str, Any]) -> str:
    payload = graph.to_dict() if isinstance(graph, TopologyGraph) else graph
    return deterministic_topology_json(payload)


def export_graph_mermaid(graph: TopologyGraph | dict[str, Any]) -> str:
    payload = graph.to_dict() if isinstance(graph, TopologyGraph) else graph
    nodes = payload.get("nodes") or []
    edges = payload.get("edges") or []
    lines = [
        "flowchart LR",
        "%% PortMap-AI metadata-only topology visualization; labels are sanitized.",
    ]
    for node in nodes:
        node_id = _mermaid_id(node.get("node_id"))
        label = _mermaid_label(node.get("label") or node.get("asset_category") or "unknown")
        lines.append(f"  {node_id}[\"{label}\"]")
    for edge in edges:
        source = _mermaid_id(edge.get("source_node_id"))
        target = _mermaid_id(edge.get("target_node_id"))
        label = _mermaid_label(edge.get("service_hint") or edge.get("protocol") or "flow")
        lines.append(f"  {source} -->|{label}| {target}")
    return "\n".join(lines)


def export_graph_cytoscape(graph: TopologyGraph | dict[str, Any]) -> dict[str, Any]:
    payload = graph.to_dict() if isinstance(graph, TopologyGraph) else graph
    nodes = [
        {
            "data": {
                "id": str(node.get("node_id") or ""),
                "label": str(node.get("label") or "unknown"),
                "asset_category": str(node.get("asset_category") or "UNKNOWN"),
                "node_class": str(node.get("node_class") or "unknown"),
                "source_mode": str(node.get("source_mode") or "unknown"),
                "confidence_score": float(node.get("confidence_score") or 0.0),
            }
        }
        for node in payload.get("nodes") or []
        if isinstance(node, dict)
    ]
    edges = [
        {
            "data": {
                "id": str(edge.get("edge_id") or ""),
                "source": str(edge.get("source_node_id") or ""),
                "target": str(edge.get("target_node_id") or ""),
                "relationship_type": str(edge.get("relationship_type") or "flow_observed"),
                "protocol": str(edge.get("protocol") or "unknown"),
                "service_hint": str(edge.get("service_hint") or "unknown"),
                "source_mode": str(edge.get("source_mode") or "unknown"),
                "weight": float(edge.get("weight") or 0.0),
                "confidence_score": float(edge.get("confidence_score") or 0.0),
            }
        }
        for edge in payload.get("edges") or []
        if isinstance(edge, dict)
    ]
    return {
        "format": "cytoscape",
        "elements": {"nodes": nodes, "edges": edges},
        "summary": dict(payload.get("summary") or {}),
        "safety": {
            "metadata_only": True,
            "raw_packet_stored": False,
            "packet_payload_inspected": False,
            "raw_dns_history_stored": False,
            "enforcement_enabled": False,
        },
    }


def export_graph_cytoscape_json(graph: TopologyGraph | dict[str, Any]) -> str:
    return json.dumps(export_graph_cytoscape(graph), sort_keys=True, separators=(",", ":"), default=str)


def _mermaid_id(value: Any) -> str:
    text = str(value or "unknown")
    safe = "".join(char if char.isalnum() else "_" for char in text)
    if not safe or safe[0].isdigit():
        safe = f"node_{safe}"
    return safe[:80]


def _mermaid_label(value: Any) -> str:
    text = str(value or "unknown")
    text = text.replace('"', "'").replace("\n", " ")
    return text[:80]
