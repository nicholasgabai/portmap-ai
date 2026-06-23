from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.attribution.confidence_models import ATTRIBUTION_SAFETY_FLAGS


BEHAVIOR_GRAPH_RECORD_VERSION = 1
GRAPH_NODE_TYPES = {
    "asset_node",
    "service_node",
    "port_node",
    "protocol_node",
    "application_node",
    "profile_node",
}
GRAPH_EDGE_TYPES = {
    "asset_exposes_service",
    "service_uses_port",
    "service_uses_protocol",
    "service_classified_as_application",
    "service_linked_to_profile",
    "asset_observed_flow",
}


def build_behavior_graph_model(
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    learning_profile: dict[str, Any] | None = None,
    learning_profile_history: dict[str, Any] | None = None,
    flows: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic metadata-only behavior graph for one observed service."""
    timestamp = generated_at or _now()
    if not isinstance(observation, dict) or not observation:
        return _graph_record(timestamp=timestamp, nodes=[], edges=[], related={})

    classifier = classification_model if isinstance(classification_model, dict) else {}
    profile = learning_profile if isinstance(learning_profile, dict) else {}
    history = learning_profile_history if isinstance(learning_profile_history, dict) else {}

    related_asset = _asset_label(observation)
    related_service = _service_label(observation, classifier)
    related_port = _port_label(observation)
    related_protocol = _protocol_label(observation)
    related_application = _application_label(classifier)
    related_profile = _profile_label(profile, history)

    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[str, dict[str, Any]] = {}

    asset_node = _add_node(nodes, "asset_node", related_asset) if related_asset != "-" else None
    service_node = _add_node(nodes, "service_node", related_service) if related_service != "-" else None
    port_node = _add_node(nodes, "port_node", related_port) if related_port != "-" else None
    protocol_node = _add_node(nodes, "protocol_node", related_protocol) if related_protocol != "-" else None
    application_node = (
        _add_node(nodes, "application_node", related_application) if related_application != "-" else None
    )
    profile_node = _add_node(nodes, "profile_node", related_profile) if related_profile != "-" else None

    if asset_node and service_node:
        _add_edge(edges, "asset_exposes_service", asset_node, service_node)
    if service_node and port_node:
        _add_edge(edges, "service_uses_port", service_node, port_node)
    if service_node and protocol_node:
        _add_edge(edges, "service_uses_protocol", service_node, protocol_node)
    if service_node and application_node:
        _add_edge(edges, "service_classified_as_application", service_node, application_node)
    if service_node and profile_node:
        _add_edge(edges, "service_linked_to_profile", service_node, profile_node)
    if asset_node and service_node and _has_flow_metadata(observation, flows):
        _add_edge(
            edges,
            "asset_observed_flow",
            asset_node,
            service_node,
            metadata={"flow_reference": _flow_reference(observation, flows)},
        )
    for finding in findings or []:
        if isinstance(finding, dict) and asset_node and service_node and _finding_matches_observation(finding, observation):
            _add_edge(
                edges,
                "asset_observed_flow",
                asset_node,
                service_node,
                metadata={"flow_reference": _safe_text(finding.get("finding") or finding.get("reason") or "finding")},
            )

    return _graph_record(
        timestamp=timestamp,
        nodes=sorted(nodes.values(), key=lambda row: (row["node_type"], row["node_id"])),
        edges=sorted(edges.values(), key=lambda row: (row["edge_type"], row["edge_id"])),
        related={
            "related_asset": related_asset,
            "related_service": related_service,
            "related_profile": related_profile,
        },
    )


def deterministic_behavior_graph_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _graph_record(
    *,
    timestamp: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    related: dict[str, str],
) -> dict[str, Any]:
    summary = _graph_summary(nodes, edges, related)
    return {
        "record_type": "graph_behavior_model",
        "record_version": BEHAVIOR_GRAPH_RECORD_VERSION,
        "graph_id": "behavior-graph-" + _digest(
            {
                "nodes": [(row.get("node_type"), row.get("node_id")) for row in nodes],
                "edges": [(row.get("edge_type"), row.get("source_id"), row.get("target_id")) for row in edges],
            }
        )[:16],
        "generated_at": timestamp,
        "nodes": nodes,
        "edges": edges,
        "summary": summary,
        "metadata_only": True,
        "read_only": True,
        "training_performed": False,
        "inference_executed": False,
        "automated_action": False,
        "enforcement_enabled": False,
        "external_connectivity": False,
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def _graph_summary(nodes: list[dict[str, Any]], edges: list[dict[str, Any]], related: dict[str, str]) -> dict[str, Any]:
    counts: dict[str, int] = {node_type: 0 for node_type in GRAPH_NODE_TYPES}
    for node in nodes:
        node_type = str(node.get("node_type") or "")
        if node_type in counts:
            counts[node_type] += 1
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "asset_count": counts["asset_node"],
        "service_count": counts["service_node"],
        "application_count": counts["application_node"],
        "profile_count": counts["profile_node"],
        "relationship_count": len(edges),
        "related_asset": related.get("related_asset") or "-",
        "related_service": related.get("related_service") or "-",
        "related_profile": related.get("related_profile") or "-",
    }


def _add_node(nodes: dict[str, dict[str, Any]], node_type: str, label: str) -> dict[str, Any]:
    safe_type = node_type if node_type in GRAPH_NODE_TYPES else "service_node"
    safe_label = _safe_text(label)
    node_id = _node_id(safe_type, safe_label)
    nodes.setdefault(
        node_id,
        {
            "node_id": node_id,
            "node_type": safe_type,
            "label": safe_label,
            "metadata_only": True,
        },
    )
    return nodes[node_id]


def _add_edge(
    edges: dict[str, dict[str, Any]],
    edge_type: str,
    source: dict[str, Any],
    target: dict[str, Any],
    *,
    metadata: dict[str, Any] | None = None,
) -> None:
    safe_type = edge_type if edge_type in GRAPH_EDGE_TYPES else "asset_observed_flow"
    edge_id = _edge_id(safe_type, str(source.get("node_id") or ""), str(target.get("node_id") or ""), metadata)
    edges.setdefault(
        edge_id,
        {
            "edge_id": edge_id,
            "edge_type": safe_type,
            "source_id": source.get("node_id"),
            "target_id": target.get("node_id"),
            "metadata": _safe_metadata(metadata or {}),
            "metadata_only": True,
        },
    )


def _asset_label(observation: dict[str, Any]) -> str:
    return _first_text(
        observation,
        ("node_id", "asset_id", "asset", "host", "hostname", "observed_entity_reference", "source_node"),
    )


def _service_label(observation: dict[str, Any], classification_model: dict[str, Any]) -> str:
    service = _first_text(observation, ("service_name", "service", "service_hint", "program", "process", "process_hint"))
    if service != "-":
        return service
    application = _application_label(classification_model)
    if application != "-":
        return application
    port = _port_label(observation)
    protocol = _protocol_label(observation)
    if port != "-" or protocol != "-":
        return f"{protocol}/{port}".strip("/").lower()
    return "-"


def _port_label(observation: dict[str, Any]) -> str:
    for key in ("port", "service_port", "dst_port", "destination_port", "local_port"):
        value = observation.get(key)
        try:
            if value not in {"", "-", None}:
                return str(int(value))
        except (TypeError, ValueError):
            continue
    return "-"


def _protocol_label(observation: dict[str, Any]) -> str:
    return _first_text(observation, ("protocol", "protocol_hint", "transport", "application_protocol")).lower()


def _application_label(classification_model: dict[str, Any]) -> str:
    return _safe_text(classification_model.get("top_classification") or classification_model.get("candidate_app_class"))


def _profile_label(profile: dict[str, Any], history: dict[str, Any]) -> str:
    return _safe_text(profile.get("profile_id") or history.get("profile_id"))


def _first_text(observation: dict[str, Any], keys: tuple[str, ...]) -> str:
    for key in keys:
        value = observation.get(key)
        if isinstance(value, dict):
            value = value.get("id") or value.get("name") or value.get("value") or value.get("label")
        if isinstance(value, list):
            value = next((item for item in value if item not in {"", "-", None}), None)
        text = _safe_text(value)
        if text != "-":
            return text
    return "-"


def _has_flow_metadata(observation: dict[str, Any], flows: Iterable[dict[str, Any]] | None) -> bool:
    return _flow_reference(observation, flows) != "-"


def _flow_reference(observation: dict[str, Any], flows: Iterable[dict[str, Any]] | None) -> str:
    own_reference = _first_text(
        observation,
        (
            "flow_id",
            "flow_key",
            "flow",
            "relationship_state",
            "session_state",
            "remote_address",
            "destination",
            "dst",
            "peer",
        ),
    )
    if own_reference != "-":
        return own_reference
    for flow in flows or []:
        if not isinstance(flow, dict):
            continue
        reference = _first_text(flow, ("flow_id", "flow_key", "source", "destination", "dst", "peer"))
        if reference != "-":
            return reference
    return "-"


def _finding_matches_observation(finding: dict[str, Any], observation: dict[str, Any]) -> bool:
    finding_port = _port_label(finding)
    observation_port = _port_label(observation)
    if finding_port != "-" and observation_port != "-" and finding_port == observation_port:
        return True
    finding_service = _first_text(finding, ("service_name", "service", "program"))
    observation_service = _first_text(observation, ("service_name", "service", "program"))
    return finding_service != "-" and observation_service != "-" and finding_service == observation_service


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, str]:
    return {str(key): _safe_text(value) for key, value in sorted(metadata.items()) if _safe_text(value) != "-"}


def _safe_text(value: Any, *, limit: int = 96) -> str:
    if value in {"", "-", None}:
        return "-"
    text = " ".join(str(value).replace("\n", " ").replace("\r", " ").split())
    return text[:limit] if text else "-"


def _node_id(node_type: str, label: str) -> str:
    return "graph-node-" + node_type.replace("_node", "") + "-" + _digest({"type": node_type, "label": label})[:16]


def _edge_id(edge_type: str, source_id: str, target_id: str, metadata: dict[str, Any] | None) -> str:
    return "graph-edge-" + edge_type + "-" + _digest(
        {
            "type": edge_type,
            "source": source_id,
            "target": target_id,
            "metadata": _safe_metadata(metadata or {}),
        }
    )[:16]


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
