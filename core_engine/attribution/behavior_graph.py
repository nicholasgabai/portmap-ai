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
GRAPH_RELATIONSHIP_TYPES = {
    "shared_asset",
    "shared_service",
    "shared_protocol",
    "shared_port",
    "shared_application_candidate",
    "shared_learning_profile",
    "observed_flow_relationship",
    "related_risk_signal",
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
    relationships: dict[str, dict[str, Any]] = {}

    asset_node = _add_node(nodes, "asset_node", related_asset) if related_asset != "-" else None
    service_node = _add_node(nodes, "service_node", related_service) if related_service != "-" else None
    port_node = _add_node(nodes, "port_node", related_port) if related_port != "-" else None
    protocol_node = _add_node(nodes, "protocol_node", related_protocol) if related_protocol != "-" else None
    application_node = (
        _add_node(nodes, "application_node", related_application) if related_application != "-" else None
    )
    profile_node = _add_node(nodes, "profile_node", related_profile) if related_profile != "-" else None
    peer_asset_nodes = [
        _add_node(nodes, "asset_node", label)
        for label in _related_asset_labels(observation, flows)
        if label != related_asset
    ]
    related_service_nodes = [
        _add_node(nodes, "service_node", label)
        for label in _related_service_labels(observation, history)
        if label != related_service
    ]
    application_nodes = [
        _add_node(nodes, "application_node", label)
        for label in _application_candidate_labels(classifier)
        if label != related_application
    ]
    profile_nodes = [
        _add_node(nodes, "profile_node", label)
        for label in _related_profile_labels(observation, history)
        if label != related_profile
    ]

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

    _infer_relationships(
        relationships,
        observation=observation,
        classification_model=classifier,
        asset_node=asset_node,
        service_node=service_node,
        port_node=port_node,
        protocol_node=protocol_node,
        application_node=application_node,
        profile_node=profile_node,
        peer_asset_nodes=peer_asset_nodes,
        related_service_nodes=related_service_nodes,
        application_nodes=application_nodes,
        profile_nodes=profile_nodes,
        flows=flows,
    )

    return _graph_record(
        timestamp=timestamp,
        nodes=sorted(nodes.values(), key=lambda row: (row["node_type"], row["node_id"])),
        edges=sorted(edges.values(), key=lambda row: (row["edge_type"], row["edge_id"])),
        relationships=sorted(
            relationships.values(), key=lambda row: (row["relationship_type"], row["relationship_id"])
        ),
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
    relationships: list[dict[str, Any]] | None = None,
    related: dict[str, str],
) -> dict[str, Any]:
    relationship_rows = relationships or []
    summary = _graph_summary(nodes, edges, relationship_rows, related)
    return {
        "record_type": "graph_behavior_model",
        "record_version": BEHAVIOR_GRAPH_RECORD_VERSION,
        "graph_id": "behavior-graph-" + _digest(
            {
                "nodes": [(row.get("node_type"), row.get("node_id")) for row in nodes],
                "edges": [(row.get("edge_type"), row.get("source_id"), row.get("target_id")) for row in edges],
                "relationships": [
                    (row.get("relationship_type"), row.get("source_id"), row.get("target_id"))
                    for row in relationship_rows
                ],
            }
        )[:16],
        "generated_at": timestamp,
        "nodes": nodes,
        "edges": edges,
        "relationships": relationship_rows,
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


def _graph_summary(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    related: dict[str, str],
) -> dict[str, Any]:
    counts: dict[str, int] = {node_type: 0 for node_type in GRAPH_NODE_TYPES}
    for node in nodes:
        node_type = str(node.get("node_type") or "")
        if node_type in counts:
            counts[node_type] += 1
    strongest = _strongest_relationship(relationships)
    return {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "asset_count": counts["asset_node"],
        "service_count": counts["service_node"],
        "application_count": counts["application_node"],
        "profile_count": counts["profile_node"],
        "relationship_count": len(edges),
        "inferred_relationship_count": len(relationships),
        "strongest_relationship": strongest.get("relationship_id", "-"),
        "strongest_relationship_type": strongest.get("relationship_type", "-"),
        "strongest_relationship_score": strongest.get("strength_score", "-"),
        "related_entity_count": _related_entity_count(relationships),
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


def _add_relationship(
    relationships: dict[str, dict[str, Any]],
    relationship_type: str,
    source: dict[str, Any] | str,
    target: dict[str, Any] | str,
    *,
    evidence: Iterable[Any],
) -> None:
    safe_type = relationship_type if relationship_type in GRAPH_RELATIONSHIP_TYPES else "observed_flow_relationship"
    source_id, source_label = _relationship_endpoint(source)
    target_id, target_label = _relationship_endpoint(target)
    evidence_summary = _unique_text(evidence, limit=8)
    if source_id == "-" or target_id == "-" or not evidence_summary:
        return
    relationship_id = _relationship_id(safe_type, source_id, target_id, evidence_summary)
    relationships.setdefault(
        relationship_id,
        {
            "relationship_id": relationship_id,
            "source_id": source_id,
            "target_id": target_id,
            "source_label": source_label,
            "target_label": target_label,
            "relationship_type": safe_type,
            "strength_score": _relationship_strength(safe_type, evidence_summary),
            "evidence_count": len(evidence_summary),
            "evidence_summary": evidence_summary,
            "metadata_only": True,
        },
    )


def _infer_relationships(
    relationships: dict[str, dict[str, Any]],
    *,
    observation: dict[str, Any],
    classification_model: dict[str, Any],
    asset_node: dict[str, Any] | None,
    service_node: dict[str, Any] | None,
    port_node: dict[str, Any] | None,
    protocol_node: dict[str, Any] | None,
    application_node: dict[str, Any] | None,
    profile_node: dict[str, Any] | None,
    peer_asset_nodes: list[dict[str, Any]],
    related_service_nodes: list[dict[str, Any]],
    application_nodes: list[dict[str, Any]],
    profile_nodes: list[dict[str, Any]],
    flows: Iterable[dict[str, Any]] | None,
) -> None:
    port = _port_label(observation)
    protocol = _protocol_label(observation)
    flow_reference = _flow_reference(observation, flows)
    risk_signals = _risk_signal_values(observation)

    if asset_node and application_node:
        evidence = ["asset_application_context", f"application:{application_node['label']}"]
        if port != "-":
            evidence.append(f"port:{port}")
        if protocol != "-":
            evidence.append(f"protocol:{protocol}")
        _add_relationship(relationships, "shared_application_candidate", asset_node, application_node, evidence=evidence)

    for peer_asset in peer_asset_nodes:
        evidence = ["shared_observation_context"]
        if flow_reference != "-":
            evidence.append(f"flow:{flow_reference}")
        if protocol != "-":
            evidence.append(f"protocol:{protocol}")
        _add_relationship(relationships, "shared_asset", asset_node or "-", peer_asset, evidence=evidence)

    for related_service in related_service_nodes:
        evidence = ["service_context"]
        if port != "-":
            evidence.append(f"port:{port}")
            _add_relationship(relationships, "shared_port", service_node or "-", related_service, evidence=evidence)
        if protocol != "-":
            evidence.append(f"protocol:{protocol}")
            _add_relationship(relationships, "shared_protocol", service_node or "-", related_service, evidence=evidence)
        _add_relationship(relationships, "shared_service", service_node or "-", related_service, evidence=evidence)

    if service_node and port_node and port != "-":
        _add_relationship(relationships, "shared_port", service_node, port_node, evidence=[f"port:{port}"])
    if service_node and protocol_node and protocol != "-":
        _add_relationship(relationships, "shared_protocol", service_node, protocol_node, evidence=[f"protocol:{protocol}"])

    for candidate_node in application_nodes:
        evidence = ["candidate_distribution"]
        probability = _candidate_probability_for_label(classification_model, candidate_node.get("label"))
        if probability != "-":
            evidence.append(f"probability:{probability}")
        _add_relationship(
            relationships,
            "shared_application_candidate",
            application_node or "-",
            candidate_node,
            evidence=evidence,
        )

    for related_profile in profile_nodes:
        _add_relationship(
            relationships,
            "shared_learning_profile",
            profile_node or "-",
            related_profile,
            evidence=["learning_profile_context"],
        )
    if service_node and profile_node:
        _add_relationship(
            relationships,
            "shared_learning_profile",
            service_node,
            profile_node,
            evidence=["service_profile_link"],
        )

    if flow_reference != "-" and service_node:
        flow_id = _flow_entity_id(flow_reference)
        evidence = [f"flow:{flow_reference}"]
        if port != "-":
            evidence.append(f"port:{port}")
        if protocol != "-":
            evidence.append(f"protocol:{protocol}")
        _add_relationship(relationships, "observed_flow_relationship", flow_id, service_node, evidence=evidence)

    if risk_signals and service_node:
        target = application_node or asset_node or service_node
        _add_relationship(
            relationships,
            "related_risk_signal",
            service_node,
            target,
            evidence=[f"risk_signal:{signal}" for signal in risk_signals[:6]],
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


def _related_asset_labels(observation: dict[str, Any], flows: Iterable[dict[str, Any]] | None) -> list[str]:
    labels = _list_text(observation, ("related_assets", "peer_assets", "assets"))
    labels.extend(_list_text(observation, ("peer_asset", "source_asset", "destination_asset", "remote_asset")))
    for flow in flows or []:
        if isinstance(flow, dict):
            labels.extend(_list_text(flow, ("source_asset", "destination_asset", "peer_asset", "node_id")))
    return _unique_text(labels)


def _related_service_labels(observation: dict[str, Any], history: dict[str, Any]) -> list[str]:
    labels = _list_text(observation, ("related_services", "peer_services", "services"))
    if isinstance(history, dict):
        labels.extend(_list_text(history, ("historical_services",)))
    return _unique_text(labels)


def _application_candidate_labels(classification_model: dict[str, Any]) -> list[str]:
    labels = _list_text(classification_model, ("application_candidates", "candidate_applications"))
    candidates = classification_model.get("candidates")
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, dict):
                labels.append(_safe_text(item.get("candidate") or item.get("label")))
            else:
                labels.append(_safe_text(item))
    alternatives = classification_model.get("alternative_candidates")
    if isinstance(alternatives, list):
        for item in alternatives:
            if isinstance(item, dict):
                labels.append(_safe_text(item.get("candidate") or item.get("label")))
            else:
                labels.append(_safe_text(item))
    return _unique_text(labels)


def _related_profile_labels(observation: dict[str, Any], history: dict[str, Any]) -> list[str]:
    labels = _list_text(observation, ("related_profiles", "peer_profiles", "profile_ids"))
    records = history.get("observation_records") if isinstance(history, dict) else None
    if isinstance(records, list):
        for item in records:
            if isinstance(item, dict):
                labels.append(_safe_text(item.get("profile_id")))
    return _unique_text(labels)


def _risk_signal_values(observation: dict[str, Any]) -> list[str]:
    values = _list_text(observation, ("score_factors", "risk_signals", "signals"))
    for key in ("reason", "finding", "risk_signal"):
        value = _safe_text(observation.get(key))
        if value != "-":
            values.append(value)
    return _unique_text(values)


def _list_text(observation: dict[str, Any], keys: tuple[str, ...]) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = observation.get(key)
        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    values.append(_safe_text(item.get("id") or item.get("name") or item.get("value") or item.get("label")))
                else:
                    values.append(_safe_text(item))
        elif isinstance(value, dict):
            values.append(_safe_text(value.get("id") or value.get("name") or value.get("value") or value.get("label")))
        else:
            values.append(_safe_text(value))
    return [value for value in values if value != "-"]


def _candidate_probability_for_label(observation: dict[str, Any], label: Any) -> str:
    target = _safe_text(label)
    candidates = observation.get("candidates")
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, dict) and _safe_text(item.get("candidate") or item.get("label")) == target:
                value = item.get("probability") or item.get("confidence")
                try:
                    return f"{float(value):.2f}"
                except (TypeError, ValueError):
                    return "-"
    return "-"


def _relationship_endpoint(value: dict[str, Any] | str) -> tuple[str, str]:
    if isinstance(value, dict):
        return _safe_text(value.get("node_id")), _safe_text(value.get("label"))
    text = _safe_text(value)
    return text, text


def _relationship_strength(relationship_type: str, evidence_summary: list[str]) -> float:
    base = 0.24 if relationship_type in {"shared_port", "shared_protocol"} else 0.30
    if relationship_type in {"observed_flow_relationship", "related_risk_signal"}:
        base = 0.36
    if relationship_type in {"shared_learning_profile", "shared_application_candidate"}:
        base = 0.34
    score = base + (0.16 * min(len(evidence_summary), 4))
    if any(str(item).startswith(("flow:", "risk_signal:", "probability:")) for item in evidence_summary):
        score += 0.08
    return round(min(max(score, 0.0), 1.0), 2)


def _strongest_relationship(relationships: list[dict[str, Any]]) -> dict[str, Any]:
    if not relationships:
        return {}
    return sorted(
        relationships,
        key=lambda row: (
            -float(row.get("strength_score") or 0.0),
            str(row.get("relationship_type") or ""),
            str(row.get("relationship_id") or ""),
        ),
    )[0]


def _related_entity_count(relationships: list[dict[str, Any]]) -> int:
    entity_ids = set()
    for row in relationships:
        for key in ("source_id", "target_id"):
            value = _safe_text(row.get(key))
            if value != "-":
                entity_ids.add(value)
    return len(entity_ids)


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


def _unique_text(values: Iterable[Any], *, limit: int = 24) -> list[str]:
    rows = []
    seen = set()
    for value in values:
        text = _safe_text(value)
        if text == "-" or text in seen:
            continue
        seen.add(text)
        rows.append(text)
        if len(rows) >= limit:
            break
    return rows


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


def _relationship_id(relationship_type: str, source_id: str, target_id: str, evidence: list[str]) -> str:
    return "graph-rel-" + relationship_type + "-" + _digest(
        {
            "type": relationship_type,
            "source": source_id,
            "target": target_id,
            "evidence": evidence,
        }
    )[:16]


def _flow_entity_id(flow_reference: str) -> str:
    return "graph-flow-" + _digest({"flow": flow_reference})[:16]


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
