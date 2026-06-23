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
GRAPH_CLUSTER_TYPES = {
    "asset_cluster",
    "service_cluster",
    "application_cluster",
    "profile_cluster",
    "risk_signal_cluster",
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
    node_rows = sorted(nodes.values(), key=lambda row: (row["node_type"], row["node_id"]))
    edge_rows = sorted(edges.values(), key=lambda row: (row["edge_type"], row["edge_id"]))
    relationship_rows = sorted(
        relationships.values(), key=lambda row: (row["relationship_type"], row["relationship_id"])
    )
    cluster_rows = _build_behavior_clusters(
        node_rows,
        edge_rows,
        relationship_rows,
        context=_cluster_context(observation, classifier, profile, history, generated_at=generated_at),
    )

    return _graph_record(
        timestamp=timestamp,
        nodes=node_rows,
        edges=edge_rows,
        relationships=relationship_rows,
        clusters=cluster_rows,
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
    clusters: list[dict[str, Any]] | None = None,
    related: dict[str, str],
) -> dict[str, Any]:
    relationship_rows = relationships or []
    cluster_rows = clusters or []
    summary = _graph_summary(nodes, edges, relationship_rows, cluster_rows, related)
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
                "clusters": [(row.get("cluster_type"), row.get("cluster_id")) for row in cluster_rows],
            }
        )[:16],
        "generated_at": timestamp,
        "nodes": nodes,
        "edges": edges,
        "relationships": relationship_rows,
        "clusters": cluster_rows,
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
    clusters: list[dict[str, Any]],
    related: dict[str, str],
) -> dict[str, Any]:
    counts: dict[str, int] = {node_type: 0 for node_type in GRAPH_NODE_TYPES}
    for node in nodes:
        node_type = str(node.get("node_type") or "")
        if node_type in counts:
            counts[node_type] += 1
    strongest = _strongest_relationship(relationships)
    strongest_cluster = _strongest_cluster(clusters)
    primary = _primary_cluster(clusters)
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
        "cluster_count": len(clusters),
        "strongest_cluster": strongest_cluster.get("cluster_id", "-"),
        "strongest_cluster_type": strongest_cluster.get("cluster_type", "-"),
        "strongest_cluster_score": strongest_cluster.get("confidence_score", "-"),
        "primary_cluster": primary.get("cluster_id", "-"),
        "primary_cluster_type": primary.get("cluster_type", "-"),
        "primary_cluster_risk": primary.get("cluster_risk_level", "-"),
        "primary_cluster_confidence": primary.get("cluster_confidence", "-"),
        "primary_cluster_reason": primary.get("primary_reason", "-"),
        "primary_cluster_trend": primary.get("cluster_trend", "-"),
        "primary_cluster_age": primary.get("cluster_age", "-"),
        "primary_cluster_evolution_score": primary.get("cluster_evolution_score", "-"),
        "primary_cluster_new_relationships": primary.get("new_relationships", "-"),
        "primary_cluster_lost_relationships": primary.get("lost_relationships", "-"),
        "primary_cluster_new_signals": primary.get("new_signals", "-"),
        "primary_cluster_lost_signals": primary.get("lost_signals", "-"),
        "primary_cluster_evolution_summary": primary.get("evolution_summary", "-"),
        "primary_cluster_trend_summary": primary.get("trend_summary", "-"),
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


def _build_behavior_clusters(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    *,
    context: dict[str, Any],
) -> list[dict[str, Any]]:
    clusters = [
        _cluster_for(
            "asset_cluster",
            nodes,
            edges,
            relationships,
            context=context,
            node_types={"asset_node"},
            relationship_types={"shared_asset"},
        ),
        _cluster_for(
            "service_cluster",
            nodes,
            edges,
            relationships,
            context=context,
            node_types={"service_node", "port_node", "protocol_node"},
            relationship_types={
                "shared_service",
                "shared_protocol",
                "shared_port",
                "observed_flow_relationship",
            },
        ),
        _cluster_for(
            "application_cluster",
            nodes,
            edges,
            relationships,
            context=context,
            node_types={"application_node"},
            relationship_types={"shared_application_candidate"},
        ),
        _cluster_for(
            "profile_cluster",
            nodes,
            edges,
            relationships,
            context=context,
            node_types={"profile_node"},
            relationship_types={"shared_learning_profile"},
        ),
        _cluster_for(
            "risk_signal_cluster",
            nodes,
            edges,
            relationships,
            context=context,
            node_types=set(),
            relationship_types={"related_risk_signal"},
        ),
    ]
    return sorted(
        [cluster for cluster in clusters if cluster is not None],
        key=lambda row: (row["cluster_type"], row["cluster_id"]),
    )


def _cluster_for(
    cluster_type: str,
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    *,
    context: dict[str, Any],
    node_types: set[str],
    relationship_types: set[str],
) -> dict[str, Any] | None:
    safe_type = cluster_type if cluster_type in GRAPH_CLUSTER_TYPES else "service_cluster"
    matching_nodes = [row for row in nodes if str(row.get("node_type") or "") in node_types]
    matching_relationships = [
        row for row in relationships if str(row.get("relationship_type") or "") in relationship_types
    ]
    member_ids = {str(row.get("node_id") or "") for row in matching_nodes if row.get("node_id")}
    member_labels = {str(row.get("label") or "") for row in matching_nodes if row.get("label")}
    for relationship in matching_relationships:
        for key in ("source_id", "target_id"):
            value = str(relationship.get(key) or "")
            if value:
                member_ids.add(value)
        for key in ("source_label", "target_label"):
            value = str(relationship.get(key) or "")
            if value:
                member_labels.add(value)
    cluster_edges = [
        row
        for row in edges
        if str(row.get("source_id") or "") in member_ids or str(row.get("target_id") or "") in member_ids
    ]
    if not member_ids and not matching_relationships:
        return None
    strongest_relationship = _strongest_relationship(matching_relationships)
    confidence = _cluster_confidence(matching_relationships, cluster_edges, len(member_ids))
    evidence = _cluster_evidence(matching_relationships, cluster_edges, member_labels)
    analysis = _cluster_analysis(
        safe_type,
        matching_relationships,
        cluster_edges,
        member_count=len(member_ids),
        confidence_score=confidence,
        context=context,
    )
    evolution = _cluster_evolution(
        safe_type,
        matching_relationships,
        member_count=len(member_ids),
        cluster_confidence=analysis["cluster_confidence"],
        context=context,
    )
    cluster_id = _cluster_id(
        safe_type,
        sorted(member_ids),
        [(row.get("relationship_type"), row.get("relationship_id")) for row in matching_relationships],
    )
    return {
        "cluster_id": cluster_id,
        "cluster_type": safe_type,
        "member_count": len(member_ids),
        "relationship_count": len(matching_relationships),
        "strongest_member": _cluster_strongest_member(strongest_relationship, member_labels),
        "strongest_relationship_type": strongest_relationship.get("relationship_type", "-"),
        "confidence_score": confidence,
        "cluster_risk_level": analysis["cluster_risk_level"],
        "cluster_confidence": analysis["cluster_confidence"],
        "cluster_stability": analysis["cluster_stability"],
        "cluster_drift": analysis["cluster_drift"],
        "primary_reason": analysis["primary_reason"],
        "cluster_first_seen": evolution["cluster_first_seen"],
        "cluster_last_seen": evolution["cluster_last_seen"],
        "cluster_age": evolution["cluster_age"],
        "cluster_trend": evolution["cluster_trend"],
        "cluster_evolution_score": evolution["cluster_evolution_score"],
        "new_relationships": evolution["new_relationships"],
        "lost_relationships": evolution["lost_relationships"],
        "new_signals": evolution["new_signals"],
        "lost_signals": evolution["lost_signals"],
        "evolution_summary": evolution["evolution_summary"],
        "trend_summary": evolution["trend_summary"],
        "evidence_summary": _unique_text([*analysis["evidence_summary"], *evidence], limit=10),
        "metadata_only": True,
    }


def _cluster_context(
    observation: dict[str, Any],
    classification_model: dict[str, Any],
    learning_profile: dict[str, Any],
    learning_profile_history: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    history_summary = learning_profile_history.get("historical_summary")
    if not isinstance(history_summary, dict):
        history_summary = {}
    risk_signals = _risk_signal_values(observation)
    first_seen = _first_temporal_value(observation, learning_profile_history, generated_at=generated_at)
    last_seen = _last_temporal_value(observation, learning_profile_history, generated_at=generated_at)
    previous_confidence = _optional_float(
        _first_present_value(
            observation.get("previous_confidence"),
            observation.get("historical_confidence"),
            history_summary.get("confidence_first"),
        )
    )
    candidate_confidence = _safe_float(
        classification_model.get("confidence") or classification_model.get("confidence_score")
    )
    return {
        "risk_score": _safe_float(
            observation.get("risk_score")
            or observation.get("score")
            or observation.get("confidence")
            or history_summary.get("risk_score")
        ),
        "risk_signals": risk_signals,
        "profile_stability": _safe_float(
            history_summary.get("stability_score") or learning_profile.get("stability_score")
        ),
        "profile_stability_label": _safe_text(
            history_summary.get("stability_label") or learning_profile.get("stability_label")
        ),
        "drift_score": _safe_float(history_summary.get("drift_score") or learning_profile_history.get("drift_score")),
        "drift_label": _safe_text(history_summary.get("drift_label") or learning_profile_history.get("drift_label")),
        "observation_count": _safe_int_value(
            history_summary.get("historical_observations")
            or learning_profile_history.get("observation_count")
            or learning_profile.get("observation_count")
            or observation.get("count")
        ),
        "candidate_confidence": candidate_confidence,
        "previous_confidence": previous_confidence,
        "confidence_change": _confidence_change(candidate_confidence, previous_confidence, history_summary),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "has_temporal_metadata": first_seen != "-" or last_seen != "-",
        "previous_relationship_count": _optional_int(
            _first_present_value(
                observation.get("previous_relationship_count"),
                observation.get("prior_relationship_count"),
                observation.get("historical_relationship_count"),
                history_summary.get("previous_relationship_count"),
            )
        ),
        "previous_signal_count": _optional_int(
            _first_present_value(
                observation.get("previous_signal_count"),
                observation.get("prior_signal_count"),
                observation.get("historical_signal_count"),
                history_summary.get("previous_signal_count"),
            )
        ),
        "previous_entity_count": _optional_int(
            _first_present_value(
                observation.get("previous_entity_count"),
                observation.get("prior_entity_count"),
                observation.get("historical_entity_count"),
                history_summary.get("previous_entity_count"),
            )
        ),
        "signal_count": len(risk_signals),
    }


def _cluster_analysis(
    cluster_type: str,
    relationships: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    member_count: int,
    confidence_score: float,
    context: dict[str, Any],
) -> dict[str, Any]:
    relationship_scores = [float(row.get("strength_score") or 0.0) for row in relationships]
    max_relationship = max(relationship_scores, default=0.0)
    risk_score = float(context.get("risk_score") or 0.0)
    drift_score = float(context.get("drift_score") or 0.0)
    profile_stability = float(context.get("profile_stability") or 0.0)
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    risk_signal_count = len(context.get("risk_signals") or [])

    cluster_confidence = _cluster_analysis_confidence(
        confidence_score=confidence_score,
        relationship_count=len(relationships),
        member_count=member_count,
        candidate_confidence=candidate_confidence,
        profile_stability=profile_stability,
    )
    cluster_stability = _cluster_stability_label(
        observation_count=int(context.get("observation_count") or 0),
        profile_stability=profile_stability,
        relationship_count=len(relationships),
        member_count=member_count,
    )
    cluster_drift = _cluster_drift_label(drift_score, context.get("drift_label"))
    risk_level = _cluster_risk_level(
        cluster_type=cluster_type,
        risk_score=risk_score,
        max_relationship=max_relationship,
        drift_score=drift_score,
        risk_signal_count=risk_signal_count,
        cluster_stability=cluster_stability,
    )
    primary_reason = _cluster_primary_reason(
        cluster_type=cluster_type,
        risk_level=risk_level,
        risk_score=risk_score,
        max_relationship=max_relationship,
        drift_score=drift_score,
        risk_signal_count=risk_signal_count,
        cluster_stability=cluster_stability,
    )
    evidence = _cluster_analysis_evidence(
        cluster_type=cluster_type,
        risk_score=risk_score,
        max_relationship=max_relationship,
        drift_score=drift_score,
        profile_stability=profile_stability,
        observation_count=int(context.get("observation_count") or 0),
        candidate_confidence=candidate_confidence,
        risk_signal_count=risk_signal_count,
        edge_count=len(edges),
        relationship_count=len(relationships),
    )
    return {
        "cluster_risk_level": risk_level,
        "cluster_confidence": cluster_confidence,
        "cluster_stability": cluster_stability,
        "cluster_drift": cluster_drift,
        "primary_reason": primary_reason,
        "evidence_summary": evidence,
    }


def _cluster_evolution(
    cluster_type: str,
    relationships: list[dict[str, Any]],
    *,
    member_count: int,
    cluster_confidence: float,
    context: dict[str, Any],
) -> dict[str, Any]:
    first_seen = _safe_text(context.get("first_seen"))
    last_seen = _safe_text(context.get("last_seen"))
    has_temporal = bool(context.get("has_temporal_metadata"))
    current_relationships = len(relationships)
    current_signals = int(context.get("signal_count") or 0)
    previous_relationships = context.get("previous_relationship_count")
    previous_signals = context.get("previous_signal_count")
    previous_entities = context.get("previous_entity_count")
    new_relationships, lost_relationships = _delta_pair(current_relationships, previous_relationships)
    new_signals, lost_signals = _delta_pair(current_signals, previous_signals)
    new_entities, lost_entities = _delta_pair(member_count, previous_entities)
    confidence_change = abs(float(context.get("confidence_change") or 0.0))
    drift_score = float(context.get("drift_score") or 0.0)

    trend = _cluster_trend(
        has_temporal=has_temporal,
        current_relationships=current_relationships,
        current_signals=current_signals,
        previous_relationships=previous_relationships,
        previous_signals=previous_signals,
        previous_entities=previous_entities,
        new_relationships=new_relationships,
        lost_relationships=lost_relationships,
        new_signals=new_signals,
        lost_signals=lost_signals,
        new_entities=new_entities,
        lost_entities=lost_entities,
        first_seen=first_seen,
        last_seen=last_seen,
    )
    if trend == "emerging":
        new_relationships = current_relationships
        new_signals = current_signals
        new_entities = member_count
    evolution_score = _cluster_evolution_score(
        new_relationships=new_relationships,
        lost_relationships=lost_relationships,
        new_signals=new_signals,
        lost_signals=lost_signals,
        new_entities=new_entities,
        lost_entities=lost_entities,
        confidence_change=confidence_change,
        drift_score=drift_score,
        cluster_confidence=cluster_confidence,
    )
    age = _duration_label(first_seen, last_seen)
    evolution_summary = _cluster_evolution_summary(
        cluster_type=cluster_type,
        trend=trend,
        relationship_delta=new_relationships - lost_relationships,
        signal_delta=new_signals - lost_signals,
        entity_delta=new_entities - lost_entities,
    )
    trend_summary = _cluster_trend_summary(
        trend=trend,
        age=age,
        evolution_score=evolution_score,
        current_relationships=current_relationships,
        current_signals=current_signals,
    )
    return {
        "cluster_first_seen": first_seen,
        "cluster_last_seen": last_seen,
        "cluster_age": age,
        "cluster_trend": trend,
        "cluster_evolution_score": evolution_score,
        "new_relationships": new_relationships,
        "lost_relationships": lost_relationships,
        "new_signals": new_signals,
        "lost_signals": lost_signals,
        "evolution_summary": evolution_summary,
        "trend_summary": trend_summary,
    }


def _cluster_trend(
    *,
    has_temporal: bool,
    current_relationships: int,
    current_signals: int,
    previous_relationships: int | None,
    previous_signals: int | None,
    previous_entities: int | None,
    new_relationships: int,
    lost_relationships: int,
    new_signals: int,
    lost_signals: int,
    new_entities: int,
    lost_entities: int,
    first_seen: str,
    last_seen: str,
) -> str:
    if not has_temporal:
        return "unknown"
    if current_relationships == 0 and current_signals == 0 and first_seen != "-" and last_seen != "-" and first_seen != last_seen:
        return "dormant"
    has_previous = previous_relationships is not None or previous_signals is not None or previous_entities is not None
    if has_previous:
        if new_relationships or new_signals or new_entities:
            return "growing"
        if lost_relationships or lost_signals or lost_entities:
            return "shrinking"
        return "stable"
    if current_relationships or current_signals:
        return "emerging"
    return "unknown"


def _cluster_evolution_score(
    *,
    new_relationships: int,
    lost_relationships: int,
    new_signals: int,
    lost_signals: int,
    new_entities: int,
    lost_entities: int,
    confidence_change: float,
    drift_score: float,
    cluster_confidence: float,
) -> float:
    relationship_change = min(new_relationships + lost_relationships, 6) / 6.0
    signal_change = min(new_signals + lost_signals, 6) / 6.0
    entity_change = min(new_entities + lost_entities, 6) / 6.0
    score = (
        relationship_change * 0.30
        + signal_change * 0.20
        + entity_change * 0.15
        + min(confidence_change, 1.0) * 0.15
        + min(drift_score, 1.0) * 0.12
        + min(cluster_confidence, 1.0) * 0.08
    )
    return round(min(max(score, 0.0), 1.0), 2)


def _cluster_evolution_summary(
    *,
    cluster_type: str,
    trend: str,
    relationship_delta: int,
    signal_delta: int,
    entity_delta: int,
) -> str:
    return (
        f"{cluster_type}:{trend}; "
        f"relationships:{relationship_delta:+d}; "
        f"signals:{signal_delta:+d}; "
        f"entities:{entity_delta:+d}"
    )


def _cluster_trend_summary(
    *,
    trend: str,
    age: str,
    evolution_score: float,
    current_relationships: int,
    current_signals: int,
) -> str:
    return (
        f"trend:{trend}; age:{age}; evolution:{evolution_score:.2f}; "
        f"relationships:{current_relationships}; signals:{current_signals}"
    )


def _cluster_analysis_confidence(
    *,
    confidence_score: float,
    relationship_count: int,
    member_count: int,
    candidate_confidence: float,
    profile_stability: float,
) -> float:
    support = min(relationship_count / max(member_count, 1), 1.0)
    confidence = (confidence_score * 0.58) + (candidate_confidence * 0.18) + (profile_stability * 0.14) + (support * 0.10)
    return round(min(max(confidence, 0.0), 1.0), 2)


def _cluster_stability_label(
    *,
    observation_count: int,
    profile_stability: float,
    relationship_count: int,
    member_count: int,
) -> str:
    if observation_count <= 1 and relationship_count <= 1:
        return "sparse"
    if profile_stability >= 0.70 and relationship_count >= 2:
        return "stable"
    if profile_stability > 0 and profile_stability <= 0.35:
        return "unstable"
    if member_count <= 1 or relationship_count == 0:
        return "sparse"
    return "unknown"


def _cluster_drift_label(drift_score: float, drift_label: Any) -> str:
    label = _safe_text(drift_label).lower()
    if label in {"none", "low", "medium", "high"}:
        return label
    if drift_score >= 0.70:
        return "high"
    if drift_score >= 0.45:
        return "medium"
    if drift_score >= 0.18:
        return "low"
    return "none"


def _cluster_risk_level(
    *,
    cluster_type: str,
    risk_score: float,
    max_relationship: float,
    drift_score: float,
    risk_signal_count: int,
    cluster_stability: str,
) -> str:
    risk = (risk_score * 0.46) + (max_relationship * 0.26) + (drift_score * 0.18)
    if cluster_type == "risk_signal_cluster":
        risk += min(risk_signal_count, 4) * 0.09
    elif risk_signal_count:
        risk += min(risk_signal_count, 3) * 0.04
    if cluster_stability == "stable":
        risk -= 0.08
    elif cluster_stability == "unstable":
        risk += 0.08
    risk = min(max(risk, 0.0), 1.0)
    if risk >= 0.82:
        return "critical"
    if risk >= 0.62:
        return "high"
    if risk >= 0.35:
        return "medium"
    return "low"


def _cluster_primary_reason(
    *,
    cluster_type: str,
    risk_level: str,
    risk_score: float,
    max_relationship: float,
    drift_score: float,
    risk_signal_count: int,
    cluster_stability: str,
) -> str:
    if risk_signal_count and cluster_type == "risk_signal_cluster":
        return f"{risk_level}_risk_from_{risk_signal_count}_risk_signals"
    if drift_score >= 0.45:
        return f"{risk_level}_risk_from_profile_drift"
    if risk_score >= 0.60:
        return f"{risk_level}_risk_from_service_score"
    if max_relationship >= 0.80:
        return f"{risk_level}_risk_from_strong_relationship"
    if cluster_stability == "sparse":
        return f"{risk_level}_risk_from_sparse_observations"
    return f"{risk_level}_risk_from_cluster_context"


def _cluster_analysis_evidence(
    *,
    cluster_type: str,
    risk_score: float,
    max_relationship: float,
    drift_score: float,
    profile_stability: float,
    observation_count: int,
    candidate_confidence: float,
    risk_signal_count: int,
    edge_count: int,
    relationship_count: int,
) -> list[str]:
    return _unique_text(
        [
            f"cluster_type:{cluster_type}",
            f"risk_score:{risk_score:.2f}",
            f"max_relationship:{max_relationship:.2f}",
            f"drift_score:{drift_score:.2f}",
            f"profile_stability:{profile_stability:.2f}",
            f"observations:{observation_count}",
            f"candidate_confidence:{candidate_confidence:.2f}",
            f"risk_signals:{risk_signal_count}",
            f"edges:{edge_count}",
            f"relationships:{relationship_count}",
        ],
        limit=10,
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


def _first_temporal_value(
    observation: dict[str, Any],
    learning_profile_history: dict[str, Any],
    *,
    generated_at: str | None,
) -> str:
    return _safe_time_text(
        observation.get("first_seen")
        or observation.get("first_observed")
        or learning_profile_history.get("first_observed")
        or learning_profile_history.get("first_seen")
        or _first_observation_record_time(learning_profile_history)
        or observation.get("timestamp")
        or observation.get("generated_at")
        or generated_at
    )


def _last_temporal_value(
    observation: dict[str, Any],
    learning_profile_history: dict[str, Any],
    *,
    generated_at: str | None,
) -> str:
    return _safe_time_text(
        observation.get("last_seen")
        or observation.get("last_observed")
        or observation.get("timestamp")
        or observation.get("generated_at")
        or learning_profile_history.get("last_observed")
        or learning_profile_history.get("last_seen")
        or _last_observation_record_time(learning_profile_history)
        or generated_at
    )


def _first_observation_record_time(learning_profile_history: dict[str, Any]) -> Any:
    records = learning_profile_history.get("observation_records")
    if not isinstance(records, list):
        return None
    times = [_safe_time_text(row.get("observed_at") or row.get("timestamp")) for row in records if isinstance(row, dict)]
    rows = [time for time in times if time != "-"]
    return rows[0] if rows else None


def _last_observation_record_time(learning_profile_history: dict[str, Any]) -> Any:
    records = learning_profile_history.get("observation_records")
    if not isinstance(records, list):
        return None
    times = [_safe_time_text(row.get("observed_at") or row.get("timestamp")) for row in records if isinstance(row, dict)]
    rows = [time for time in times if time != "-"]
    return rows[-1] if rows else None


def _safe_time_text(value: Any) -> str:
    if value in {"", "-", None}:
        return "-"
    parsed = _parse_time(value)
    if parsed is None:
        return _safe_text(value, limit=48)
    return parsed.isoformat()


def _duration_label(first_seen: str, last_seen: str) -> str:
    first = _parse_time(first_seen)
    last = _parse_time(last_seen)
    if first is None or last is None:
        return "-"
    seconds = max(int((last - first).total_seconds()), 0)
    if seconds < 60:
        return "0m"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h"
    days = hours // 24
    return f"{days}d"


def _parse_time(value: Any) -> datetime | None:
    if value in {"", "-", None}:
        return None
    if isinstance(value, (int, float)):
        try:
            timestamp = float(value)
            if timestamp > 10_000_000_000:
                timestamp = timestamp / 1000.0
            return datetime.fromtimestamp(timestamp, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed
    except ValueError:
        return None


def _delta_pair(current: int, previous: int | None) -> tuple[int, int]:
    if previous is None:
        return 0, 0
    delta = int(current) - int(previous)
    return max(delta, 0), max(-delta, 0)


def _optional_int(value: Any) -> int | None:
    if value in {"", "-", None}:
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _optional_float(value: Any) -> float | None:
    if value in {"", "-", None}:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _first_present_value(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and value.strip() in {"", "-"}:
            continue
        return value
    return None


def _confidence_change(current: float, previous: float | None, history_summary: dict[str, Any]) -> float:
    explicit = _optional_float(history_summary.get("confidence_delta"))
    if explicit is not None:
        return abs(explicit)
    if previous is None:
        return 0.0
    return abs(current - previous)


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


def _strongest_cluster(clusters: list[dict[str, Any]]) -> dict[str, Any]:
    if not clusters:
        return {}
    return sorted(
        clusters,
        key=lambda row: (
            -float(row.get("confidence_score") or 0.0),
            str(row.get("cluster_type") or ""),
            str(row.get("cluster_id") or ""),
        ),
    )[0]


def _primary_cluster(clusters: list[dict[str, Any]]) -> dict[str, Any]:
    if not clusters:
        return {}
    risk_rank = {"critical": 3, "high": 2, "medium": 1, "low": 0}
    return sorted(
        clusters,
        key=lambda row: (
            -risk_rank.get(str(row.get("cluster_risk_level") or ""), -1),
            -float(row.get("cluster_confidence") or row.get("confidence_score") or 0.0),
            str(row.get("cluster_type") or ""),
            str(row.get("cluster_id") or ""),
        ),
    )[0]


def _cluster_confidence(
    relationships: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    member_count: int,
) -> float:
    scores = [float(row.get("strength_score") or 0.0) for row in relationships]
    if scores:
        average_score = sum(scores) / len(scores)
        max_score = max(scores)
        density = min(len(relationships) / max(member_count, 1), 1.0)
        confidence = (average_score * 0.55) + (max_score * 0.30) + (density * 0.15)
    else:
        edge_support = min(len(edges), 3) * 0.08
        member_support = min(member_count, 4) * 0.06
        confidence = edge_support + member_support
    return round(min(max(confidence, 0.0), 1.0), 2)


def _cluster_evidence(
    relationships: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    member_labels: set[str],
) -> list[str]:
    evidence: list[str] = []
    for relationship in sorted(
        relationships,
        key=lambda row: (-float(row.get("strength_score") or 0.0), str(row.get("relationship_id") or "")),
    ):
        relationship_type = _safe_text(relationship.get("relationship_type"))
        if relationship_type != "-":
            evidence.append(f"relationship:{relationship_type}")
        for item in relationship.get("evidence_summary") or []:
            evidence.append(item)
    if edges:
        evidence.append(f"structural_edges:{len(edges)}")
    if member_labels:
        evidence.append("members:" + ",".join(sorted(member_labels)[:3]))
    return _unique_text(evidence, limit=8)


def _cluster_strongest_member(relationship: dict[str, Any], member_labels: set[str]) -> str:
    for key in ("target_label", "source_label"):
        value = _safe_text(relationship.get(key))
        if value != "-":
            return value
    return sorted(member_labels)[0] if member_labels else "-"


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


def _safe_float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _safe_int_value(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 0


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


def _cluster_id(cluster_type: str, member_ids: list[str], relationships: list[tuple[Any, Any]]) -> str:
    return "graph-cluster-" + cluster_type.replace("_cluster", "") + "-" + _digest(
        {
            "type": cluster_type,
            "members": member_ids,
            "relationships": relationships,
        }
    )[:16]


def _flow_entity_id(flow_reference: str) -> str:
    return "graph-flow-" + _digest({"flow": flow_reference})[:16]


def _digest(value: Any) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
