from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
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
GRAPH_INSIGHT_TYPES = {
    "emerging_risk_cluster",
    "repeated_risk_signal",
    "unstable_identity",
    "ambiguous_application_cluster",
    "high_relationship_density",
    "low_confidence_high_risk",
}
INVESTIGATION_RECOMMENDATION_CATEGORIES = {
    "verify_service_identity",
    "review_risk_cluster",
    "inspect_graph_relationships",
    "collect_additional_observations",
    "validate_historical_change",
    "review_missing_evidence",
    "confirm_expected_behavior",
}
INVESTIGATION_RECOMMENDATION_PRIORITIES = {"critical", "high", "medium", "low"}
FEDERATED_INTELLIGENCE_CATEGORIES = {
    "learned_application_fingerprint",
    "behavioral_summary",
    "service_metadata",
    "threat_indicator",
    "confidence_observation",
    "graph_metadata",
    "cluster_summary",
    "prediction_summary",
}
FEDERATED_CONSENSUS_CATEGORIES = {
    "single_source",
    "multi_source",
    "strong_consensus",
    "weak_consensus",
    "conflicting",
    "expired",
    "unknown",
}
FEDERATED_INTELLIGENCE_SCHEMA_VERSION = "1.0"
INVESTIGATION_CHAIN_CATEGORIES = {
    "identity_verification_chain",
    "risk_evolution_chain",
    "prediction_validation_chain",
    "federated_consensus_chain",
    "missing_evidence_chain",
    "behavior_review_chain",
    "stability_monitoring_chain",
}
INVESTIGATION_CHAIN_PRIORITIES = {"critical", "high", "medium", "low"}


def build_behavior_graph_model(
    observation: dict[str, Any],
    *,
    classification_model: dict[str, Any] | None = None,
    learning_profile: dict[str, Any] | None = None,
    learning_profile_history: dict[str, Any] | None = None,
    flows: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    federated_intelligence: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a deterministic metadata-only behavior graph for one observed service."""
    timestamp = generated_at or _now()
    classifier = classification_model if isinstance(classification_model, dict) else {}
    profile = learning_profile if isinstance(learning_profile, dict) else {}
    history = learning_profile_history if isinstance(learning_profile_history, dict) else {}
    peer_intelligence = _federated_intelligence_inputs(
        observation if isinstance(observation, dict) else {},
        classifier,
        history,
        federated_intelligence,
    )
    if not isinstance(observation, dict) or not observation:
        return _graph_record(
            timestamp=timestamp,
            nodes=[],
            edges=[],
            related={},
            peer_intelligence=peer_intelligence,
        )

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
    cluster_context = _cluster_context(observation, classifier, profile, history, generated_at=generated_at)
    cluster_rows = _build_behavior_clusters(
        node_rows,
        edge_rows,
        relationship_rows,
        context=cluster_context,
    )

    return _graph_record(
        timestamp=timestamp,
        nodes=node_rows,
        edges=edge_rows,
        relationships=relationship_rows,
        clusters=cluster_rows,
        risk_context=cluster_context,
        related={
            "related_asset": related_asset,
            "related_service": related_service,
            "related_profile": related_profile,
        },
        peer_intelligence=peer_intelligence,
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
    risk_context: dict[str, Any] | None = None,
    peer_intelligence: Iterable[dict[str, Any]] | None = None,
    related: dict[str, str],
) -> dict[str, Any]:
    relationship_rows = relationships or []
    cluster_rows = clusters or []
    insight_rows = _build_graph_insights(nodes, edges, relationship_rows, cluster_rows)
    risk_evolution = _build_historical_risk_evolution(
        relationship_rows,
        cluster_rows,
        insight_rows,
        context=risk_context or {},
    )
    behavioral_decision = _build_behavioral_decision_explanation(
        relationship_rows,
        cluster_rows,
        insight_rows,
        risk_evolution,
        context=risk_context or {},
    )
    investigation_recommendations = _build_investigation_recommendations(
        relationship_rows,
        cluster_rows,
        insight_rows,
        risk_evolution,
        behavioral_decision,
        context=risk_context or {},
        related=related,
    )
    review_queue = _build_review_queue_summary(
        relationship_rows,
        cluster_rows,
        insight_rows,
        risk_evolution,
        behavioral_decision,
        investigation_recommendations,
        context=risk_context or {},
    )
    threat_prediction = _build_threat_prediction_model(
        relationship_rows,
        cluster_rows,
        insight_rows,
        risk_evolution,
        behavioral_decision,
        investigation_recommendations,
        review_queue,
        context=risk_context or {},
    )
    federated_model = _build_federated_intelligence_model(
        relationship_rows,
        cluster_rows,
        insight_rows,
        risk_evolution,
        behavioral_decision,
        investigation_recommendations,
        review_queue,
        threat_prediction,
        context=risk_context or {},
        related=related,
        generated_at=timestamp,
        peer_intelligence=peer_intelligence,
    )
    investigation_chains = _build_autonomous_investigation_chains(
        relationship_rows,
        cluster_rows,
        insight_rows,
        risk_evolution,
        behavioral_decision,
        investigation_recommendations,
        review_queue,
        threat_prediction,
        federated_model,
        context=risk_context or {},
        related=related,
    )
    summary = _graph_summary(
        nodes,
        edges,
        relationship_rows,
        cluster_rows,
        insight_rows,
        risk_evolution,
        behavioral_decision,
        investigation_recommendations,
        review_queue,
        threat_prediction,
        federated_model,
        investigation_chains,
        related,
    )
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
                "insights": [(row.get("insight_type"), row.get("insight_id")) for row in insight_rows],
                "risk_evolution": {
                    "direction": risk_evolution.get("risk_evolution_direction"),
                    "delta": risk_evolution.get("risk_delta"),
                    "reasons": risk_evolution.get("risk_change_reasons"),
                },
                "behavioral_decision": {
                    "decision": behavioral_decision.get("behavioral_decision"),
                    "category": behavioral_decision.get("behavioral_decision_category"),
                    "confidence": behavioral_decision.get("behavioral_decision_confidence"),
                    "reasons": behavioral_decision.get("behavioral_decision_reasons"),
                },
                "investigation_recommendations": [
                    (row.get("category"), row.get("priority"), row.get("recommendation_id"))
                    for row in investigation_recommendations
                ],
                "review_queue": {
                    "required": review_queue.get("review_queue_required"),
                    "priority": review_queue.get("review_queue_priority"),
                    "category": review_queue.get("review_queue_category"),
                    "reason": review_queue.get("review_queue_reason"),
                },
                "threat_prediction": {
                    "category": threat_prediction.get("prediction_category"),
                    "score": threat_prediction.get("predicted_risk_score"),
                    "confidence": threat_prediction.get("prediction_confidence"),
                    "horizon": threat_prediction.get("prediction_horizon"),
                    "reasons": threat_prediction.get("prediction_reasons"),
                },
                "federated_intelligence": {
                    "consensus": federated_model.get("consensus"),
                    "confidence": federated_model.get("federated_confidence"),
                    "agreement": federated_model.get("agreement_score"),
                    "contributors": federated_model.get("unique_contributors"),
                    "conflicts": federated_model.get("conflicts"),
                },
                "investigation_chains": [
                    (row.get("chain_category"), row.get("chain_priority"), row.get("chain_id"))
                    for row in investigation_chains
                ],
            }
        )[:16],
        "generated_at": timestamp,
        "nodes": nodes,
        "edges": edges,
        "relationships": relationship_rows,
        "clusters": cluster_rows,
        "insights": insight_rows,
        "risk_evolution": risk_evolution,
        "behavioral_decision": behavioral_decision,
        "investigation_recommendations": investigation_recommendations,
        "review_queue": review_queue,
        "threat_prediction": threat_prediction,
        "federated_intelligence": federated_model,
        "investigation_chains": investigation_chains,
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
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    review_queue: dict[str, Any],
    threat_prediction: dict[str, Any],
    federated_model: dict[str, Any],
    investigation_chains: list[dict[str, Any]],
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
    strongest_insight = _strongest_graph_insight(insights)
    top_investigation = _top_investigation_recommendation(investigation_recommendations)
    top_chain = _top_investigation_chain(investigation_chains)
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
        "graph_insight_count": len(insights),
        "strongest_graph_insight": strongest_insight.get("insight_id", "-"),
        "strongest_graph_insight_type": strongest_insight.get("insight_type", "-"),
        "strongest_graph_insight_score": strongest_insight.get("insight_score", "-"),
        "graph_insight_summary": _graph_insight_summary(insights),
        "graph_operator_next_steps": _graph_operator_next_steps(strongest_insight),
        "previous_risk_score": risk_evolution.get("previous_risk_score", "-"),
        "current_risk_score": risk_evolution.get("current_risk_score", "-"),
        "risk_delta": risk_evolution.get("risk_delta", "-"),
        "risk_evolution_direction": risk_evolution.get("risk_evolution_direction", "insufficient_history"),
        "risk_evolution_velocity": risk_evolution.get("risk_evolution_velocity", "unknown"),
        "risk_evolution_confidence": risk_evolution.get("risk_evolution_confidence", 0.0),
        "risk_change_reasons": risk_evolution.get("risk_change_reasons", "insufficient_history"),
        "risk_evolution_summary": risk_evolution.get("risk_evolution_summary", "-"),
        "risk_operator_next_steps": risk_evolution.get("risk_operator_next_steps", "-"),
        "behavioral_decision": behavioral_decision.get("behavioral_decision", "-"),
        "behavioral_decision_confidence": behavioral_decision.get("behavioral_decision_confidence", 0.0),
        "behavioral_decision_category": behavioral_decision.get(
            "behavioral_decision_category", "insufficient_context"
        ),
        "behavioral_decision_summary": behavioral_decision.get("behavioral_decision_summary", "-"),
        "behavioral_decision_reasons": behavioral_decision.get("behavioral_decision_reasons", "-"),
        "behavioral_decision_evidence": behavioral_decision.get("behavioral_decision_evidence", "-"),
        "behavioral_decision_limitations": behavioral_decision.get("behavioral_decision_limitations", "-"),
        "behavioral_decision_next_steps": behavioral_decision.get("behavioral_decision_next_steps", "-"),
        "investigation_recommendation_count": len(investigation_recommendations),
        "top_investigation_recommendation": top_investigation.get("title", "-"),
        "top_investigation_priority": top_investigation.get("priority", "-"),
        "top_investigation_category": top_investigation.get("category", "-"),
        "investigation_recommendation_summary": _investigation_recommendation_summary(
            investigation_recommendations
        ),
        "investigation_operator_next_steps": _investigation_operator_next_steps(top_investigation),
        "review_queue_required": review_queue.get("review_queue_required", "no"),
        "review_queue_priority": review_queue.get("review_queue_priority", "none"),
        "review_queue_category": review_queue.get("review_queue_category", "none"),
        "review_queue_reason": review_queue.get("review_queue_reason", "-"),
        "review_queue_evidence": review_queue.get("review_queue_evidence", "-"),
        "review_queue_next_step": review_queue.get("review_queue_next_step", "-"),
        "review_queue_summary": review_queue.get("review_queue_summary", "-"),
        "predicted_risk_level": threat_prediction.get("predicted_risk_level", "low"),
        "predicted_risk_score": threat_prediction.get("predicted_risk_score", 0.0),
        "prediction_confidence": threat_prediction.get("prediction_confidence", 0.0),
        "prediction_horizon": threat_prediction.get("prediction_horizon", "medium_term"),
        "prediction_category": threat_prediction.get("prediction_category", "uncertain_prediction"),
        "prediction_summary": threat_prediction.get("prediction_summary", "-"),
        "prediction_reasons": threat_prediction.get("prediction_reasons", "-"),
        "prediction_limitations": threat_prediction.get("prediction_limitations", "-"),
        "prediction_next_steps": threat_prediction.get("prediction_next_steps", "-"),
        "federated_status": federated_model.get("federated_status", "unknown"),
        "federated_confidence": federated_model.get("federated_confidence", 0.0),
        "federated_observation_count": federated_model.get("federated_observation_count", 0),
        "originating_nodes": federated_model.get("originating_nodes", "-"),
        "consensus": federated_model.get("consensus", "unknown"),
        "conflicts": federated_model.get("conflicts", 0),
        "agreement_score": federated_model.get("agreement_score", 0.0),
        "agreement_percentage": federated_model.get("agreement_percentage", "0%"),
        "confidence_trend": federated_model.get("confidence_trend", "stable"),
        "federated_age": federated_model.get("federated_age", "-"),
        "federated_freshness": federated_model.get("federated_freshness", "unknown"),
        "expiration": federated_model.get("expiration", "-"),
        "source_count": federated_model.get("source_count", 0),
        "unique_contributors": federated_model.get("unique_contributors", 0),
        "source_nodes": federated_model.get("source_nodes", "-"),
        "contributors": federated_model.get("contributors", "-"),
        "conflict_summary": federated_model.get("conflict_summary", "-"),
        "consensus_summary": federated_model.get("consensus_summary", "-"),
        "federated_operator_recommendation": federated_model.get("operator_recommendation", "-"),
        "investigation_chain_count": len(investigation_chains),
        "top_investigation_chain": top_chain.get("chain_id", "-"),
        "top_investigation_chain_category": top_chain.get("chain_category", "-"),
        "top_investigation_chain_priority": top_chain.get("chain_priority", "-"),
        "top_investigation_chain_confidence": top_chain.get("chain_confidence", 0.0),
        "investigation_chain_summary": _investigation_chain_summary(investigation_chains),
        "investigation_chain_next_steps": _investigation_chain_next_steps(top_chain),
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
    previous_risk_signals = _previous_risk_signal_values(observation, history_summary)
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
    current_risk_score = _optional_float(
        _first_present_value(observation.get("risk_score"), observation.get("score"), observation.get("confidence"))
    )
    previous_risk_score = _optional_float(
        _first_present_value(
            observation.get("previous_risk_score"),
            observation.get("prior_risk_score"),
            observation.get("historical_risk_score"),
            history_summary.get("previous_risk_score"),
            history_summary.get("prior_risk_score"),
            history_summary.get("risk_score_previous"),
        )
    )
    return {
        "risk_score": _safe_float(
            observation.get("risk_score")
            or observation.get("score")
            or observation.get("confidence")
            or history_summary.get("risk_score")
        ),
        "current_risk_score": current_risk_score,
        "previous_risk_score": previous_risk_score,
        "risk_score_history": _risk_score_history_values(observation, history_summary),
        "risk_signals": risk_signals,
        "previous_risk_signals": previous_risk_signals,
        "originating_node": _safe_text(
            observation.get("node_id") or observation.get("node") or observation.get("asset") or "local_node"
        ),
        "top_classification": _safe_text(classification_model.get("top_classification")),
        "evidence_quality": _safe_text(classification_model.get("evidence_quality")).lower(),
        "candidate_count": _safe_int_value(
            classification_model.get("candidate_count")
            or len(classification_model.get("candidates") or [])
            or len(classification_model.get("alternative_candidates") or [])
        ),
        "missing_evidence": _classification_missing_evidence_values(classification_model),
        "has_profile_metadata": bool(learning_profile or learning_profile_history),
        "recommendation_count": _safe_int_value(
            history_summary.get("recommendation_count") or learning_profile_history.get("recommendation_count")
        ),
        "primary_recommendation": _safe_text(
            history_summary.get("primary_recommendation") or learning_profile_history.get("primary_recommendation")
        ),
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
        "previous_cluster_count": _optional_int(
            _first_present_value(
                observation.get("previous_cluster_count"),
                observation.get("prior_cluster_count"),
                observation.get("historical_cluster_count"),
                history_summary.get("previous_cluster_count"),
            )
        ),
        "signal_count": len(risk_signals),
    }


def _build_historical_risk_evolution(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    *,
    context: dict[str, Any],
) -> dict[str, Any]:
    current_score = _optional_float(context.get("current_risk_score"))
    previous_score = _optional_float(context.get("previous_risk_score"))
    history = [value for value in context.get("risk_score_history") or [] if isinstance(value, (int, float))]
    observation_count = int(context.get("observation_count") or 0)
    has_history = observation_count > 1 and current_score is not None and previous_score is not None
    delta = round(current_score - previous_score, 2) if has_history else None
    relationship_delta = _count_delta(len(relationships), context.get("previous_relationship_count"))
    signal_delta = _count_delta(int(context.get("signal_count") or 0), context.get("previous_signal_count"))
    cluster_delta = _count_delta(len(clusters), context.get("previous_cluster_count"))
    direction = _risk_evolution_direction(
        delta=delta,
        history=history,
        has_history=has_history,
    )
    velocity = _risk_evolution_velocity(
        direction=direction,
        delta=delta,
        relationship_delta=relationship_delta,
        signal_delta=signal_delta,
        cluster_delta=cluster_delta,
    )
    reasons = _risk_change_reason_values(
        direction=direction,
        delta=delta,
        relationships=relationships,
        clusters=clusters,
        insights=insights,
        relationship_delta=relationship_delta,
        signal_delta=signal_delta,
        cluster_delta=cluster_delta,
        context=context,
    )
    confidence = _risk_evolution_confidence(
        has_history=has_history,
        observation_count=observation_count,
        history_count=len(history),
        relationship_count=len(relationships),
        cluster_count=len(clusters),
        insight_count=len(insights),
        reason_count=len(reasons),
    )
    return {
        "previous_risk_score": round(previous_score, 2) if previous_score is not None else "-",
        "current_risk_score": round(current_score, 2) if current_score is not None else "-",
        "risk_delta": delta if delta is not None else "-",
        "risk_evolution_direction": direction,
        "risk_evolution_velocity": velocity,
        "risk_evolution_confidence": confidence,
        "risk_change_reasons": "; ".join(reasons),
        "risk_evolution_summary": _risk_evolution_summary(direction, velocity, delta, reasons),
        "risk_operator_next_steps": _risk_operator_next_steps(direction),
        "metadata_only": True,
        "read_only": True,
        "advisory_only": True,
    }


def _build_behavioral_decision_explanation(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    *,
    context: dict[str, Any],
) -> dict[str, Any]:
    primary_cluster = _primary_cluster(clusters)
    strongest_insight = _strongest_graph_insight(insights)
    risk_score = _optional_float(context.get("current_risk_score"))
    if risk_score is None:
        risk_score = _optional_float(context.get("risk_score")) or 0.0
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    drift_score = float(context.get("drift_score") or 0.0)
    observation_count = int(context.get("observation_count") or 0)
    evidence_quality = _safe_text(context.get("evidence_quality")).lower()
    cluster_risk = _safe_text(primary_cluster.get("cluster_risk_level"))
    cluster_trend = _safe_text(primary_cluster.get("cluster_trend"))
    stability_label = _safe_text(context.get("profile_stability_label"))
    risk_direction = _safe_text(risk_evolution.get("risk_evolution_direction"))
    insight_score = float(strongest_insight.get("insight_score") or 0.0)

    category = _behavioral_decision_category(
        risk_score=risk_score,
        candidate_confidence=candidate_confidence,
        cluster_risk=cluster_risk,
        cluster_trend=cluster_trend,
        insight_score=insight_score,
        risk_direction=risk_direction,
        drift_score=drift_score,
        stability_label=stability_label,
        observation_count=observation_count,
        evidence_quality=evidence_quality,
        relationship_count=len(relationships),
        cluster_count=len(clusters),
        has_profile_metadata=bool(context.get("has_profile_metadata")),
    )
    reasons = _behavioral_decision_reasons(
        category=category,
        risk_score=risk_score,
        candidate_confidence=candidate_confidence,
        cluster_risk=cluster_risk,
        cluster_trend=cluster_trend,
        insight_score=insight_score,
        risk_direction=risk_direction,
        drift_score=drift_score,
        stability_label=stability_label,
        observation_count=observation_count,
        evidence_quality=evidence_quality,
        relationship_count=len(relationships),
        cluster_count=len(clusters),
    )
    evidence = _behavioral_decision_evidence(
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        risk_evolution=risk_evolution,
        context=context,
        relationship_count=len(relationships),
        cluster_count=len(clusters),
    )
    limitations = _behavioral_decision_limitations(
        candidate_confidence=candidate_confidence,
        evidence_quality=evidence_quality,
        observation_count=observation_count,
        risk_direction=risk_direction,
        has_profile_metadata=bool(context.get("has_profile_metadata")),
    )
    confidence = _behavioral_decision_confidence(
        category=category,
        candidate_confidence=candidate_confidence,
        evidence_quality=evidence_quality,
        observation_count=observation_count,
        relationship_count=len(relationships),
        cluster_count=len(clusters),
        insight_score=insight_score,
        risk_evolution_confidence=float(risk_evolution.get("risk_evolution_confidence") or 0.0),
        limitation_count=len(limitations),
    )
    return {
        "behavioral_decision": category,
        "behavioral_decision_confidence": confidence,
        "behavioral_decision_category": category,
        "behavioral_decision_summary": _behavioral_decision_summary(category, reasons),
        "behavioral_decision_reasons": "; ".join(reasons),
        "behavioral_decision_evidence": "; ".join(evidence),
        "behavioral_decision_limitations": "; ".join(limitations) if limitations else "no_major_limitations",
        "behavioral_decision_next_steps": _behavioral_decision_next_steps(category),
        "advisory_only": True,
        "metadata_only": True,
        "read_only": True,
    }


def _build_investigation_recommendations(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    *,
    context: dict[str, Any],
    related: dict[str, str],
) -> list[dict[str, Any]]:
    if not relationships and not clusters and not insights and not _has_investigation_context(context):
        return []
    primary_cluster = _primary_cluster(clusters)
    strongest_relationship = _strongest_relationship(relationships)
    strongest_insight = _strongest_graph_insight(insights)
    rows: list[dict[str, Any]] = []
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    evidence_quality = _safe_text(context.get("evidence_quality")).lower()
    missing_evidence = list(context.get("missing_evidence") or [])
    observation_count = int(context.get("observation_count") or 0)
    decision_category = _safe_text(behavioral_decision.get("behavioral_decision_category"))
    cluster_risk = _safe_text(primary_cluster.get("cluster_risk_level"))
    cluster_trend = _safe_text(primary_cluster.get("cluster_trend"))
    insight_score = float(strongest_insight.get("insight_score") or 0.0)
    risk_direction = _safe_text(risk_evolution.get("risk_evolution_direction"))

    if candidate_confidence < 0.62 or int(context.get("candidate_count") or 0) > 1:
        rows.append(
            _investigation_recommendation(
                "verify_service_identity",
                _investigation_priority(
                    base="medium",
                    decision_category=decision_category,
                    cluster_risk=cluster_risk,
                    insight_score=insight_score,
                    risk_direction=risk_direction,
                    candidate_confidence=candidate_confidence,
                ),
                "Verify service identity",
                "Attribution confidence or candidate ambiguity limits service identity certainty.",
                [
                    f"classification_confidence:{candidate_confidence:.2f}",
                    f"candidate_count:{int(context.get('candidate_count') or 0)}",
                    f"top_classification:{_safe_text(context.get('top_classification'))}",
                ],
                missing_evidence or ["process_or_service_confirmation"],
                "Review process, service name, expected-service allowlist, and historical profile evidence.",
                0.22,
                ["no_process_or_service_confirmation"],
                related=related,
                primary_cluster=primary_cluster,
                strongest_relationship=strongest_relationship,
                strongest_insight=strongest_insight,
            )
        )
    if cluster_risk in {"medium", "high", "critical"} or decision_category in {"investigate_behavior", "elevated_risk_behavior"}:
        rows.append(
            _investigation_recommendation(
                "review_risk_cluster",
                _investigation_priority(
                    base="high" if cluster_risk in {"high", "critical"} else "medium",
                    decision_category=decision_category,
                    cluster_risk=cluster_risk,
                    insight_score=insight_score,
                    risk_direction=risk_direction,
                    candidate_confidence=candidate_confidence,
                ),
                "Review behavioral risk cluster",
                "Primary cluster risk or behavioral decision indicates operator review is warranted.",
                [
                    f"cluster_risk:{cluster_risk}",
                    f"cluster_trend:{cluster_trend}",
                    f"decision:{decision_category}",
                ],
                ["operator_cluster_review"],
                "Inspect the primary cluster, risk reason, related graph insight, and expected behavior.",
                0.18,
                ["cluster_context_not_operator_verified"],
                related=related,
                primary_cluster=primary_cluster,
                strongest_relationship=strongest_relationship,
                strongest_insight=strongest_insight,
            )
        )
    if relationships and (len(relationships) >= 3 or float(strongest_relationship.get("strength_score") or 0.0) >= 0.70):
        rows.append(
            _investigation_recommendation(
                "inspect_graph_relationships",
                _investigation_priority(
                    base="medium",
                    decision_category=decision_category,
                    cluster_risk=cluster_risk,
                    insight_score=insight_score,
                    risk_direction=risk_direction,
                    candidate_confidence=candidate_confidence,
                ),
                "Inspect graph relationships",
                "Graph relationships provide meaningful context for the behavioral conclusion.",
                [
                    f"relationships:{len(relationships)}",
                    f"strongest_relationship:{_safe_text(strongest_relationship.get('relationship_type'))}",
                    f"relationship_score:{float(strongest_relationship.get('strength_score') or 0.0):.2f}",
                ],
                ["relationship_owner_context"],
                "Review relationship endpoints, shared ports, shared protocols, and linked profile evidence.",
                0.14,
                ["relationship_context_not_confirmed"],
                related=related,
                primary_cluster=primary_cluster,
                strongest_relationship=strongest_relationship,
                strongest_insight=strongest_insight,
            )
        )
    if observation_count <= 2 or decision_category == "insufficient_context" or risk_direction == "insufficient_history":
        rows.append(
            _investigation_recommendation(
                "collect_additional_observations",
                _investigation_priority(
                    base="medium",
                    decision_category=decision_category,
                    cluster_risk=cluster_risk,
                    insight_score=insight_score,
                    risk_direction=risk_direction,
                    candidate_confidence=candidate_confidence,
                ),
                "Collect additional observations",
                "Observation history is limited or historical risk context is insufficient.",
                [
                    f"observations:{observation_count}",
                    f"risk_direction:{risk_direction}",
                    f"decision:{decision_category}",
                ],
                ["additional_history"],
                "Continue metadata-only observation and compare future profile and graph summaries.",
                0.26,
                ["history_window_too_small"],
                related=related,
                primary_cluster=primary_cluster,
                strongest_relationship=strongest_relationship,
                strongest_insight=strongest_insight,
            )
        )
    if risk_direction in {"increasing", "decreasing", "fluctuating"}:
        rows.append(
            _investigation_recommendation(
                "validate_historical_change",
                _investigation_priority(
                    base="high" if risk_direction in {"increasing", "fluctuating"} else "medium",
                    decision_category=decision_category,
                    cluster_risk=cluster_risk,
                    insight_score=insight_score,
                    risk_direction=risk_direction,
                    candidate_confidence=candidate_confidence,
                ),
                "Validate historical risk change",
                "Historical risk evolution changed and should be compared against expected behavior.",
                [
                    f"risk_direction:{risk_direction}",
                    f"risk_delta:{risk_evolution.get('risk_delta')}",
                    f"risk_confidence:{float(risk_evolution.get('risk_evolution_confidence') or 0.0):.2f}",
                ],
                ["operator_validation_of_change"],
                "Compare the risk delta, change reasons, and cluster trend against expected service behavior.",
                0.17,
                ["historical_change_not_operator_validated"],
                related=related,
                primary_cluster=primary_cluster,
                strongest_relationship=strongest_relationship,
                strongest_insight=strongest_insight,
            )
        )
    if missing_evidence or evidence_quality in {"-", "weak", "limited", "low", "unknown"}:
        rows.append(
            _investigation_recommendation(
                "review_missing_evidence",
                _investigation_priority(
                    base="medium",
                    decision_category=decision_category,
                    cluster_risk=cluster_risk,
                    insight_score=insight_score,
                    risk_direction=risk_direction,
                    candidate_confidence=candidate_confidence,
                ),
                "Review missing attribution evidence",
                "Missing or weak evidence limits confidence in the behavioral explanation.",
                [
                    f"evidence_quality:{evidence_quality}",
                    f"missing_evidence:{len(missing_evidence)}",
                    f"classification_confidence:{candidate_confidence:.2f}",
                ],
                missing_evidence or ["stronger_attribution_evidence"],
                "Review process, service, fingerprint, and profile evidence gaps before relying on classification.",
                0.24,
                ["evidence_gaps_remain"],
                related=related,
                primary_cluster=primary_cluster,
                strongest_relationship=strongest_relationship,
                strongest_insight=strongest_insight,
            )
        )
    if decision_category == "benign_observation" or (
        cluster_risk in {"-", "low"} and risk_direction in {"stable", "decreasing"} and observation_count >= 3
    ):
        rows.append(
            _investigation_recommendation(
                "confirm_expected_behavior",
                "low",
                "Confirm expected behavior",
                "Available metadata suggests stable or expected behavior that should be confirmed operationally.",
                [
                    f"decision:{decision_category}",
                    f"cluster_risk:{cluster_risk}",
                    f"risk_direction:{risk_direction}",
                ],
                ["operator_expectation_confirmation"],
                "Confirm the service remains expected and continue routine metadata-only monitoring.",
                0.08,
                ["expected_behavior_not_operator_confirmed"],
                related=related,
                primary_cluster=primary_cluster,
                strongest_relationship=strongest_relationship,
                strongest_insight=strongest_insight,
            )
        )
    return _dedupe_investigation_recommendations(rows)


def _has_investigation_context(context: dict[str, Any]) -> bool:
    return any(
        _safe_text(context.get(key)) != "-"
        for key in ("top_classification", "evidence_quality", "primary_recommendation")
    ) or any(
        _optional_float(context.get(key)) is not None
        for key in ("current_risk_score", "previous_risk_score", "risk_score", "candidate_confidence")
    )


def _investigation_recommendation(
    category: str,
    priority: str,
    title: str,
    rationale: str,
    evidence: Iterable[Any],
    missing_evidence: Iterable[Any],
    suggested_operator_action: str,
    expected_confidence_gain: float,
    blocking_conditions: Iterable[Any],
    *,
    related: dict[str, str],
    primary_cluster: dict[str, Any],
    strongest_relationship: dict[str, Any],
    strongest_insight: dict[str, Any],
) -> dict[str, Any]:
    safe_category = category if category in INVESTIGATION_RECOMMENDATION_CATEGORIES else "collect_additional_observations"
    safe_priority = priority if priority in INVESTIGATION_RECOMMENDATION_PRIORITIES else "medium"
    evidence_rows = _unique_text(evidence, limit=10)
    missing_rows = _unique_text(missing_evidence, limit=8)
    blocking_rows = _unique_text(blocking_conditions, limit=8)
    related_cluster = _safe_text(primary_cluster.get("cluster_id"))
    related_relationship = _safe_text(strongest_relationship.get("relationship_id"))
    related_insight = _safe_text(strongest_insight.get("insight_id"))
    recommendation_id = "investigation-rec-" + _digest(
        {
            "category": safe_category,
            "priority": safe_priority,
            "evidence": evidence_rows,
            "missing": missing_rows,
            "cluster": related_cluster,
            "relationship": related_relationship,
            "insight": related_insight,
        }
    )[:16]
    return {
        "recommendation_id": recommendation_id,
        "priority": safe_priority,
        "category": safe_category,
        "title": _safe_text(title, limit=96),
        "rationale": _safe_text(rationale, limit=160),
        "evidence": evidence_rows,
        "missing_evidence": missing_rows,
        "suggested_operator_action": _safe_text(suggested_operator_action, limit=180),
        "expected_confidence_gain": _bounded_score(expected_confidence_gain),
        "blocking_conditions": blocking_rows,
        "related_asset": related.get("related_asset") or "-",
        "related_service": related.get("related_service") or "-",
        "related_profile": related.get("related_profile") or "-",
        "related_cluster": related_cluster,
        "related_relationship": related_relationship,
        "related_insight": related_insight,
        "advisory_only": True,
        "metadata_only": True,
        "read_only": True,
    }


def _investigation_priority(
    *,
    base: str,
    decision_category: str,
    cluster_risk: str,
    insight_score: float,
    risk_direction: str,
    candidate_confidence: float,
) -> str:
    rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(base, 1)
    if decision_category == "elevated_risk_behavior":
        rank = max(rank, 2)
    if cluster_risk == "critical":
        rank = max(rank, 3)
    elif cluster_risk == "high":
        rank = max(rank, 2)
    if insight_score >= 0.85:
        rank = max(rank, 2)
    if risk_direction in {"increasing", "fluctuating"}:
        rank = max(rank, 2)
    if candidate_confidence < 0.35 and rank < 3:
        rank = max(rank, 1)
    return ["low", "medium", "high", "critical"][rank]


def _dedupe_investigation_recommendations(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_category: dict[str, dict[str, Any]] = {}
    for row in rows:
        category = _safe_text(row.get("category"))
        current = by_category.get(category)
        if current is None or _investigation_sort_key(row) < _investigation_sort_key(current):
            by_category[category] = row
    return sorted(by_category.values(), key=_investigation_sort_key)


def _investigation_sort_key(row: dict[str, Any]) -> tuple[int, str, str]:
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(_safe_text(row.get("priority")), 2)
    return (priority_rank, _safe_text(row.get("category")), _safe_text(row.get("recommendation_id")))


def _top_investigation_recommendation(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    return sorted(rows, key=_investigation_sort_key)[0]


def _investigation_recommendation_summary(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "-"
    return "; ".join(
        f"{_safe_text(row.get('priority'))}:{_safe_text(row.get('category'))}:{_safe_text(row.get('title'), limit=48)}"
        for row in sorted(rows, key=_investigation_sort_key)[:3]
    )


def _investigation_operator_next_steps(top: dict[str, Any]) -> str:
    if not top:
        return "-"
    return _safe_text(top.get("suggested_operator_action"), limit=180)


def _build_review_queue_summary(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    *,
    context: dict[str, Any],
) -> dict[str, Any]:
    primary_cluster = _primary_cluster(clusters)
    strongest_insight = _strongest_graph_insight(insights)
    top_investigation = _top_investigation_recommendation(investigation_recommendations)
    if not _has_review_queue_context(
        relationships,
        clusters,
        insights,
        risk_evolution,
        behavioral_decision,
        investigation_recommendations,
        context=context,
    ):
        return _review_queue_record(
            required=False,
            priority="none",
            category="none",
            reason="insufficient_evidence_for_operator_review",
            evidence=[],
            next_step="Collect additional metadata before adding this item to the operator review queue.",
        )

    priority = _review_queue_priority(
        behavioral_decision=behavioral_decision,
        risk_evolution=risk_evolution,
        top_investigation=top_investigation,
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        context=context,
    )
    category = _review_queue_category(
        priority=priority,
        behavioral_decision=behavioral_decision,
        risk_evolution=risk_evolution,
        top_investigation=top_investigation,
        primary_cluster=primary_cluster,
        context=context,
    )
    evidence = _review_queue_evidence(
        priority=priority,
        category=category,
        relationships=relationships,
        clusters=clusters,
        insights=insights,
        risk_evolution=risk_evolution,
        behavioral_decision=behavioral_decision,
        top_investigation=top_investigation,
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        context=context,
    )
    reason = _review_queue_reason(priority, category, evidence)
    return _review_queue_record(
        required=priority != "none",
        priority=priority,
        category=category,
        reason=reason,
        evidence=evidence,
        next_step=_review_queue_next_step(priority, category),
    )


def _has_review_queue_context(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    *,
    context: dict[str, Any],
) -> bool:
    if relationships or clusters or insights or investigation_recommendations:
        return True
    if _safe_text(behavioral_decision.get("behavioral_decision_category")) not in {"-", "insufficient_context"}:
        return True
    if _safe_text(risk_evolution.get("current_risk_score")) != "-":
        return True
    return _optional_float(context.get("current_risk_score")) is not None or _optional_float(context.get("risk_score")) is not None


def _review_queue_priority(
    *,
    behavioral_decision: dict[str, Any],
    risk_evolution: dict[str, Any],
    top_investigation: dict[str, Any],
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    context: dict[str, Any],
) -> str:
    decision = _safe_text(behavioral_decision.get("behavioral_decision_category"))
    risk_direction = _safe_text(risk_evolution.get("risk_evolution_direction"))
    cluster_risk = _safe_text(primary_cluster.get("cluster_risk_level"))
    cluster_trend = _safe_text(primary_cluster.get("cluster_trend"))
    top_priority = _safe_text(top_investigation.get("priority"))
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    evidence_quality = _safe_text(context.get("evidence_quality")).lower()
    observation_count = int(context.get("observation_count") or 0)
    insight_score = float(strongest_insight.get("insight_score") or 0.0)
    drift_score = float(context.get("drift_score") or 0.0)

    if top_priority == "critical" or (decision == "elevated_risk_behavior" and cluster_risk == "critical"):
        priority = "critical"
    elif (
        decision == "elevated_risk_behavior"
        or risk_direction in {"increasing", "fluctuating"}
        or cluster_risk in {"high", "critical"}
        or top_priority == "high"
        or insight_score >= 0.80
    ):
        priority = "high"
    elif (
        decision == "benign_observation"
        or (
            cluster_risk in {"-", "low"}
            and cluster_trend in {"stable", "dormant", "unknown", "-"}
            and risk_direction in {"stable", "decreasing"}
            and candidate_confidence >= 0.50
            and observation_count >= 3
        )
    ):
        priority = "low"
    elif (
        top_priority == "medium"
        or candidate_confidence < 0.50
        or evidence_quality in {"-", "weak", "limited", "low", "unknown"}
        or observation_count <= 2
        or risk_direction == "insufficient_history"
        or drift_score >= 0.45
    ):
        priority = "medium"
    else:
        priority = "medium"
    return _normalized_review_queue_priority(
        priority,
        decision=decision,
        top_priority=top_priority,
        risk_direction=risk_direction,
        cluster_risk=cluster_risk,
        cluster_trend=cluster_trend,
        observation_count=observation_count,
    )


def _normalized_review_queue_priority(
    priority: str,
    *,
    decision: str,
    top_priority: str,
    risk_direction: str,
    cluster_risk: str,
    cluster_trend: str,
    observation_count: int,
) -> str:
    if top_priority == "critical":
        return "critical"
    if decision == "elevated_risk_behavior" and priority in {"none", "low", "medium"}:
        return "high"
    stable_low_context = (
        decision == "benign_observation"
        and cluster_risk not in {"high", "critical"}
        and risk_direction in {"stable", "decreasing"}
        and cluster_trend in {"stable", "dormant", "unknown", "-"}
        and observation_count >= 3
    )
    if stable_low_context:
        return "low"
    if priority not in {"critical", "high", "medium", "low", "none"}:
        return "medium"
    return priority


def _review_queue_category(
    *,
    priority: str,
    behavioral_decision: dict[str, Any],
    risk_evolution: dict[str, Any],
    top_investigation: dict[str, Any],
    primary_cluster: dict[str, Any],
    context: dict[str, Any],
) -> str:
    if priority == "none":
        return "none"
    decision = _safe_text(behavioral_decision.get("behavioral_decision_category"))
    risk_direction = _safe_text(risk_evolution.get("risk_evolution_direction"))
    cluster_risk = _safe_text(primary_cluster.get("cluster_risk_level"))
    evidence_quality = _safe_text(context.get("evidence_quality")).lower()
    if decision == "elevated_risk_behavior" or cluster_risk in {"high", "critical"}:
        return "elevated_behavior_review"
    if risk_direction in {"increasing", "decreasing", "fluctuating", "insufficient_history"}:
        return "historical_change_review"
    if _safe_text(top_investigation.get("category")) in {"verify_service_identity", "review_missing_evidence"}:
        return "confidence_review"
    if evidence_quality in {"-", "weak", "limited", "low", "unknown"}:
        return "confidence_review"
    if priority == "low":
        return "stable_observation_review"
    return "operator_attention_review"


def _review_queue_evidence(
    *,
    priority: str,
    category: str,
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    top_investigation: dict[str, Any],
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    context: dict[str, Any],
) -> list[str]:
    return _unique_text(
        [
            f"priority:{priority}",
            f"category:{category}",
            f"risk_direction:{_safe_text(risk_evolution.get('risk_evolution_direction'))}",
            f"decision:{_safe_text(behavioral_decision.get('behavioral_decision_category'))}",
            f"candidate_confidence:{float(context.get('candidate_confidence') or 0.0):.2f}",
            f"evidence_quality:{_safe_text(context.get('evidence_quality')).lower()}",
            f"observations:{int(context.get('observation_count') or 0)}",
            f"cluster_risk:{_safe_text(primary_cluster.get('cluster_risk_level'))}",
            f"cluster_trend:{_safe_text(primary_cluster.get('cluster_trend'))}",
            f"top_investigation:{_safe_text(top_investigation.get('category'))}",
            f"top_investigation_priority:{_safe_text(top_investigation.get('priority'))}",
            f"decision_confidence:{float(behavioral_decision.get('behavioral_decision_confidence') or 0.0):.2f}",
            f"risk_confidence:{float(risk_evolution.get('risk_evolution_confidence') or 0.0):.2f}",
            f"insight:{_safe_text(strongest_insight.get('insight_type'))}",
            f"insight_score:{float(strongest_insight.get('insight_score') or 0.0):.2f}",
            f"relationships:{len(relationships)}",
            f"clusters:{len(clusters)}",
            f"insights:{len(insights)}",
        ],
        limit=18,
    )


def _review_queue_reason(priority: str, category: str, evidence: list[str]) -> str:
    if priority == "none":
        return "insufficient_evidence_for_operator_review"
    return f"{priority}_{category}_from_{len(evidence)}_metadata_signals"


def _review_queue_next_step(priority: str, category: str) -> str:
    if priority == "critical":
        return "Place at the top of operator review and inspect cluster, risk evolution, and investigation recommendations."
    if priority == "high":
        return "Queue for near-term operator review of risk evolution, graph insight, and primary cluster context."
    if priority == "medium":
        return "Queue for standard operator review after checking confidence, missing evidence, and observation history."
    if priority == "low":
        return "Keep in low-priority review for expected behavior confirmation during routine monitoring."
    return "Do not queue yet; collect more metadata before operator review."


def _review_queue_record(
    *,
    required: bool,
    priority: str,
    category: str,
    reason: str,
    evidence: list[str],
    next_step: str,
) -> dict[str, Any]:
    evidence_text = "; ".join(evidence) if evidence else "-"
    required_text = "yes" if required else "no"
    return {
        "review_queue_required": required_text,
        "review_queue_priority": priority,
        "review_queue_category": category,
        "review_queue_reason": _safe_text(reason, limit=140),
        "review_queue_evidence": _safe_text(evidence_text, limit=180),
        "review_queue_next_step": _safe_text(next_step, limit=180),
        "review_queue_summary": _safe_text(
            f"required:{required_text}; priority:{priority}; category:{category}; reason:{reason}",
            limit=180,
        ),
        "metadata_only": True,
        "read_only": True,
        "advisory_only": True,
    }


def _build_threat_prediction_model(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    review_queue: dict[str, Any],
    *,
    context: dict[str, Any],
) -> dict[str, Any]:
    primary_cluster = _primary_cluster(clusters)
    strongest_insight = _strongest_graph_insight(insights)
    top_investigation = _top_investigation_recommendation(investigation_recommendations)
    current_risk = _prediction_current_risk(context, risk_evolution)
    category = _prediction_category(
        risk_evolution=risk_evolution,
        behavioral_decision=behavioral_decision,
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        top_investigation=top_investigation,
        review_queue=review_queue,
        context=context,
    )
    score = _prediction_risk_score(
        category=category,
        current_risk=current_risk,
        risk_evolution=risk_evolution,
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        review_queue=review_queue,
        context=context,
    )
    confidence = _prediction_confidence(
        category=category,
        risk_evolution=risk_evolution,
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        context=context,
        relationship_count=len(relationships),
        cluster_count=len(clusters),
        insight_count=len(insights),
    )
    reasons = _prediction_reasons(
        category=category,
        score=score,
        risk_evolution=risk_evolution,
        behavioral_decision=behavioral_decision,
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        top_investigation=top_investigation,
        review_queue=review_queue,
        context=context,
    )
    limitations = _prediction_limitations(
        risk_evolution=risk_evolution,
        primary_cluster=primary_cluster,
        strongest_insight=strongest_insight,
        context=context,
        relationship_count=len(relationships),
        cluster_count=len(clusters),
        insight_count=len(insights),
    )
    horizon = _prediction_horizon(
        category=category,
        score=score,
        risk_evolution=risk_evolution,
        primary_cluster=primary_cluster,
        review_queue=review_queue,
    )
    return {
        "predicted_risk_level": _prediction_risk_level(score),
        "predicted_risk_score": score,
        "prediction_confidence": confidence,
        "prediction_horizon": horizon,
        "prediction_category": category,
        "prediction_summary": _prediction_summary(category, score, horizon, reasons),
        "prediction_reasons": "; ".join(reasons),
        "prediction_limitations": "; ".join(limitations) if limitations else "no_major_limitations",
        "prediction_next_steps": _prediction_next_steps(category),
        "metadata_only": True,
        "read_only": True,
        "advisory_only": True,
        "training_performed": False,
        "automated_action": False,
        "external_connectivity": False,
    }


def _prediction_current_risk(context: dict[str, Any], risk_evolution: dict[str, Any]) -> float:
    current = _optional_float(risk_evolution.get("current_risk_score"))
    if current is None:
        current = _optional_float(context.get("current_risk_score"))
    if current is None:
        current = _optional_float(context.get("risk_score"))
    return _bounded_score(current or 0.0)


def _prediction_category(
    *,
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    top_investigation: dict[str, Any],
    review_queue: dict[str, Any],
    context: dict[str, Any],
) -> str:
    confidence = float(context.get("candidate_confidence") or 0.0)
    evidence_quality = _safe_text(context.get("evidence_quality")).lower()
    observation_count = int(context.get("observation_count") or 0)
    drift_score = float(context.get("drift_score") or 0.0)
    stability = float(context.get("profile_stability") or 0.0)
    stability_label = _safe_text(context.get("profile_stability_label"))
    risk_direction = _safe_text(risk_evolution.get("risk_evolution_direction"))
    cluster_risk = _safe_text(primary_cluster.get("cluster_risk_level"))
    cluster_trend = _safe_text(primary_cluster.get("cluster_trend"))
    decision = _safe_text(behavioral_decision.get("behavioral_decision_category"))
    insight_score = float(strongest_insight.get("insight_score") or 0.0)
    top_priority = _safe_text(top_investigation.get("priority"))
    review_priority = _safe_text(review_queue.get("review_queue_priority"))

    sparse_low_confidence = confidence < 0.50 and observation_count <= 2
    weak_context = evidence_quality in {"-", "weak", "limited", "low", "unknown"} and observation_count <= 2
    if sparse_low_confidence or weak_context:
        return "uncertain_prediction"
    if (
        (drift_score >= 0.60 and risk_direction in {"increasing", "fluctuating"})
        or (
            cluster_trend in {"emerging", "growing"}
            and (cluster_risk in {"high", "critical"} or review_priority in {"high", "critical"})
        )
        or (decision == "elevated_risk_behavior" and risk_direction in {"increasing", "fluctuating"})
        or top_priority == "critical"
        or insight_score >= 0.84
    ):
        return "increasing_risk"
    if risk_direction == "decreasing" and drift_score <= 0.45 and cluster_risk not in {"high", "critical"}:
        return "decreasing_risk"
    if (
        (stability_label == "stable" or stability >= 0.70)
        and drift_score <= 0.25
        and risk_direction in {"stable", "decreasing"}
        and cluster_risk not in {"high", "critical"}
    ):
        return "stable_behavior"
    if cluster_trend in {"emerging", "growing"} and confidence >= 0.50:
        return "emerging_behavior"
    if risk_direction == "insufficient_history" or observation_count <= 1:
        return "uncertain_prediction"
    return "stable_behavior"


def _prediction_risk_score(
    *,
    category: str,
    current_risk: float,
    risk_evolution: dict[str, Any],
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    review_queue: dict[str, Any],
    context: dict[str, Any],
) -> float:
    drift_score = float(context.get("drift_score") or 0.0)
    stability = float(context.get("profile_stability") or 0.0)
    insight_score = float(strongest_insight.get("insight_score") or 0.0)
    cluster_score = _prediction_cluster_risk_score(primary_cluster.get("cluster_risk_level"))
    review_score = _prediction_priority_score(review_queue.get("review_queue_priority"))
    direction_score = _prediction_direction_score(risk_evolution.get("risk_evolution_direction"))
    score = (
        current_risk * 0.32
        + drift_score * 0.18
        + insight_score * 0.14
        + cluster_score * 0.14
        + review_score * 0.10
        + direction_score * 0.12
    )
    if category == "stable_behavior":
        score -= 0.12 * min(stability, 1.0)
    elif category == "decreasing_risk":
        score -= 0.06
    elif category == "emerging_behavior":
        score += 0.08
    elif category == "increasing_risk":
        score += 0.10
    elif category == "uncertain_prediction":
        score = max(score, 0.28)
    return _bounded_score(score)


def _prediction_confidence(
    *,
    category: str,
    risk_evolution: dict[str, Any],
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    context: dict[str, Any],
    relationship_count: int,
    cluster_count: int,
    insight_count: int,
) -> float:
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    stability = float(context.get("profile_stability") or 0.0)
    risk_confidence = float(risk_evolution.get("risk_evolution_confidence") or 0.0)
    cluster_confidence = float(primary_cluster.get("cluster_confidence") or primary_cluster.get("confidence_score") or 0.0)
    insight_score = float(strongest_insight.get("insight_score") or 0.0)
    observation_support = min(int(context.get("observation_count") or 0) / 6, 1.0)
    graph_support = min((relationship_count + cluster_count + insight_count) / 8, 1.0)
    confidence = (
        0.20
        + candidate_confidence * 0.18
        + stability * 0.14
        + risk_confidence * 0.14
        + cluster_confidence * 0.12
        + insight_score * 0.08
        + observation_support * 0.08
        + graph_support * 0.06
    )
    if category == "uncertain_prediction":
        confidence = min(confidence, 0.58)
    return _bounded_score(confidence)


def _prediction_horizon(
    *,
    category: str,
    score: float,
    risk_evolution: dict[str, Any],
    primary_cluster: dict[str, Any],
    review_queue: dict[str, Any],
) -> str:
    risk_direction = _safe_text(risk_evolution.get("risk_evolution_direction"))
    cluster_risk = _safe_text(primary_cluster.get("cluster_risk_level"))
    review_priority = _safe_text(review_queue.get("review_queue_priority"))
    if category == "increasing_risk" and (
        score >= 0.70 or cluster_risk in {"high", "critical"} or review_priority in {"high", "critical"}
    ):
        return "immediate"
    if category in {"increasing_risk", "emerging_behavior", "uncertain_prediction"}:
        return "short_term"
    if category == "decreasing_risk" or risk_direction == "decreasing":
        return "medium_term"
    return "medium_term"


def _prediction_reasons(
    *,
    category: str,
    score: float,
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    top_investigation: dict[str, Any],
    review_queue: dict[str, Any],
    context: dict[str, Any],
) -> list[str]:
    reasons = [
        f"category:{category}",
        f"predicted_score:{score:.2f}",
        f"risk_direction:{_safe_text(risk_evolution.get('risk_evolution_direction'))}",
        f"cluster_risk:{_safe_text(primary_cluster.get('cluster_risk_level'))}",
        f"cluster_trend:{_safe_text(primary_cluster.get('cluster_trend'))}",
        f"drift_score:{float(context.get('drift_score') or 0.0):.2f}",
        f"stability:{float(context.get('profile_stability') or 0.0):.2f}",
        f"candidate_confidence:{float(context.get('candidate_confidence') or 0.0):.2f}",
        f"behavioral_decision:{_safe_text(behavioral_decision.get('behavioral_decision_category'))}",
        f"graph_insight:{_safe_text(strongest_insight.get('insight_type'))}",
        f"graph_insight_score:{float(strongest_insight.get('insight_score') or 0.0):.2f}",
        f"top_investigation_priority:{_safe_text(top_investigation.get('priority'))}",
        f"review_priority:{_safe_text(review_queue.get('review_queue_priority'))}",
        f"observations:{int(context.get('observation_count') or 0)}",
    ]
    return sorted(_unique_text(reasons, limit=18))


def _prediction_limitations(
    *,
    risk_evolution: dict[str, Any],
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    context: dict[str, Any],
    relationship_count: int,
    cluster_count: int,
    insight_count: int,
) -> list[str]:
    limitations: list[str] = []
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    evidence_quality = _safe_text(context.get("evidence_quality")).lower()
    observation_count = int(context.get("observation_count") or 0)
    if candidate_confidence < 0.50:
        limitations.append("low_attribution_confidence")
    if evidence_quality in {"-", "weak", "limited", "low", "unknown"}:
        limitations.append("weak_evidence_quality")
    if observation_count <= 2:
        limitations.append("sparse_observation_history")
    if _safe_text(risk_evolution.get("risk_evolution_direction")) == "insufficient_history":
        limitations.append("insufficient_risk_history")
    if not primary_cluster:
        limitations.append("no_primary_cluster")
    if not strongest_insight:
        limitations.append("no_graph_insight")
    if relationship_count == 0 or cluster_count == 0 or insight_count == 0:
        limitations.append("limited_graph_context")
    return sorted(_unique_text(limitations, limit=10))


def _prediction_summary(category: str, score: float, horizon: str, reasons: list[str]) -> str:
    if category == "stable_behavior":
        prefix = "Predicted stable behavior from consistent metadata and low drift"
    elif category == "increasing_risk":
        prefix = "Predicted increasing behavioral risk from drift, risk evolution, and graph context"
    elif category == "decreasing_risk":
        prefix = "Predicted decreasing behavioral risk from historical risk reduction"
    elif category == "emerging_behavior":
        prefix = "Predicted emerging behavior from newly active cluster and relationship context"
    else:
        prefix = "Prediction remains uncertain because metadata support is limited"
    return _safe_text(f"{prefix}; score:{score:.2f}; horizon:{horizon}; reasons:{len(reasons)}", limit=180)


def _prediction_next_steps(category: str) -> str:
    if category == "stable_behavior":
        return "Continue routine observation and confirm the profile remains stable over future summaries."
    if category == "increasing_risk":
        return "Review risk evolution, drift, cluster trend, and investigation recommendations before taking any operator-approved action."
    if category == "decreasing_risk":
        return "Confirm the risk reduction is expected and continue observing for renewed drift or relationship growth."
    if category == "emerging_behavior":
        return "Collect additional observations and verify whether the emerging cluster matches expected service behavior."
    return "Gather more metadata, review missing evidence, and reassess once additional observations are available."


def _prediction_risk_level(score: float) -> str:
    if score >= 0.82:
        return "critical"
    if score >= 0.62:
        return "high"
    if score >= 0.35:
        return "medium"
    return "low"


def _prediction_cluster_risk_score(value: Any) -> float:
    return {"critical": 1.0, "high": 0.74, "medium": 0.44, "low": 0.16}.get(_safe_text(value), 0.0)


def _prediction_priority_score(value: Any) -> float:
    return {"critical": 1.0, "high": 0.74, "medium": 0.44, "low": 0.16, "none": 0.0}.get(
        _safe_text(value),
        0.0,
    )


def _prediction_direction_score(value: Any) -> float:
    return {
        "increasing": 1.0,
        "fluctuating": 0.78,
        "insufficient_history": 0.40,
        "stable": 0.22,
        "decreasing": 0.08,
    }.get(_safe_text(value), 0.30)


def _federated_intelligence_inputs(
    observation: dict[str, Any],
    classification_model: dict[str, Any],
    learning_profile_history: dict[str, Any],
    explicit: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for source in (
        explicit,
        observation.get("federated_intelligence"),
        observation.get("federated_metadata"),
        observation.get("peer_intelligence"),
        classification_model.get("federated_intelligence"),
        learning_profile_history.get("federated_intelligence"),
    ):
        if isinstance(source, dict):
            source = source.get("items") or source.get("records") or source.get("intelligence") or [source]
        if not isinstance(source, Iterable) or isinstance(source, (str, bytes)):
            continue
        for item in source:
            if isinstance(item, dict):
                rows.append(dict(item))
    return rows


def _build_federated_intelligence_model(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    review_queue: dict[str, Any],
    threat_prediction: dict[str, Any],
    *,
    context: dict[str, Any],
    related: dict[str, str],
    generated_at: str,
    peer_intelligence: Iterable[dict[str, Any]] | None,
) -> dict[str, Any]:
    peer_rows = list(peer_intelligence or [])
    has_local_metadata = bool(
        relationships
        or clusters
        or insights
        or context
        or any(_safe_text(value) != "-" for value in related.values())
    )
    objects = []
    if has_local_metadata:
        objects.append(
            _local_federated_intelligence_object(
                relationships,
                clusters,
                insights,
                risk_evolution,
                behavioral_decision,
                investigation_recommendations,
                review_queue,
                threat_prediction,
                context=context,
                related=related,
                generated_at=generated_at,
            )
        )
    for item in peer_rows:
        normalized = _normalize_federated_intelligence_object(item, generated_at=generated_at)
        if normalized:
            objects.append(normalized)
    objects = sorted(objects, key=lambda row: (row["intelligence_category"], row["subject"], row["value"], row["originating_node_id"]))
    merged = _merge_federated_intelligence(objects, generated_at=generated_at)
    return {
        "record_type": "federated_intelligence_summary",
        "record_version": FEDERATED_INTELLIGENCE_SCHEMA_VERSION,
        "federated_status": merged["status"],
        "consensus": merged["consensus"],
        "agreement_score": merged["agreement_score"],
        "agreement_percentage": f"{int(round(merged['agreement_score'] * 100))}%",
        "federated_confidence": merged["confidence"],
        "federated_observation_count": merged["observation_count"],
        "originating_nodes": "; ".join(merged["nodes"]) if merged["nodes"] else "-",
        "source_nodes": "; ".join(merged["nodes"]) if merged["nodes"] else "-",
        "contributors": "; ".join(merged["contributors"]) if merged["contributors"] else "-",
        "source_count": len(merged["nodes"]),
        "unique_contributors": len(merged["contributors"]),
        "conflicts": len(merged["conflicts"]),
        "conflict_summary": _federated_conflict_summary(merged["conflicts"]),
        "consensus_summary": _federated_consensus_summary(merged),
        "confidence_trend": _federated_confidence_trend(objects),
        "federated_age": _duration_label(merged["first_seen"], generated_at),
        "federated_freshness": _federated_freshness(merged["last_seen"], generated_at),
        "expiration": merged["expiration"],
        "operator_recommendation": _federated_operator_recommendation(merged),
        "objects": objects,
        "merged_objects": merged["merged_objects"],
        "metadata_only": True,
        "read_only": True,
        "advisory_only": True,
        "packets_shared": False,
        "payloads_shared": False,
        "credentials_shared": False,
        "external_connectivity": False,
    }


def _local_federated_intelligence_object(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    review_queue: dict[str, Any],
    threat_prediction: dict[str, Any],
    *,
    context: dict[str, Any],
    related: dict[str, str],
    generated_at: str,
) -> dict[str, Any]:
    category = "prediction_summary" if threat_prediction else "behavioral_summary"
    subject = _safe_text(related.get("related_service") or context.get("top_classification") or "observed_service")
    value = _safe_text(
        threat_prediction.get("prediction_category")
        or behavioral_decision.get("behavioral_decision_category")
        or context.get("top_classification")
    )
    confidence = float(
        threat_prediction.get("prediction_confidence")
        or behavioral_decision.get("behavioral_decision_confidence")
        or context.get("candidate_confidence")
        or 0.0
    )
    expiration = _iso_timestamp(_parse_time(generated_at) + timedelta(days=7) if _parse_time(generated_at) else None)
    return _normalize_federated_intelligence_object(
        {
            "originating_node_id": context.get("originating_node") or "local_node",
            "created_at": generated_at,
            "observation_count": int(context.get("observation_count") or 1),
            "confidence": confidence,
            "expiration": expiration,
            "intelligence_category": category,
            "subject": subject,
            "value": value,
            "metadata": {
                "top_classification": context.get("top_classification"),
                "relationships": len(relationships),
                "clusters": len(clusters),
                "insights": len(insights),
                "risk_direction": risk_evolution.get("risk_evolution_direction"),
                "review_priority": review_queue.get("review_queue_priority"),
                "investigation_count": len(investigation_recommendations),
            },
        },
        generated_at=generated_at,
    )


def _normalize_federated_intelligence_object(raw: dict[str, Any], *, generated_at: str) -> dict[str, Any] | None:
    category = _safe_text(raw.get("intelligence_category") or raw.get("category"))
    if category not in FEDERATED_INTELLIGENCE_CATEGORIES:
        category = "behavioral_summary"
    node_id = _safe_text(raw.get("originating_node_id") or raw.get("node_id") or raw.get("originating_node"))
    if node_id == "-":
        node_id = "unknown_node"
    created_at = _safe_text(raw.get("creation_timestamp") or raw.get("created_at") or raw.get("timestamp") or generated_at)
    subject = _safe_text(raw.get("subject") or raw.get("service") or raw.get("profile") or raw.get("application"))
    if subject == "-":
        subject = "observed_service"
    value = _safe_text(
        raw.get("value")
        or raw.get("classification")
        or raw.get("prediction_category")
        or raw.get("indicator")
        or raw.get("summary")
    )
    if value == "-":
        value = "observed_metadata"
    observation_count = max(_optional_int(raw.get("observation_count") or raw.get("observations")) or 1, 1)
    confidence = _bounded_score(float(raw.get("confidence") or raw.get("confidence_score") or 0.0))
    expiration = _safe_text(raw.get("expiration_timestamp") or raw.get("expiration") or raw.get("expires_at"))
    if expiration == "-":
        parsed = _parse_time(created_at) or _parse_time(generated_at)
        expiration = _iso_timestamp(parsed + timedelta(days=7) if parsed else None)
    schema_version = _safe_text(raw.get("schema_version") or FEDERATED_INTELLIGENCE_SCHEMA_VERSION)
    intelligence_id = _safe_text(raw.get("intelligence_id") or raw.get("id"))
    if intelligence_id == "-":
        intelligence_id = "federated-intel-" + _digest(
            {
                "node": node_id,
                "created_at": created_at,
                "category": category,
                "subject": subject,
                "value": value,
            }
        )[:16]
    return {
        "intelligence_id": intelligence_id,
        "originating_node_id": node_id,
        "creation_timestamp": created_at,
        "observation_count": observation_count,
        "confidence": confidence,
        "expiration_timestamp": expiration,
        "intelligence_category": category,
        "schema_version": schema_version,
        "subject": subject,
        "value": value,
        "metadata": _safe_metadata(raw.get("metadata") if isinstance(raw.get("metadata"), dict) else {}),
        "metadata_only": True,
        "read_only": True,
    }


def _merge_federated_intelligence(objects: list[dict[str, Any]], *, generated_at: str) -> dict[str, Any]:
    if not objects:
        return _empty_federated_merge(generated_at)
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for item in objects:
        key = (item["intelligence_category"], item["subject"])
        group = groups.setdefault(key, {"values": {}, "items": []})
        group["items"].append(item)
        group["values"].setdefault(item["value"], []).append(item)
    merged_objects = []
    conflicts = []
    confidence_values = []
    total_observations = 0
    nodes = set()
    for key, group in sorted(groups.items()):
        value_groups = group["values"]
        if len(value_groups) > 1:
            conflicts.append(
                {
                    "category": key[0],
                    "subject": key[1],
                    "reason": "conflicting_values",
                    "values": sorted(value_groups),
                }
            )
        for value, rows in sorted(value_groups.items()):
            nodes_for_value = sorted({row["originating_node_id"] for row in rows})
            observations = sum(int(row["observation_count"]) for row in rows)
            confidence = _federated_weighted_confidence(rows)
            confidence_values.append(confidence)
            total_observations += observations
            nodes.update(nodes_for_value)
            merged_objects.append(
                {
                    "merge_key": "|".join([key[0], key[1], value]),
                    "category": key[0],
                    "subject": key[1],
                    "value": value,
                    "source_count": len(nodes_for_value),
                    "observation_count": observations,
                    "merged_confidence": confidence,
                    "originating_nodes": nodes_for_value,
                    "conflict": len(value_groups) > 1,
                }
            )
    best_group_size = max((row["source_count"] for row in merged_objects), default=0)
    source_count = len(nodes)
    agreement_score = _bounded_score(best_group_size / max(source_count, 1))
    expiration = _federated_expiration(objects)
    consensus = _federated_consensus(
        source_count=source_count,
        agreement_score=agreement_score,
        confidence=max(confidence_values) if confidence_values else 0.0,
        conflicts=conflicts,
        expiration=expiration,
        generated_at=generated_at,
    )
    status = "expired" if consensus == "expired" else ("conflict" if conflicts else "active")
    return {
        "status": status,
        "consensus": consensus,
        "agreement_score": agreement_score,
        "confidence": max(confidence_values) if confidence_values else 0.0,
        "observation_count": total_observations,
        "nodes": sorted(nodes),
        "contributors": sorted(nodes),
        "conflicts": conflicts,
        "merged_objects": merged_objects,
        "first_seen": _federated_first_seen(objects),
        "last_seen": _federated_last_seen(objects),
        "expiration": expiration,
    }


def _federated_weighted_confidence(rows: list[dict[str, Any]]) -> float:
    remaining = 1.0
    for row in sorted(rows, key=lambda item: (item["originating_node_id"], item["intelligence_id"])):
        confidence = _bounded_score(float(row.get("confidence") or 0.0))
        observations = min(int(row.get("observation_count") or 1), 10)
        weighted = min(confidence + (observations - 1) * 0.015, 0.95)
        remaining *= 1.0 - weighted
    return _bounded_score(1.0 - remaining)


def _federated_consensus(
    *,
    source_count: int,
    agreement_score: float,
    confidence: float,
    conflicts: list[dict[str, Any]],
    expiration: str,
    generated_at: str,
) -> str:
    if source_count <= 0:
        return "unknown"
    if _is_expired(expiration, generated_at):
        return "expired"
    if conflicts:
        return "conflicting"
    if source_count == 1:
        return "single_source"
    if source_count >= 3 and agreement_score >= 0.75 and confidence >= 0.70:
        return "strong_consensus"
    if agreement_score < 0.60 or confidence < 0.45:
        return "weak_consensus"
    return "multi_source"


def _federated_confidence_trend(objects: list[dict[str, Any]]) -> str:
    rows = sorted(objects, key=lambda row: (row["creation_timestamp"], row["originating_node_id"], row["intelligence_id"]))
    values = [float(row.get("confidence") or 0.0) for row in rows]
    if len(values) < 2:
        return "stable"
    delta = values[-1] - values[0]
    if max(values) - min(values) >= 0.35:
        return "volatile"
    if delta >= 0.08:
        return "increasing"
    if delta <= -0.08:
        return "decreasing"
    return "stable"


def _federated_consensus_summary(merged: dict[str, Any]) -> str:
    consensus = merged["consensus"]
    source_count = len(merged["nodes"])
    if consensus == "expired":
        return "Observation expired."
    if consensus == "conflicting":
        return "Conflicting classifications detected."
    if consensus == "single_source":
        return "Observed by one worker only."
    if consensus == "strong_consensus":
        return f"Observed independently by {source_count} workers."
    if consensus == "multi_source":
        return f"Observed by {source_count} workers with compatible metadata."
    if consensus == "weak_consensus":
        return f"Observed by {source_count} workers with limited agreement."
    return "No federated consensus available."


def _federated_conflict_summary(conflicts: list[dict[str, Any]]) -> str:
    if not conflicts:
        return "none"
    rows = []
    for conflict in sorted(conflicts, key=lambda row: (row["category"], row["subject"]))[:3]:
        rows.append(f"{conflict['category']}:{conflict['subject']}:{','.join(conflict['values'])}")
    return _safe_text("; ".join(rows), limit=180)


def _federated_operator_recommendation(merged: dict[str, Any]) -> str:
    consensus = merged["consensus"]
    if consensus == "expired":
        return "Refresh federated metadata before relying on this observation."
    if consensus == "conflicting":
        return "Review conflicting worker metadata and preserve local authority for decisions."
    if consensus == "strong_consensus":
        return "Use federated context as supporting evidence while keeping local decisions authoritative."
    if consensus in {"multi_source", "weak_consensus"}:
        return "Compare contributor metadata and continue local observation before escalation."
    if consensus == "single_source":
        return "Treat as single-worker context until additional nodes independently observe it."
    return "Collect local metadata before using federated context."


def _federated_freshness(last_seen: str, generated_at: str) -> str:
    last = _parse_time(last_seen)
    now = _parse_time(generated_at)
    if not last or not now:
        return "unknown"
    seconds = max((now - last).total_seconds(), 0)
    if seconds <= 3600:
        return "fresh"
    if seconds <= 86_400:
        return "recent"
    return "stale"


def _federated_first_seen(objects: list[dict[str, Any]]) -> str:
    values = sorted(value for value in (_parse_time(row.get("creation_timestamp")) for row in objects) if value)
    return _iso_timestamp(values[0] if values else None)


def _federated_last_seen(objects: list[dict[str, Any]]) -> str:
    values = sorted(value for value in (_parse_time(row.get("creation_timestamp")) for row in objects) if value)
    return _iso_timestamp(values[-1] if values else None)


def _federated_expiration(objects: list[dict[str, Any]]) -> str:
    values = sorted(value for value in (_parse_time(row.get("expiration_timestamp")) for row in objects) if value)
    return _iso_timestamp(values[0] if values else None)


def _is_expired(expiration: str, generated_at: str) -> bool:
    expires = _parse_time(expiration)
    now = _parse_time(generated_at)
    return bool(expires and now and expires <= now)


def _empty_federated_merge(generated_at: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "consensus": "unknown",
        "agreement_score": 0.0,
        "confidence": 0.0,
        "observation_count": 0,
        "nodes": [],
        "contributors": [],
        "conflicts": [],
        "merged_objects": [],
        "first_seen": generated_at,
        "last_seen": generated_at,
        "expiration": "-",
    }


def _iso_timestamp(value: datetime | None) -> str:
    if value is None:
        return "-"
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.astimezone(UTC).isoformat()


def _build_autonomous_investigation_chains(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    review_queue: dict[str, Any],
    threat_prediction: dict[str, Any],
    federated_model: dict[str, Any],
    *,
    context: dict[str, Any],
    related: dict[str, str],
) -> list[dict[str, Any]]:
    if not _has_investigation_chain_context(
        relationships,
        clusters,
        insights,
        risk_evolution,
        behavioral_decision,
        investigation_recommendations,
        review_queue,
        threat_prediction,
        federated_model,
        context=context,
        related=related,
    ):
        return []

    rows: list[dict[str, Any]] = []
    decision = _safe_text(behavioral_decision.get("behavioral_decision_category"))
    review_priority = _safe_text(review_queue.get("review_queue_priority"))
    risk_direction = _safe_text(risk_evolution.get("risk_evolution_direction"))
    prediction_category = _safe_text(threat_prediction.get("prediction_category"))
    consensus = _safe_text(federated_model.get("consensus"))
    evidence_quality = _safe_text(context.get("evidence_quality")).lower()
    missing_evidence = context.get("missing_evidence")
    if not isinstance(missing_evidence, list):
        missing_evidence = []
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    stability_label = _safe_text(context.get("profile_stability_label"))
    drift_score = float(context.get("drift_score") or 0.0)

    if review_priority in {"critical", "high"} or decision in {"elevated_risk_behavior", "investigate_behavior"}:
        rows.append(
            _investigation_chain_record(
                "behavior_review_chain",
                _chain_priority_from_review(review_priority, decision),
                confidence=_chain_confidence(behavioral_decision.get("behavioral_decision_confidence"), review_queue.get("review_queue_priority")),
                reason=f"decision:{decision}; review_priority:{review_priority}",
                evidence=[
                    f"behavioral_decision:{decision}",
                    f"review_queue:{review_priority}",
                    f"review_reason:{_safe_text(review_queue.get('review_queue_reason'))}",
                ],
                limitations=_chain_limitations(context, risk_evolution, federated_model),
                next_steps="Review behavioral decision, queue context, and supporting evidence before any operator-approved action.",
                related=related,
                threat_prediction=threat_prediction,
                review_queue=review_queue,
                federated_model=federated_model,
            )
        )
    if risk_direction in {"increasing", "decreasing", "fluctuating", "insufficient_history"}:
        rows.append(
            _investigation_chain_record(
                "risk_evolution_chain",
                _chain_priority_from_risk_direction(risk_direction),
                confidence=_chain_confidence(risk_evolution.get("risk_evolution_confidence"), context.get("candidate_confidence")),
                reason=f"risk_direction:{risk_direction}; risk_delta:{risk_evolution.get('risk_delta', '-')}",
                evidence=[
                    f"risk_direction:{risk_direction}",
                    f"risk_velocity:{_safe_text(risk_evolution.get('risk_evolution_velocity'))}",
                    f"risk_reasons:{_safe_text(risk_evolution.get('risk_change_reasons'))}",
                ],
                limitations=_chain_limitations(context, risk_evolution, federated_model),
                next_steps=(
                    "Collect more observations before drawing conclusions."
                    if risk_direction == "insufficient_history"
                    else "Compare current and historical risk metadata for expected behavior changes."
                ),
                related=related,
                threat_prediction=threat_prediction,
                review_queue=review_queue,
                federated_model=federated_model,
            )
        )
    if prediction_category in {"increasing_risk", "emerging_behavior", "uncertain_prediction", "decreasing_risk"}:
        rows.append(
            _investigation_chain_record(
                "prediction_validation_chain",
                _chain_priority_from_prediction(prediction_category, threat_prediction),
                confidence=_chain_confidence(threat_prediction.get("prediction_confidence"), threat_prediction.get("predicted_risk_score")),
                reason=f"prediction:{prediction_category}; horizon:{_safe_text(threat_prediction.get('prediction_horizon'))}",
                evidence=[
                    f"prediction:{prediction_category}",
                    f"predicted_level:{_safe_text(threat_prediction.get('predicted_risk_level'))}",
                    f"prediction_reasons:{_safe_text(threat_prediction.get('prediction_reasons'))}",
                ],
                limitations=_chain_text_list(threat_prediction.get("prediction_limitations")),
                next_steps="Validate prediction inputs against risk evolution, graph insights, and future local observations.",
                related=related,
                threat_prediction=threat_prediction,
                review_queue=review_queue,
                federated_model=federated_model,
            )
        )
    if consensus in {"conflicting", "expired", "weak_consensus", "strong_consensus"}:
        rows.append(
            _investigation_chain_record(
                "federated_consensus_chain",
                _chain_priority_from_consensus(consensus),
                confidence=_chain_confidence(federated_model.get("federated_confidence"), federated_model.get("agreement_score")),
                reason=f"federated_consensus:{consensus}; conflicts:{federated_model.get('conflicts', 0)}",
                evidence=[
                    f"consensus:{consensus}",
                    f"agreement:{federated_model.get('agreement_percentage', '-')}",
                    f"conflicts:{federated_model.get('conflict_summary', '-')}",
                ],
                limitations=["federated_metadata_is_supporting_context_only"],
                next_steps="Validate federated context locally and preserve node-authoritative decisions.",
                related=related,
                threat_prediction=threat_prediction,
                review_queue=review_queue,
                federated_model=federated_model,
            )
        )
    if missing_evidence or evidence_quality in {"-", "weak", "limited", "low", "unknown"} or candidate_confidence < 0.50:
        rows.append(
            _investigation_chain_record(
                "missing_evidence_chain",
                "medium" if candidate_confidence < 0.50 else "low",
                confidence=_chain_confidence(candidate_confidence, 0.45),
                reason=f"evidence_quality:{evidence_quality}; missing:{len(missing_evidence)}",
                evidence=[f"missing:{item}" for item in missing_evidence[:6]] or [f"evidence_quality:{evidence_quality}"],
                limitations=["classification_requires_more_metadata"],
                next_steps="Verify service identity, process evidence, expected-service records, and historical observations.",
                related=related,
                threat_prediction=threat_prediction,
                review_queue=review_queue,
                federated_model=federated_model,
            )
        )
    top_investigation = _top_investigation_recommendation(investigation_recommendations)
    top_category = _safe_text(top_investigation.get("category"))
    if top_category in {"verify_service_identity", "review_missing_evidence"} or int(context.get("candidate_count") or 0) > 1:
        rows.append(
            _investigation_chain_record(
                "identity_verification_chain",
                _safe_text(top_investigation.get("priority")) if top_investigation else "medium",
                confidence=_chain_confidence(context.get("candidate_confidence"), top_investigation.get("expected_confidence_gain")),
                reason=f"top_recommendation:{top_category}; candidates:{int(context.get('candidate_count') or 0)}",
                evidence=[
                    f"top_classification:{_safe_text(context.get('top_classification'))}",
                    f"candidate_count:{int(context.get('candidate_count') or 0)}",
                    f"top_recommendation:{top_category}",
                ],
                limitations=_chain_limitations(context, risk_evolution, federated_model),
                next_steps="Confirm the service/application identity using existing metadata and operator expectations.",
                related=related,
                threat_prediction=threat_prediction,
                review_queue=review_queue,
                federated_model=federated_model,
            )
        )
    if (
        prediction_category == "stable_behavior"
        or decision == "benign_observation"
        or stability_label in {"stable", "highly_stable"}
    ) and drift_score <= 0.25:
        rows.append(
            _investigation_chain_record(
                "stability_monitoring_chain",
                "low",
                confidence=_chain_confidence(context.get("profile_stability"), threat_prediction.get("prediction_confidence")),
                reason=f"stable_context:{stability_label}; drift:{drift_score:.2f}",
                evidence=[
                    f"prediction:{prediction_category}",
                    f"decision:{decision}",
                    f"stability:{stability_label}",
                    f"drift:{drift_score:.2f}",
                ],
                limitations=["routine_monitoring_only"],
                next_steps="Continue local observation and watch for drift, prediction changes, or federated conflicts.",
                related=related,
                threat_prediction=threat_prediction,
                review_queue=review_queue,
                federated_model=federated_model,
            )
        )
    return _dedupe_investigation_chains(rows)


def _has_investigation_chain_context(
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    risk_evolution: dict[str, Any],
    behavioral_decision: dict[str, Any],
    investigation_recommendations: list[dict[str, Any]],
    review_queue: dict[str, Any],
    threat_prediction: dict[str, Any],
    federated_model: dict[str, Any],
    *,
    context: dict[str, Any],
    related: dict[str, str],
) -> bool:
    if relationships or clusters or insights or investigation_recommendations or context:
        return True
    if any(_safe_text(value) != "-" for value in related.values()):
        return True
    return any(
        _safe_text(row.get(field))
        not in {"-", "unknown", "none", "insufficient_context", "insufficient_history", "uncertain_prediction"}
        for row, field in (
            (risk_evolution, "risk_evolution_direction"),
            (behavioral_decision, "behavioral_decision_category"),
            (review_queue, "review_queue_priority"),
            (threat_prediction, "prediction_category"),
            (federated_model, "consensus"),
        )
    )


def _investigation_chain_record(
    category: str,
    priority: str,
    *,
    confidence: float,
    reason: str,
    evidence: list[str],
    limitations: list[str],
    next_steps: str,
    related: dict[str, str],
    threat_prediction: dict[str, Any],
    review_queue: dict[str, Any],
    federated_model: dict[str, Any],
) -> dict[str, Any]:
    safe_category = category if category in INVESTIGATION_CHAIN_CATEGORIES else "behavior_review_chain"
    safe_priority = priority if priority in INVESTIGATION_CHAIN_PRIORITIES else "medium"
    safe_evidence = sorted(_unique_text(evidence, limit=10))
    safe_limitations = sorted(_unique_text(limitations, limit=8)) or ["no_major_limitations"]
    chain_id = "investigation-chain-" + _digest(
        {
            "category": safe_category,
            "priority": safe_priority,
            "reason": reason,
            "evidence": safe_evidence,
            "related_asset": related.get("related_asset"),
            "related_service": related.get("related_service"),
            "related_profile": related.get("related_profile"),
            "prediction": threat_prediction.get("prediction_category"),
            "review": review_queue.get("review_queue_priority"),
            "consensus": federated_model.get("consensus"),
        }
    )[:16]
    return {
        "chain_id": chain_id,
        "chain_category": safe_category,
        "chain_priority": safe_priority,
        "chain_confidence": _bounded_score(confidence),
        "chain_status": "advisory_pending_review" if safe_priority in {"critical", "high"} else "advisory_observe",
        "chain_reason": _safe_text(reason, limit=160),
        "chain_evidence": _safe_text("; ".join(safe_evidence), limit=220),
        "chain_limitations": _safe_text("; ".join(safe_limitations), limit=180),
        "chain_next_steps": _safe_text(next_steps, limit=200),
        "related_asset": related.get("related_asset") or "-",
        "related_service": related.get("related_service") or "-",
        "related_profile": related.get("related_profile") or "-",
        "related_prediction": threat_prediction.get("prediction_category", "-"),
        "related_review_queue": review_queue.get("review_queue_priority", "-"),
        "related_federated_consensus": federated_model.get("consensus", "-"),
        "metadata_only": True,
        "read_only": True,
        "advisory_only": True,
        "automated_action": False,
        "enforcement_enabled": False,
    }


def _dedupe_investigation_chains(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["chain_category"], row["chain_reason"])
        current = deduped.get(key)
        if current is None or _investigation_chain_sort_key(row) < _investigation_chain_sort_key(current):
            deduped[key] = row
    return sorted(deduped.values(), key=_investigation_chain_sort_key)


def _investigation_chain_sort_key(row: dict[str, Any]) -> tuple[int, float, str, str]:
    priority_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return (
        priority_rank.get(_safe_text(row.get("chain_priority")), 2),
        -float(row.get("chain_confidence") or 0.0),
        _safe_text(row.get("chain_category")),
        _safe_text(row.get("chain_id")),
    )


def _top_investigation_chain(rows: list[dict[str, Any]]) -> dict[str, Any]:
    return rows[0] if rows else {}


def _investigation_chain_summary(rows: list[dict[str, Any]]) -> str:
    if not rows:
        return "-"
    return "; ".join(
        f"{row['chain_priority']}:{row['chain_category']}:{row['chain_id']}"
        for row in sorted(rows, key=_investigation_chain_sort_key)[:3]
    )


def _investigation_chain_next_steps(top: dict[str, Any]) -> str:
    if not top:
        return "-"
    return _safe_text(top.get("chain_next_steps"), limit=200)


def _chain_confidence(*values: Any) -> float:
    parsed = [_optional_float(value) for value in values]
    parsed = [value for value in parsed if value is not None]
    if not parsed:
        return 0.35
    return _bounded_score((sum(parsed) / len(parsed)) * 0.75 + max(parsed) * 0.25)


def _chain_priority_from_review(review_priority: str, decision: str) -> str:
    if review_priority == "critical":
        return "critical"
    if review_priority == "high" or decision == "elevated_risk_behavior":
        return "high"
    if review_priority == "medium" or decision == "investigate_behavior":
        return "medium"
    return "low"


def _chain_priority_from_risk_direction(direction: str) -> str:
    if direction == "increasing":
        return "high"
    if direction in {"fluctuating", "insufficient_history"}:
        return "medium"
    if direction == "decreasing":
        return "low"
    return "low"


def _chain_priority_from_prediction(category: str, prediction: dict[str, Any]) -> str:
    level = _safe_text(prediction.get("predicted_risk_level"))
    if category == "increasing_risk" and level in {"critical", "high"}:
        return "high"
    if category == "uncertain_prediction":
        return "medium"
    if category == "emerging_behavior":
        return "medium"
    return "low"


def _chain_priority_from_consensus(consensus: str) -> str:
    if consensus == "conflicting":
        return "high"
    if consensus in {"expired", "weak_consensus"}:
        return "medium"
    return "low"


def _chain_limitations(
    context: dict[str, Any],
    risk_evolution: dict[str, Any],
    federated_model: dict[str, Any],
) -> list[str]:
    limitations: list[str] = []
    if int(context.get("observation_count") or 0) <= 2:
        limitations.append("limited_observation_history")
    if float(context.get("candidate_confidence") or 0.0) < 0.50:
        limitations.append("low_attribution_confidence")
    if _safe_text(risk_evolution.get("risk_evolution_direction")) == "insufficient_history":
        limitations.append("insufficient_risk_history")
    if _safe_text(federated_model.get("consensus")) in {"unknown", "single_source"}:
        limitations.append("limited_federated_context")
    return limitations or ["operator_review_only"]


def _chain_text_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_safe_text(item) for item in value if _safe_text(item) != "-"]
    text = _safe_text(value)
    if text == "-":
        return []
    return [part.strip() for part in text.split(";") if part.strip()]


def _behavioral_decision_category(
    *,
    risk_score: float,
    candidate_confidence: float,
    cluster_risk: str,
    cluster_trend: str,
    insight_score: float,
    risk_direction: str,
    drift_score: float,
    stability_label: str,
    observation_count: int,
    evidence_quality: str,
    relationship_count: int,
    cluster_count: int,
    has_profile_metadata: bool,
) -> str:
    weak_evidence = evidence_quality in {"-", "weak", "limited", "low", "unknown"}
    missing_context = (
        observation_count <= 1
        and candidate_confidence < 0.50
        and weak_evidence
        and (not has_profile_metadata or relationship_count == 0 or cluster_count == 0)
    )
    if missing_context:
        return "insufficient_context"
    if cluster_risk == "critical" and cluster_trend in {"emerging", "growing"} and risk_score >= 0.70:
        return "elevated_risk_behavior"
    if risk_score >= 0.86 or (cluster_risk in {"high", "critical"} and insight_score >= 0.70):
        return "elevated_risk_behavior"
    if risk_score >= 0.62 or cluster_risk == "high" or drift_score >= 0.60:
        return "investigate_behavior"
    if risk_direction in {"increasing", "fluctuating"} and insight_score >= 0.45:
        return "investigate_behavior"
    if risk_score <= 0.30 and stability_label == "stable" and drift_score <= 0.15 and observation_count >= 3:
        return "benign_observation"
    if risk_score <= 0.25 and cluster_risk in {"-", "low"} and risk_direction in {"stable", "decreasing"}:
        return "benign_observation"
    return "monitor_behavior"


def _behavioral_decision_reasons(
    *,
    category: str,
    risk_score: float,
    candidate_confidence: float,
    cluster_risk: str,
    cluster_trend: str,
    insight_score: float,
    risk_direction: str,
    drift_score: float,
    stability_label: str,
    observation_count: int,
    evidence_quality: str,
    relationship_count: int,
    cluster_count: int,
) -> list[str]:
    reasons = [
        f"category:{category}",
        f"risk_score:{risk_score:.2f}",
        f"classification_confidence:{candidate_confidence:.2f}",
        f"evidence_quality:{evidence_quality or '-'}",
        f"observations:{observation_count}",
    ]
    if cluster_risk != "-":
        reasons.append(f"cluster_risk:{cluster_risk}")
    if cluster_trend != "-":
        reasons.append(f"cluster_trend:{cluster_trend}")
    if insight_score:
        reasons.append(f"graph_insight_score:{insight_score:.2f}")
    if risk_direction != "-":
        reasons.append(f"risk_direction:{risk_direction}")
    if drift_score:
        reasons.append(f"drift_score:{drift_score:.2f}")
    if stability_label != "-":
        reasons.append(f"profile_stability:{stability_label}")
    if relationship_count:
        reasons.append(f"relationships:{relationship_count}")
    if cluster_count:
        reasons.append(f"clusters:{cluster_count}")
    return sorted(_unique_text(reasons, limit=16))


def _behavioral_decision_evidence(
    *,
    primary_cluster: dict[str, Any],
    strongest_insight: dict[str, Any],
    risk_evolution: dict[str, Any],
    context: dict[str, Any],
    relationship_count: int,
    cluster_count: int,
) -> list[str]:
    evidence = [
        f"top_classification:{_safe_text(context.get('top_classification'))}",
        f"primary_cluster:{_safe_text(primary_cluster.get('cluster_id'))}",
        f"primary_cluster_risk:{_safe_text(primary_cluster.get('cluster_risk_level'))}",
        f"primary_cluster_trend:{_safe_text(primary_cluster.get('cluster_trend'))}",
        f"strongest_graph_insight:{_safe_text(strongest_insight.get('insight_type'))}",
        f"risk_evolution:{_safe_text(risk_evolution.get('risk_evolution_direction'))}",
        f"relationships:{relationship_count}",
        f"clusters:{cluster_count}",
    ]
    recommendation = _safe_text(context.get("primary_recommendation"))
    if recommendation != "-":
        evidence.append(f"recommendation:{recommendation}")
    return sorted(_unique_text(evidence, limit=12))


def _behavioral_decision_limitations(
    *,
    candidate_confidence: float,
    evidence_quality: str,
    observation_count: int,
    risk_direction: str,
    has_profile_metadata: bool,
) -> list[str]:
    limitations: list[str] = []
    if candidate_confidence < 0.50:
        limitations.append("low_classification_confidence")
    if evidence_quality in {"-", "weak", "limited", "low", "unknown"}:
        limitations.append("weak_or_missing_evidence_quality")
    if observation_count <= 1:
        limitations.append("limited_observation_history")
    if risk_direction == "insufficient_history":
        limitations.append("insufficient_risk_history")
    if not has_profile_metadata:
        limitations.append("missing_learning_profile_context")
    return sorted(_unique_text(limitations, limit=8))


def _behavioral_decision_confidence(
    *,
    category: str,
    candidate_confidence: float,
    evidence_quality: str,
    observation_count: int,
    relationship_count: int,
    cluster_count: int,
    insight_score: float,
    risk_evolution_confidence: float,
    limitation_count: int,
) -> float:
    score = 0.34
    score += min(max(candidate_confidence, 0.0), 1.0) * 0.20
    score += min(observation_count, 6) / 6.0 * 0.12
    score += min(relationship_count, 6) / 6.0 * 0.10
    score += min(cluster_count, 5) / 5.0 * 0.08
    score += min(max(insight_score, 0.0), 1.0) * 0.08
    score += min(max(risk_evolution_confidence, 0.0), 1.0) * 0.08
    if evidence_quality in {"strong", "high"}:
        score += 0.08
    elif evidence_quality in {"moderate", "medium"}:
        score += 0.04
    if category == "insufficient_context":
        score = min(score, 0.42)
    score -= min(limitation_count, 4) * 0.04
    return _bounded_score(score)


def _behavioral_decision_summary(category: str, reasons: list[str]) -> str:
    reason_count = len(reasons)
    if category == "elevated_risk_behavior":
        return f"Elevated behavioral risk is supported by graph, cluster, or historical risk context ({reason_count} reasons)."
    if category == "investigate_behavior":
        return f"Behavior warrants operator investigation based on risk, drift, or graph evidence ({reason_count} reasons)."
    if category == "benign_observation":
        return f"Behavior currently appears expected or stable from available metadata ({reason_count} reasons)."
    if category == "monitor_behavior":
        return f"Behavior should remain under observation while additional metadata accumulates ({reason_count} reasons)."
    return f"Behavioral context is insufficient for a stronger advisory conclusion ({reason_count} reasons)."


def _behavioral_decision_next_steps(category: str) -> str:
    if category == "elevated_risk_behavior":
        return "Review cluster risk, graph insights, and risk evolution before approving any operator action."
    if category == "investigate_behavior":
        return "Inspect attribution evidence, drift, relationships, and recent risk changes."
    if category == "benign_observation":
        return "Continue routine observation and compare future changes against this stable context."
    if category == "monitor_behavior":
        return "Continue collecting metadata and recheck confidence, profile stability, and graph relationships."
    return "Gather additional observations, profile history, and attribution evidence before drawing conclusions."


def _risk_evolution_direction(*, delta: float | None, history: list[float], has_history: bool) -> str:
    if not has_history:
        return "insufficient_history"
    if _risk_history_is_fluctuating(history):
        return "fluctuating"
    if delta is None or abs(delta) < 0.05:
        return "stable"
    if delta > 0:
        return "increasing"
    return "decreasing"


def _risk_history_is_fluctuating(history: list[float]) -> bool:
    if len(history) < 3:
        return False
    deltas = [round(history[index] - history[index - 1], 3) for index in range(1, len(history))]
    positive = any(delta >= 0.08 for delta in deltas)
    negative = any(delta <= -0.08 for delta in deltas)
    spread = max(history) - min(history)
    return positive and negative and spread >= 0.18


def _risk_evolution_velocity(
    *,
    direction: str,
    delta: float | None,
    relationship_delta: int | None,
    signal_delta: int | None,
    cluster_delta: int | None,
) -> str:
    if direction == "insufficient_history":
        return "unknown"
    magnitude = abs(delta or 0.0)
    structural_change = max(
        abs(relationship_delta or 0),
        abs(signal_delta or 0),
        abs(cluster_delta or 0),
    )
    if direction == "fluctuating" or magnitude >= 0.35 or structural_change >= 4:
        return "rapid"
    if magnitude >= 0.15 or structural_change >= 2:
        return "moderate"
    return "slow"


def _risk_evolution_confidence(
    *,
    has_history: bool,
    observation_count: int,
    history_count: int,
    relationship_count: int,
    cluster_count: int,
    insight_count: int,
    reason_count: int,
) -> float:
    if not has_history:
        return 0.20 if observation_count <= 1 else 0.35
    score = 0.35
    if observation_count >= 3:
        score += 0.18
    if history_count >= 3:
        score += 0.14
    if relationship_count:
        score += 0.10
    if cluster_count:
        score += 0.08
    if insight_count:
        score += 0.08
    if reason_count > 1:
        score += 0.07
    return _bounded_score(score)


def _risk_change_reason_values(
    *,
    direction: str,
    delta: float | None,
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
    insights: list[dict[str, Any]],
    relationship_delta: int | None,
    signal_delta: int | None,
    cluster_delta: int | None,
    context: dict[str, Any],
) -> list[str]:
    reasons: list[str] = []
    if direction == "insufficient_history":
        reasons.append("insufficient_history")
    elif direction == "fluctuating":
        reasons.append("risk_score_fluctuation")
    elif direction == "increasing":
        reasons.append(f"risk_score_increase:{delta:.2f}")
    elif direction == "decreasing":
        reasons.append(f"risk_score_decrease:{delta:.2f}")
    else:
        reasons.append(f"risk_score_stable:{(delta or 0.0):.2f}")

    current_signals = set(context.get("risk_signals") or [])
    previous_signals = set(context.get("previous_risk_signals") or [])
    if previous_signals:
        for signal in sorted(current_signals - previous_signals)[:4]:
            reasons.append(f"signal_added:{signal}")
        for signal in sorted(previous_signals - current_signals)[:4]:
            reasons.append(f"signal_removed:{signal}")
    if relationship_delta is not None:
        if relationship_delta > 0:
            reasons.append(f"relationships_added:{relationship_delta}")
        elif relationship_delta < 0:
            reasons.append(f"relationships_removed:{abs(relationship_delta)}")
    if signal_delta is not None:
        if signal_delta > 0:
            reasons.append(f"signals_added:{signal_delta}")
        elif signal_delta < 0:
            reasons.append(f"signals_removed:{abs(signal_delta)}")
    if cluster_delta is not None:
        if cluster_delta > 0:
            reasons.append(f"clusters_expanded:{cluster_delta}")
        elif cluster_delta < 0:
            reasons.append(f"clusters_shrank:{abs(cluster_delta)}")
    drift_label = _safe_text(context.get("drift_label"))
    if drift_label in {"medium", "high"}:
        reasons.append(f"profile_drift:{drift_label}")
    stability_label = _safe_text(context.get("profile_stability_label"))
    if stability_label in {"unstable", "sparse"}:
        reasons.append(f"profile_stability:{stability_label}")
    if insights:
        reasons.append(f"graph_insights:{len(insights)}")
    if relationships:
        reasons.append(f"relationships:{len(relationships)}")
    if clusters:
        reasons.append(f"clusters:{len(clusters)}")
    candidate_confidence = float(context.get("candidate_confidence") or 0.0)
    if candidate_confidence and candidate_confidence < 0.50:
        reasons.append(f"classification_confidence:{candidate_confidence:.2f}")
    return sorted(_unique_text(reasons, limit=16))


def _risk_evolution_summary(direction: str, velocity: str, delta: float | None, reasons: list[str]) -> str:
    delta_text = f"{delta:+.2f}" if delta is not None else "-"
    return f"direction:{direction}; delta:{delta_text}; velocity:{velocity}; reasons:{len(reasons)}"


def _risk_operator_next_steps(direction: str) -> str:
    if direction == "increasing":
        return "Review new signals, relationships, and cluster changes before taking any action."
    if direction == "decreasing":
        return "Continue observation and confirm the reduction matches expected behavior."
    if direction == "stable":
        return "Continue monitoring and compare against future observations."
    if direction == "fluctuating":
        return "Review alternating risk drivers and recent metadata changes."
    return "Collect additional observations before interpreting risk evolution."


def _count_delta(current: int, previous: Any) -> int | None:
    prior = _optional_int(previous)
    if prior is None:
        return None
    return int(current) - prior


def _previous_risk_signal_values(observation: dict[str, Any], history_summary: dict[str, Any]) -> list[str]:
    values = _list_text(
        observation,
        ("previous_risk_signals", "prior_risk_signals", "historical_risk_signals", "previous_signals"),
    )
    values.extend(
        _list_text(
            history_summary,
            ("previous_risk_signals", "prior_risk_signals", "historical_risk_signals", "previous_signals"),
        )
    )
    return _unique_text(values)


def _risk_score_history_values(observation: dict[str, Any], history_summary: dict[str, Any]) -> list[float]:
    rows: list[float] = []
    for container in (observation, history_summary):
        for key in ("risk_score_history", "historical_risk_scores", "risk_history", "risk_scores"):
            value = container.get(key)
            if isinstance(value, list):
                for item in value:
                    score = _risk_history_score_value(item)
                    if score is not None:
                        rows.append(score)
    return rows


def _risk_history_score_value(value: Any) -> float | None:
    if isinstance(value, dict):
        return _optional_float(
            _first_present_value(value.get("risk_score"), value.get("score"), value.get("value"), value.get("confidence"))
        )
    return _optional_float(value)


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


def _build_graph_insights(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    insights: dict[str, dict[str, Any]] = {}
    for cluster in clusters:
        _maybe_add_graph_insight(
            insights,
            _emerging_risk_cluster_insight(cluster),
        )
        _maybe_add_graph_insight(
            insights,
            _repeated_risk_signal_insight(cluster),
        )
        _maybe_add_graph_insight(
            insights,
            _unstable_identity_insight(cluster),
        )
        _maybe_add_graph_insight(
            insights,
            _ambiguous_application_cluster_insight(cluster),
        )
        _maybe_add_graph_insight(
            insights,
            _low_confidence_high_risk_insight(cluster),
        )
    _maybe_add_graph_insight(
        insights,
        _high_relationship_density_insight(nodes, edges, relationships, clusters),
    )
    return sorted(
        insights.values(),
        key=lambda row: (-float(row.get("insight_score") or 0.0), str(row.get("insight_type") or ""), str(row.get("insight_id") or "")),
    )


def _maybe_add_graph_insight(insights: dict[str, dict[str, Any]], insight: dict[str, Any] | None) -> None:
    if not insight:
        return
    insights.setdefault(str(insight.get("insight_id")), insight)


def _emerging_risk_cluster_insight(cluster: dict[str, Any]) -> dict[str, Any] | None:
    risk = _safe_text(cluster.get("cluster_risk_level"))
    trend = _safe_text(cluster.get("cluster_trend"))
    if risk not in {"high", "critical"} or trend not in {"emerging", "growing"}:
        return None
    score = _bounded_score(
        0.42
        + (_risk_rank(risk) * 0.14)
        + (float(cluster.get("cluster_evolution_score") or 0.0) * 0.22)
        + (float(cluster.get("cluster_confidence") or 0.0) * 0.12)
    )
    return _graph_insight(
        "emerging_risk_cluster",
        score,
        cluster,
        [
            f"risk:{risk}",
            f"trend:{trend}",
            f"evolution:{float(cluster.get('cluster_evolution_score') or 0.0):.2f}",
            f"relationships:{int(cluster.get('relationship_count') or 0)}",
        ],
        summary=f"{risk} {trend} cluster with active relationship or signal change",
    )


def _repeated_risk_signal_insight(cluster: dict[str, Any]) -> dict[str, Any] | None:
    if _safe_text(cluster.get("cluster_type")) != "risk_signal_cluster":
        return None
    relationship_count = int(cluster.get("relationship_count") or 0)
    if relationship_count <= 0:
        return None
    score = _bounded_score(
        0.35
        + min(relationship_count, 6) * 0.07
        + (_risk_rank(cluster.get("cluster_risk_level")) * 0.10)
        + (float(cluster.get("cluster_confidence") or 0.0) * 0.15)
    )
    return _graph_insight(
        "repeated_risk_signal",
        score,
        cluster,
        [
            f"risk:{_safe_text(cluster.get('cluster_risk_level'))}",
            f"relationships:{relationship_count}",
            f"signals:{int(cluster.get('new_signals') or 0)}",
        ],
        summary="Risk signal relationships recur within the behavior graph",
    )


def _unstable_identity_insight(cluster: dict[str, Any]) -> dict[str, Any] | None:
    stability = _safe_text(cluster.get("cluster_stability"))
    drift = _safe_text(cluster.get("cluster_drift"))
    if stability != "unstable" and drift not in {"medium", "high"}:
        return None
    score = _bounded_score(
        0.38
        + (0.18 if stability == "unstable" else 0.0)
        + (_drift_rank(drift) * 0.13)
        + (float(cluster.get("cluster_evolution_score") or 0.0) * 0.12)
    )
    return _graph_insight(
        "unstable_identity",
        score,
        cluster,
        [
            f"stability:{stability}",
            f"drift:{drift}",
            f"confidence:{float(cluster.get('cluster_confidence') or 0.0):.2f}",
        ],
        summary="Cluster identity is unstable or drifting across observations",
    )


def _ambiguous_application_cluster_insight(cluster: dict[str, Any]) -> dict[str, Any] | None:
    if _safe_text(cluster.get("cluster_type")) != "application_cluster":
        return None
    member_count = int(cluster.get("member_count") or 0)
    confidence = float(cluster.get("cluster_confidence") or 0.0)
    relationship_count = int(cluster.get("relationship_count") or 0)
    if member_count < 2 and not (relationship_count >= 1 and confidence < 0.70):
        return None
    score = _bounded_score(0.32 + min(member_count, 5) * 0.08 + max(0.0, 0.70 - confidence) * 0.25)
    return _graph_insight(
        "ambiguous_application_cluster",
        score,
        cluster,
        [
            f"members:{member_count}",
            f"confidence:{confidence:.2f}",
            f"relationships:{relationship_count}",
        ],
        summary="Multiple application candidates remain plausible for this cluster",
    )


def _high_relationship_density_insight(
    nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    clusters: list[dict[str, Any]],
) -> dict[str, Any] | None:
    entity_count = max(_related_entity_count(relationships), len(nodes), 1)
    relationship_count = len(relationships)
    density = relationship_count / entity_count
    if relationship_count < 4 or density < 0.75:
        return None
    primary = _primary_cluster(clusters)
    score = _bounded_score(0.30 + min(density, 2.0) * 0.22 + min(len(edges), 8) * 0.025)
    return _graph_insight(
        "high_relationship_density",
        score,
        primary,
        [
            f"relationships:{relationship_count}",
            f"entities:{entity_count}",
            f"density:{density:.2f}",
            f"edges:{len(edges)}",
        ],
        summary="Graph entities have dense relationship support",
    )


def _low_confidence_high_risk_insight(cluster: dict[str, Any]) -> dict[str, Any] | None:
    risk = _safe_text(cluster.get("cluster_risk_level"))
    confidence = float(cluster.get("cluster_confidence") or 0.0)
    if risk not in {"high", "critical"} or confidence > 0.55:
        return None
    score = _bounded_score(0.40 + (_risk_rank(risk) * 0.13) + ((0.55 - confidence) * 0.30))
    return _graph_insight(
        "low_confidence_high_risk",
        score,
        cluster,
        [
            f"risk:{risk}",
            f"confidence:{confidence:.2f}",
            f"reason:{_safe_text(cluster.get('primary_reason'))}",
        ],
        summary="Risk is elevated while graph confidence remains limited",
    )


def _graph_insight(
    insight_type: str,
    score: float,
    cluster: dict[str, Any],
    evidence: Iterable[Any],
    *,
    summary: str,
) -> dict[str, Any]:
    safe_type = insight_type if insight_type in GRAPH_INSIGHT_TYPES else "high_relationship_density"
    evidence_summary = _unique_text(evidence, limit=8)
    cluster_id = _safe_text(cluster.get("cluster_id") if isinstance(cluster, dict) else None)
    insight_id = "graph-insight-" + _digest(
        {
            "insight_type": safe_type,
            "cluster_id": cluster_id,
            "evidence": evidence_summary,
        }
    )[:16]
    return {
        "insight_id": insight_id,
        "insight_type": safe_type,
        "insight_score": round(min(max(score, 0.0), 1.0), 2),
        "related_cluster": cluster_id,
        "related_cluster_type": _safe_text(cluster.get("cluster_type") if isinstance(cluster, dict) else None),
        "evidence_count": len(evidence_summary),
        "evidence_summary": evidence_summary,
        "summary": _safe_text(summary, limit=160),
        "operator_next_steps": _insight_next_steps(safe_type),
        "advisory_only": True,
        "metadata_only": True,
        "read_only": True,
    }


def _insight_next_steps(insight_type: str) -> str:
    if insight_type == "emerging_risk_cluster":
        return "Review the related cluster, recent signals, and expected service behavior."
    if insight_type == "repeated_risk_signal":
        return "Compare recurring signals against allowlists and historical observations."
    if insight_type == "unstable_identity":
        return "Review profile stability, drift, and identity evidence before trusting attribution."
    if insight_type == "ambiguous_application_cluster":
        return "Check process, service, and fingerprint evidence for competing application candidates."
    if insight_type == "low_confidence_high_risk":
        return "Gather more metadata before acting on elevated risk context."
    return "Review dense graph relationships and confirm expected dependencies."


def _strongest_graph_insight(insights: list[dict[str, Any]]) -> dict[str, Any]:
    if not insights:
        return {}
    return sorted(
        insights,
        key=lambda row: (
            -float(row.get("insight_score") or 0.0),
            str(row.get("insight_type") or ""),
            str(row.get("insight_id") or ""),
        ),
    )[0]


def _graph_insight_summary(insights: list[dict[str, Any]]) -> str:
    if not insights:
        return "-"
    rows = [
        f"{_safe_text(row.get('insight_type'))}:{float(row.get('insight_score') or 0.0):.2f}"
        for row in _top_graph_insights(insights)
    ]
    return "; ".join(rows)


def _graph_operator_next_steps(strongest_insight: dict[str, Any]) -> str:
    return _safe_text(strongest_insight.get("operator_next_steps") if strongest_insight else None, limit=160)


def _top_graph_insights(insights: list[dict[str, Any]], *, limit: int = 3) -> list[dict[str, Any]]:
    rows = sorted(
        insights,
        key=lambda row: (-float(row.get("insight_score") or 0.0), str(row.get("insight_type") or "")),
    )
    selected: list[dict[str, Any]] = []
    seen_types: set[str] = set()
    for row in rows:
        insight_type = _safe_text(row.get("insight_type"))
        if insight_type in seen_types:
            continue
        selected.append(row)
        seen_types.add(insight_type)
        if len(selected) >= limit:
            break
    return selected


def _risk_rank(value: Any) -> int:
    return {"low": 0, "medium": 1, "high": 2, "critical": 3}.get(_safe_text(value), 0)


def _drift_rank(value: Any) -> int:
    return {"none": 0, "low": 1, "medium": 2, "high": 3}.get(_safe_text(value), 0)


def _bounded_score(value: float) -> float:
    return round(min(max(float(value), 0.0), 1.0), 2)


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


def _classification_missing_evidence_values(classification_model: dict[str, Any]) -> list[str]:
    values = _list_text(
        classification_model,
        ("missing_evidence", "missing_evidence_summary", "missing_signals", "limitations"),
    )
    candidates = classification_model.get("candidates")
    if isinstance(candidates, list):
        for item in candidates:
            if isinstance(item, dict):
                values.extend(_list_text(item, ("missing_evidence", "missing_signals")))
    return _unique_text(values, limit=8)


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
