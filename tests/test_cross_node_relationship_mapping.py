import json

import pytest

from core_engine.topology import (
    LateralAnalysisError,
    RelationshipGraphError,
    build_lateral_analysis_report,
    build_lateral_relationship_analysis,
    build_node_relationship_graph,
    build_node_relationship_record,
    deterministic_lateral_analysis_json,
    deterministic_relationship_graph_json,
    normalize_topology_distance,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _relationship(**overrides):
    base = {
        "source_node_class": "master",
        "target_node_class": "worker",
        "relationship_type": "runtime_heartbeat",
        "flow_reference": "flow-pair-redacted-001",
        "session_reference": "session-redacted-001",
        "shared_service_state": "shared",
        "observation_count": 6,
        "relationship_state": "recurring",
        "topology_distance": 1,
        "transport_state": "established",
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def test_cross_node_relationship_generation_and_export_safety():
    record = build_node_relationship_record(_relationship(), generated_at=FIXED_TIME)

    assert record["source_node_class"] == "master"
    assert record["target_node_class"] == "worker"
    assert record["relationship_state"] == "recurring"
    assert record["shared_service_state"] == "shared"
    assert record["recurring_interaction_score"] >= 0.8
    assert record["topology_distance"] == 1
    assert record["relationship_strength"] >= 0.8
    assert record["relationship_confidence"] >= 0.7
    assert record["source_mode"] == "live"
    assert record["raw_packet_stored"] is False
    assert record["packet_payload_inspected"] is False
    assert record["pcap_generated"] is False
    assert record["graph_db_dependency"] is False


def test_relationship_graph_deduplicates_and_summarizes_states():
    graph = build_node_relationship_graph(
        [
            _relationship(flow_reference="flow-pair-redacted-001"),
            _relationship(flow_reference="flow-pair-redacted-001", observation_count=8),
            _relationship(
                source_node_class="worker",
                target_node_class="external",
                relationship_type="external_service_adjacency",
                flow_reference="flow-pair-redacted-002",
                session_reference="session-redacted-002",
                shared_service_state="not_shared",
                observation_count=1,
                relationship_state="",
                topology_distance=3,
                transport_state="closed",
            ),
        ],
        generated_at=FIXED_TIME,
    )

    assert graph["summary"]["relationship_count"] == 2
    assert graph["summary"]["recurring_count"] == 1
    assert graph["summary"]["dormant_count"] == 1
    assert graph["summary"]["shared_service_count"] == 1
    assert graph["dashboard_status"]["panel"] == "cross_node_relationships"
    assert graph["api_status"]["relationships"][0]["source_mode"] == "live"


def test_transient_and_unknown_relationship_handling():
    transient = build_node_relationship_record(
        _relationship(
            source_node_class="edge",
            target_node_class="external",
            observation_count=1,
            relationship_state="",
            shared_service_state="not_shared",
            topology_distance="2",
            transport_state="syn_sent",
        ),
        generated_at=FIXED_TIME,
    )
    unknown = build_node_relationship_record(
        {"source_mode": "fixture", "relationship_type": "peer_relationship"},
        generated_at=FIXED_TIME,
    )

    assert transient["relationship_state"] == "transient"
    assert transient["topology_distance"] == 2
    assert unknown["source_node_class"] == "unknown"
    assert unknown["target_node_class"] == "unknown"
    assert unknown["relationship_state"] == "unknown"
    assert unknown["source_mode"] == "fixture"
    assert normalize_topology_distance("not-a-distance") == 0


def test_lateral_relationship_analysis_expected_unusual_and_suspicious_states():
    expected = build_lateral_relationship_analysis(
        build_node_relationship_record(_relationship(), generated_at=FIXED_TIME),
        generated_at=FIXED_TIME,
    )
    unusual = build_lateral_relationship_analysis(
        build_node_relationship_record(
            _relationship(
                source_node_class="worker",
                target_node_class="worker",
                relationship_type="peer_service",
                observation_count=3,
                topology_distance=2,
            ),
            generated_at=FIXED_TIME,
        ),
        generated_at=FIXED_TIME,
    )
    suspicious = build_lateral_relationship_analysis(
        build_node_relationship_record(
            _relationship(
                source_node_class="worker",
                target_node_class="worker",
                relationship_type="peer_service",
                observation_count=8,
                topology_distance=4,
                drift_detected=True,
            ),
            generated_at=FIXED_TIME,
        ),
        generated_at=FIXED_TIME,
    )

    assert expected["lateral_relationship_state"] == "expected"
    assert unusual["lateral_relationship_state"] in {"unusual", "suspicious"}
    assert unusual["unusual_peer_detected"] is True
    assert suspicious["lateral_relationship_state"] == "suspicious"
    assert suspicious["threat_verdict"] == "not_assessed"
    assert suspicious["enforcement_action"] == "none"


def test_lateral_analysis_report_summarizes_operator_review_counts():
    relationships = [
        build_node_relationship_record(_relationship(), generated_at=FIXED_TIME),
        build_node_relationship_record(
            _relationship(
                source_node_class="worker",
                target_node_class="worker",
                relationship_type="peer_service",
                observation_count=8,
                topology_distance=4,
                drift_detected=True,
            ),
            generated_at=FIXED_TIME,
        ),
    ]

    report = build_lateral_analysis_report(relationships, generated_at=FIXED_TIME)

    assert report["summary"]["analysis_count"] == 2
    assert report["summary"]["suspicious_count"] == 1
    assert report["summary"]["unusual_peer_count"] == 1
    assert report["dashboard_status"]["panel"] == "lateral_relationship_analysis"
    assert report["dashboard_status"]["recommended_review"] is True


def test_export_serialization_has_no_payload_or_graph_database_dependency():
    graph = build_node_relationship_graph([_relationship(source_mode="replay")], generated_at=FIXED_TIME)
    analysis = build_lateral_analysis_report(graph["relationships"], generated_at=FIXED_TIME)
    graph_json = deterministic_relationship_graph_json(graph)
    analysis_json = deterministic_lateral_analysis_json(analysis)

    assert graph_json == json.dumps(graph, sort_keys=True, separators=(",", ":"), default=str)
    assert '"source_mode":"replay"' in graph_json
    assert '"raw_packet_stored":false' in graph_json
    assert '"packet_payload_inspected":false' in graph_json
    assert '"pcap_generated":false' in graph_json
    assert '"graph_db_dependency":false' in analysis_json
    assert "payload_content" not in graph_json
    assert "hostname" not in analysis_json


def test_malformed_relationship_handling_and_cross_platform_classes():
    with pytest.raises(RelationshipGraphError):
        build_node_relationship_record("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(RelationshipGraphError):
        build_node_relationship_graph(object(), generated_at=FIXED_TIME)
    with pytest.raises(LateralAnalysisError):
        build_lateral_relationship_analysis("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(LateralAnalysisError):
        build_lateral_analysis_report(object(), generated_at=FIXED_TIME)

    record = build_node_relationship_record(
        _relationship(
            source_node_class="orchestrator",
            target_node_class="edge",
            relationship_type="control_plane",
            source_mode="unknown",
        ),
        generated_at=FIXED_TIME,
    )
    assert record["source_node_class"] == "orchestrator"
    assert record["target_node_class"] == "edge"
    assert record["source_mode"] == "unknown"
