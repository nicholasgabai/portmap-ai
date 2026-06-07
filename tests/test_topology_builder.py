import pytest

from core_engine.visualization import (
    TopologyVisualizationError,
    build_topology_graph,
    flow_to_edge,
    observation_to_node,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _flow(**overrides):
    base = {
        "flow_reference": "flow-redacted-001",
        "flow_direction": "outbound",
        "local_endpoint_class": "workstation",
        "remote_endpoint_class": "server",
        "local_port": 52444,
        "remote_port": 443,
        "protocol": "tcp",
        "service_hint": "https",
        "session_state": "active",
        "observation_count": 3,
        "source_mode": "live",
        "first_seen": FIXED_TIME,
        "last_seen": FIXED_TIME,
    }
    base.update(overrides)
    return base


def test_observation_to_node_produces_export_safe_node():
    node = observation_to_node(_flow(), endpoint="local", generated_at=FIXED_TIME)
    payload = node.to_dict()

    assert payload["record_type"] == "visual_topology_node"
    assert payload["asset_category"] == "WORKSTATION"
    assert payload["source_mode"] == "live"
    assert 0.0 <= payload["confidence_score"] <= 1.0
    assert payload["raw_packet_stored"] is False
    assert payload["packet_payload_inspected"] is False
    assert payload["enforcement_enabled"] is False
    assert "private" not in payload["label"]


def test_flow_to_edge_preserves_source_mode_and_confidence():
    edge = flow_to_edge(_flow(), generated_at=FIXED_TIME).to_dict()

    assert edge["record_type"] == "visual_topology_edge"
    assert edge["protocol"] == "tcp"
    assert edge["service_hint"] == "https"
    assert edge["source_mode"] == "live"
    assert edge["source_node_id"] != edge["target_node_id"]
    assert 0.0 <= edge["weight"] <= 1.0
    assert 0.0 <= edge["confidence_score"] <= 1.0


def test_build_topology_graph_deduplicates_nodes_and_aggregates_edges():
    graph = build_topology_graph(
        observations=[_flow()],
        flows=[_flow(), _flow(observation_count=2)],
        generated_at=FIXED_TIME,
    )
    payload = graph.to_dict()

    assert payload["record_type"] == "visual_topology_graph"
    assert payload["summary"]["node_count"] == 2
    assert payload["summary"]["edge_count"] == 1
    assert payload["edges"][0]["observation_count"] == 5
    assert payload["summary"]["bounded"] is True
    assert payload["limits"]["nodes_truncated"] is False
    assert payload["limits"]["edges_truncated"] is False


def test_build_topology_graph_applies_bounded_limits():
    flows = [
        _flow(
            local_endpoint_class=f"workstation-{index}",
            remote_endpoint_class=f"server-{index}",
            remote_port=443 + index,
        )
        for index in range(10)
    ]

    graph = build_topology_graph(flows=flows, generated_at=FIXED_TIME, max_nodes=3, max_edges=4).to_dict()

    assert graph["summary"]["node_count"] == 3
    assert graph["summary"]["edge_count"] == 4
    assert graph["limits"]["nodes_truncated"] is True
    assert graph["limits"]["edges_truncated"] is True


def test_build_topology_graph_handles_empty_and_malformed_inputs():
    empty = build_topology_graph(generated_at=FIXED_TIME).to_dict()

    assert empty["summary"]["node_count"] == 0
    assert empty["summary"]["edge_count"] == 0

    with pytest.raises(TopologyVisualizationError):
        observation_to_node("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(TopologyVisualizationError):
        flow_to_edge("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(TopologyVisualizationError):
        build_topology_graph(observations=object(), generated_at=FIXED_TIME)
