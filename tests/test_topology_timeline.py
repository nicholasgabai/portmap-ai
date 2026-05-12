import re

from core_engine.topology import build_timeline_entries, build_topology_graph, summarize_timeline, summarize_topology
from core_engine.visibility_history import build_visibility_snapshot


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


ASSETS = [
    {"asset_id": "asset-sample-a", "label": "Sample App", "category": "application", "confidence": 0.8},
    {"asset_id": "asset-sample-b", "label": "Sample Data", "category": "database", "confidence": 0.7},
]
SERVICES = [
    {"service_id": "service-sample-a", "target": "asset-sample-a", "service": "HTTPS", "port": 8443, "confidence": 0.9},
    {"service_id": "service-sample-b", "target": "asset-sample-b", "service": "PostgreSQL", "port": 15432, "confidence": 0.8},
]
EDGES = [
    {
        "edge_id": "edge-sample",
        "src": "asset-sample-a",
        "dst": "asset-sample-b",
        "relationship_type": "service_dependency",
        "protocol": "TLS",
        "observation_count": 2,
        "confidence": 0.85,
    }
]


def test_graph_creation_from_assets_services_and_edges():
    graph = build_topology_graph(assets=ASSETS, services=SERVICES, topology_edges=EDGES, generated_at="sample-time")

    assert graph["node_count"] == 2
    assert graph["edge_count"] == 1
    assert graph["service_count"] == 2
    assert graph["relationship_count"] == 2
    assert graph["generated_at"] == "sample-time"
    assert graph["raw_payload_stored"] is False
    assert graph["automatic_changes"] is False
    assert graph["administrator_controlled"] is True
    node = next(item for item in graph["nodes"] if item["asset_id"] == "asset-sample-a")
    assert node["service_count"] == 1
    assert node["category"] == "application"
    edge = graph["edges"][0]
    assert edge["source_asset"] == "asset-sample-a"
    assert edge["target_asset"] == "asset-sample-b"
    assert edge["protocol_service_label"] == "TLS"


def test_graph_creation_from_snapshot_data():
    snapshot = build_visibility_snapshot(
        assets=[{"host": "192.0.2.10", "ip_version": 4, "status": "reachable"}],
        services=[{"target": "192.0.2.10", "port": 8443, "service": "HTTPS", "confidence": 0.8}],
        flows={
            "flows": [
                {
                    "flow_id": "flow-sample",
                    "initiator": {"ip": "192.0.2.10"},
                    "responder": {"ip": "198.51.100.20"},
                    "payload_bytes": 128,
                    "application_protocols": ["HTTPS"],
                }
            ]
        },
        label="sample",
    )

    graph = build_topology_graph(snapshots=[snapshot], generated_at="sample-time")

    assert graph["node_count"] >= 2
    assert graph["edge_count"] == 1
    assert graph["service_count"] == 1
    assert summarize_topology(graph)["by_relationship"]["observed_relationship"] == 1


def test_empty_graph_behavior():
    graph = build_topology_graph(generated_at="sample-time")
    summary = summarize_topology(graph)

    assert graph["nodes"] == []
    assert graph["edges"] == []
    assert summary["node_count"] == 0
    assert summary["edge_count"] == 0
    assert summary["automatic_changes"] is False


def test_duplicate_node_and_edge_handling():
    graph = build_topology_graph(
        assets=[ASSETS[0], ASSETS[0]],
        services=[SERVICES[0], SERVICES[0]],
        topology_edges=[EDGES[0], EDGES[0]],
        generated_at="sample-time",
    )

    assert graph["node_count"] == 2
    assert graph["edge_count"] == 1
    assert graph["edges"][0]["observation_count"] == 4


def test_timeline_creation_from_events():
    entries = build_timeline_entries(
        events=[
            {
                "event_id": "event-sample",
                "event_type": "asset_observed",
                "severity": "low",
                "timestamp": "sample-t1",
                "message": "Sample asset observed",
                "asset_ref": "asset-sample-a",
            }
        ]
    )

    assert len(entries) == 1
    assert entries[0]["timeline_id"].startswith("timeline-")
    assert entries[0]["category"] == "asset_observed"
    assert entries[0]["severity"] == "low"
    assert entries[0]["asset_ref"] == "asset-sample-a"
    assert entries[0]["recommended_review"] is False


def test_timeline_creation_from_delta_findings():
    entries = build_timeline_entries(
        deltas=[
            {
                "type": "service_added",
                "severity": "high",
                "timestamp": "sample-t2",
                "target": "asset-sample-a",
                "evidence": {"asset_id": "asset-sample-a", "service": "HTTPS"},
            }
        ],
        findings=[
            {
                "finding_id": "finding-sample",
                "finding_type": "policy_review_required",
                "severity": "medium",
                "created_at": "sample-t3",
                "message": "Sample review required",
                "asset_ref": "asset-sample-a",
            }
        ],
    )

    assert [entry["category"] for entry in entries] == ["baseline_delta", "finding"]
    assert all(entry["recommended_review"] for entry in entries)
    assert all(entry["automatic_changes"] is False for entry in entries)


def test_timeline_severity_grouping_and_safety_flags():
    entries = build_timeline_entries(
        events=[
            {"event_id": "event-info", "event_type": "system_notice", "severity": "info", "message": "Sample"},
            {"event_id": "event-critical", "event_type": "policy_review_required", "severity": "critical", "message": "Sample"},
        ]
    )
    summary = summarize_timeline(entries)

    assert summary["entry_count"] == 2
    assert summary["by_severity"] == {"info": 1, "critical": 1}
    assert summary["highest_severity"] == "critical"
    assert summary["recommended_review_count"] == 1
    assert summary["raw_payload_stored"] is False
    assert summary["administrator_controlled"] is True


def test_no_private_identifiers_in_examples_or_output():
    graph = build_topology_graph(assets=ASSETS, services=SERVICES, topology_edges=EDGES, generated_at="sample-time")
    entries = build_timeline_entries(events=[{"event_id": "event-sample", "event_type": "system_notice", "message": "Sample"}])
    combined = repr(graph) + repr(entries)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(combined)
