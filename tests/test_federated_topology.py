import json
import re

from core_engine.topology import (
    build_federated_topology,
    merge_federated_assets,
    merge_federated_services,
    merge_federated_topology_edges,
    normalize_node_topology_snapshots,
    summarize_federated_topology,
)
from core_engine.topology.snapshots import build_topology_snapshot


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _snapshot(node_id="node-master", label="Master Asset", service_name="https", edge_label="tls", confidence=0.8):
    snapshot = build_topology_snapshot(
        assets=[
            {
                "asset_id": "asset-shared",
                "label": label,
                "category": "server",
                "confidence": confidence,
                "source_refs": [f"asset:{node_id}"],
            }
        ],
        services=[
            {
                "service_id": f"service-{node_id}",
                "asset_id": "asset-shared",
                "port": 443,
                "service_name": service_name,
                "confidence": confidence,
            }
        ],
        topology_edges=[
            {
                "edge_id": f"edge-{node_id}",
                "source_asset": "asset-shared",
                "target_asset": f"asset-peer-{node_id}",
                "relationship_type": "connects_to",
                "protocol_service_label": edge_label,
                "observation_count": 2,
                "confidence": confidence,
            }
        ],
        findings=[
            {
                "finding_id": f"finding-{node_id}",
                "finding_type": "sample_topology_review",
                "severity": "medium",
                "summary": "Review federated topology sample.",
            }
        ],
        label=f"snapshot-{node_id}",
        observed_at="2026-01-01T00:00:00+00:00",
        source_ref=f"snapshot:{node_id}",
    )
    return {"node_id": node_id, "snapshot": snapshot, "source_ref": f"node-snapshot:{node_id}"}


def test_normalize_node_topology_snapshots_preserves_source_attribution():
    reports = normalize_node_topology_snapshots([_snapshot("node-master")], observed_at="2026-01-01T00:05:00+00:00")

    assert reports[0]["node_id"] == "node-master"
    assert reports[0]["source_node_ids"] == ["node-master"]
    assert reports[0]["assets"][0]["source_node_ids"] == ["node-master"]
    assert "node-snapshot:node-master" in reports[0]["assets"][0]["source_refs"]
    assert reports[0]["raw_payload_stored"] is False


def test_federated_topology_merges_multi_node_snapshots():
    federated = build_federated_topology(
        [_snapshot("node-master"), _snapshot("node-worker", label="Master Asset")],
        generated_at="2026-01-01T00:05:00+00:00",
    )

    assert federated["summary"]["source_node_count"] == 2
    assert federated["summary"]["asset_count"] >= 1
    assert federated["summary"]["service_count"] == 1
    assert federated["summary"]["topology_edge_count"] == 2
    assert federated["dashboard_summary"]["panel"] == "federated_topology"
    assert all("source_node_ids" in asset for asset in federated["assets"])
    assert federated["automatic_changes"] is False


def test_asset_label_drift_conflict_is_reported():
    federated = build_federated_topology(
        [_snapshot("node-master", label="Master Asset"), _snapshot("node-worker", label="Worker Asset")],
        generated_at="2026-01-01T00:05:00+00:00",
    )
    conflict_types = {conflict["conflict_type"] for conflict in federated["conflicts"]}

    assert "duplicate_asset" in conflict_types
    assert "asset_label_drift" in conflict_types
    assert federated["summary"]["recommended_review"] is True


def test_service_name_drift_conflict_is_reported():
    services, conflicts = merge_federated_services(
        [
            {"asset_id": "asset-sample", "port": 443, "service_name": "https", "source_node_ids": ["node-a"], "confidence": 0.6},
            {"asset_id": "asset-sample", "port": 443, "service_name": "sample-web", "source_node_ids": ["node-b"], "confidence": 0.8},
        ]
    )

    assert len(services) == 1
    assert services[0]["confidence"] > 0.6
    assert {conflict["conflict_type"] for conflict in conflicts} >= {"duplicate_service", "service_name_drift"}


def test_edge_disagreement_conflict_is_reported():
    edges, conflicts = merge_federated_topology_edges(
        [
            {
                "source_asset": "asset-a",
                "target_asset": "asset-b",
                "relationship_type": "connects_to",
                "protocol_service_label": "tls",
                "source_node_ids": ["node-a"],
            },
            {
                "source_asset": "asset-a",
                "target_asset": "asset-b",
                "relationship_type": "connects_to",
                "protocol_service_label": "http",
                "source_node_ids": ["node-b"],
            },
        ]
    )

    assert len(edges) == 1
    assert edges[0]["observation_count"] == 2
    assert {conflict["conflict_type"] for conflict in conflicts} >= {"duplicate_topology_edge", "edge_disagreement"}


def test_merge_assets_combines_confidence_and_source_refs():
    assets, conflicts = merge_federated_assets(
        [
            {"asset_id": "asset-sample", "label": "Sample", "source_node_ids": ["node-a"], "source_refs": ["snapshot:a"], "confidence": 0.5},
            {"asset_id": "asset-sample", "label": "Sample", "source_node_ids": ["node-b"], "source_refs": ["snapshot:b"], "confidence": 0.9},
        ]
    )

    assert len(assets) == 1
    assert assets[0]["source_node_ids"] == ["node-a", "node-b"]
    assert assets[0]["source_refs"] == ["snapshot:a", "snapshot:b"]
    assert assets[0]["confidence"] > 0.7
    assert any(conflict["conflict_type"] == "duplicate_asset" for conflict in conflicts)


def test_federated_outputs_include_timeline_and_correlation_records():
    federated = build_federated_topology(
        [_snapshot("node-master", label="A"), _snapshot("node-worker", label="B")],
        generated_at="2026-01-01T00:05:00+00:00",
    )

    assert federated["timeline_summary"]["entry_count"] >= 1
    assert len(federated["correlation_records"]) >= 1
    assert all(record["local_only"] is True for record in federated["correlation_records"])


def test_empty_federated_topology_summary_is_deterministic():
    federated = build_federated_topology([], generated_at="2026-01-01T00:05:00+00:00")
    summary = summarize_federated_topology(node_count=0)

    assert federated["summary"]["source_node_count"] == 0
    assert federated["summary"]["asset_count"] == 0
    assert summary["asset_count"] == 0
    assert summary["recommended_review"] is False


def test_federated_topology_output_has_no_private_identifiers():
    federated = build_federated_topology(
        [_snapshot("node-master"), _snapshot("node-worker")],
        generated_at="2026-01-01T00:05:00+00:00",
    )
    payload = json.dumps(federated, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
