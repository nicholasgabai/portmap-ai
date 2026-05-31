import json

from core_engine.history import (
    build_relationship_history_records,
    build_topology_evolution_report,
    deterministic_topology_evolution_json,
    score_relationship_confidence,
    score_topology_maturity,
)
from core_engine.history.snapshots import build_historical_snapshot
from core_engine.telemetry.behavior_summary import build_behavioral_intelligence_summary


NOW = "2026-03-01T00:00:00+00:00"


def _topology(generated_at: str, edges: list[dict]):
    return {
        "record_type": "live_topology",
        "generated_at": generated_at,
        "topology_update": {"update_digest": f"sha256:{generated_at[:10]}"},
        "topology_edges": edges,
    }


def _edge(source: str, target: str, protocol: str = "tcp/https", *, count: int = 1):
    return {
        "record_type": "topology_edge",
        "source_asset": source,
        "target_asset": target,
        "relationship_type": "observed_flow",
        "protocol": protocol,
        "observation_count": count,
        "confidence": 0.78,
        "source_refs": [f"fixture:{source}:{target}"],
    }


def _previous_relationship(**overrides):
    row = {
        "record_type": "long_term_topology_relationship",
        "relationship_id": "topology-relationship-existing",
        "relationship_key": "node-alpha|node-bravo|observed_flow|tcp/https",
        "source_asset": "node-alpha",
        "target_asset": "node-bravo",
        "relationship_type": "observed_flow",
        "protocol": "tcp/https",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-02-01T00:00:00+00:00",
        "observation_count": 4,
        "recurrence_count": 2,
        "classification": "transient",
        "stable_relationship": False,
        "transient_relationship": True,
        "dormant_relationship": False,
        "dormant_returned": False,
        "confidence": 0.7,
        "source_refs": ["fixture:previous"],
    }
    row.update(overrides)
    return row


def _snapshot():
    summary = build_behavioral_intelligence_summary(generated_at=NOW)
    return build_historical_snapshot(summary, generated_at=NOW)


def test_stable_relationship_tracking_from_recurring_history():
    records = build_relationship_history_records(
        [_topology(NOW, [_edge("node-alpha", "node-bravo", count=3)])],
        previous_relationships=[_previous_relationship()],
        generated_at=NOW,
    )

    relationship = records[0]

    assert relationship["classification"] == "stable"
    assert relationship["stable_relationship"] is True
    assert relationship["recurrence_count"] == 3
    assert relationship["observation_count"] == 7
    assert relationship["topology_maturity_score"] >= 0.75
    assert relationship["confidence"] > 0.7
    assert relationship["payload_bytes_stored"] == 0
    assert relationship["automatic_enforcement"] is False


def test_transient_relationship_and_drift_detection():
    report = build_topology_evolution_report(
        topology_records=[_topology(NOW, [_edge("node-charlie", "node-delta", "udp/dns")])],
        previous_relationships=[_previous_relationship()],
        generated_at=NOW,
    )

    relationship = next(row for row in report["relationships"] if row["source_asset"] == "node-charlie")

    assert relationship["classification"] == "transient"
    assert relationship["transient_relationship"] is True
    assert report["drift_summary"]["added_relationship_count"] == 1
    assert report["drift_summary"]["removed_relationship_count"] == 1
    assert report["drift_summary"]["status"] == "review_required"


def test_dormant_relationship_return_detection():
    previous = _previous_relationship(classification="dormant", dormant_relationship=True, stable_relationship=False, transient_relationship=False)
    report = build_topology_evolution_report(
        topology_records=[_topology(NOW, [_edge("node-alpha", "node-bravo")])],
        previous_relationships=[previous],
        generated_at=NOW,
    )

    relationship = report["relationships"][0]

    assert relationship["classification"] == "dormant_returned"
    assert relationship["dormant_returned"] is True
    assert report["drift_summary"]["dormant_return_count"] == 1
    assert report["dashboard_status"]["recommended_review"] is True


def test_recurring_communication_paths_and_export_are_safe():
    report = build_topology_evolution_report(
        topology_records=[
            _topology("2026-02-01T00:00:00+00:00", [_edge("node-alpha", "node-bravo")]),
            _topology(NOW, [_edge("node-alpha", "node-bravo")]),
        ],
        historical_snapshots=[_snapshot()],
        generated_at=NOW,
    )

    assert len(report["communication_paths"]) == 1
    assert report["communication_paths"][0]["relationship_key"] == "node-alpha|node-bravo|observed_flow|tcp/https"
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert report["api_status"]["historical_snapshot_context"]["snapshot_count"] == 1
    assert "relationships" not in report["export_summary"]
    assert report["credentials_stored"] is False


def test_malformed_input_is_isolated():
    report = build_topology_evolution_report(
        topology_records=[{"record_type": "live_topology", "generated_at": NOW}],
        generated_at=NOW,
    )

    assert report["relationship_summary"]["malformed_relationship_count"] == 1
    assert report["relationships"][0]["classification"] == "malformed"
    assert report["relationships"][0]["raw_record_stored"] is False


def test_maturity_confidence_scoring_and_serialization_are_deterministic():
    confidence = score_relationship_confidence(observation_count=4, recurrence_count=3, source_count=2, previous_confidence=0.5)
    maturity = score_topology_maturity(recurrence_count=3, age_days=30)
    report = build_topology_evolution_report(
        topology_records=[_topology(NOW, [_edge("node-alpha", "node-bravo")])],
        previous_relationships=[_previous_relationship()],
        generated_at=NOW,
    )
    left = deterministic_topology_evolution_json(report)
    right = deterministic_topology_evolution_json(json.loads(left))

    assert confidence > 0.7
    assert maturity >= 0.9
    assert left == right


def test_bounded_retention_behavior():
    edges = [_edge(f"node-{index}", "node-target", "tcp/custom") for index in range(4)]
    records = build_relationship_history_records([_topology(NOW, edges)], max_relationships=2, generated_at=NOW)

    assert len(records) == 2
    assert all(row["bounded_retention_applied"] is True for row in records)
    assert all(row["dropped_relationship_count"] == 2 for row in records)
