import json

import pytest

from core_engine.visualization import (
    TimelineVisualizationError,
    build_historical_timeline_window,
    build_topology_graph,
    deterministic_timeline_json,
    empty_timeline_window,
    make_timeline_event,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:01:00+00:00"
T3 = "2026-01-01T00:02:00+00:00"


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
        "confidence_score": 0.76,
        "source_mode": "live",
        "first_seen": T1,
        "last_seen": T2,
    }
    base.update(overrides)
    return base


def test_timeline_event_generation_is_export_safe():
    event = make_timeline_event(
        event_type="flow_started",
        event_category="flow",
        timestamp=T1,
        source_reference="node-redacted-source",
        target_reference="node-redacted-target",
        summary="Flow metadata observed",
        severity_level="low",
        confidence_score=0.8,
        related_flow_references=["flow-redacted-001"],
        source_mode="fixture",
    ).to_dict()

    assert event["record_type"] == "visual_timeline_event"
    assert event["event_type"] == "flow_started"
    assert event["event_category"] == "flow"
    assert event["source_mode"] == "fixture"
    assert event["preview_only"] is True
    assert event["destructive_action"] is False
    assert event["raw_payload_stored"] is False
    assert event["raw_dns_history_stored"] is False
    assert 0.0 <= event["confidence_score"] <= 1.0


def test_timeline_maps_flow_topology_service_asset_drift_policy_and_remediation():
    graph = build_topology_graph(flows=[_flow()], generated_at=T2)
    window = build_historical_timeline_window(
        topology_graphs=[graph],
        flow_summaries=[_flow()],
        asset_classifications=[
            {
                "asset_reference": "asset-redacted-001",
                "asset_category": "SERVER",
                "confidence_score": 0.7,
                "source_mode": "fixture",
                "last_seen": T1,
            }
        ],
        drift_records=[
            {
                "drift_id": "drift-redacted-001",
                "drift_severity": "moderate_drift",
                "confidence_score": 0.66,
                "source_mode": "replay",
                "timestamp": T2,
            }
        ],
        policy_evaluations=[
            {
                "evaluation_id": "eval-redacted-001",
                "policy_id": "policy-redacted-001",
                "matched": True,
                "severity": "high",
                "confidence_score": 0.8,
                "source_mode": "live",
                "timestamp": T2,
            }
        ],
        remediation_recommendations=[
            {
                "recommendation_id": "rec-redacted-001",
                "risk_score": 0.72,
                "confidence_score": 0.74,
                "policy_references": ["policy-redacted-001"],
                "flow_references": ["flow-redacted-001"],
                "source_mode": "live",
                "timestamp": T3,
            }
        ],
        incident_candidates=[
            {
                "candidate_id": "candidate-redacted-001",
                "candidate_state": "blocked_by_safety",
                "severity_level": "medium",
                "confidence_score": 0.5,
                "source_mode": "live",
                "timestamp": T3,
            }
        ],
        runtime_health_summaries=[
            {
                "runtime_id": "runtime-redacted-001",
                "health_state": "degraded",
                "confidence_score": 0.7,
                "source_mode": "live",
                "timestamp": T3,
            }
        ],
        generated_at=T3,
    ).to_dict()

    event_types = {event["event_type"] for event in window["events"]}

    assert {"node_seen", "topology_edge_seen", "flow_started", "service_seen", "asset_classified", "drift_detected", "policy_matched", "remediation_recommended", "guardrail_blocked", "runtime_degraded"} <= event_types
    assert window["category_counts"]["flow"] >= 1
    assert window["category_counts"]["topology"] >= 1
    assert window["severity_counts"]["high"] >= 1
    assert all(event["preview_only"] is True for event in window["events"])
    assert all(event["destructive_action"] is False for event in window["events"])


def test_timeline_sorts_chronologically_deduplicates_and_bounds_events():
    flow = _flow(flow_reference="flow-redacted-duplicate", first_seen=T2, last_seen=T2)
    window = build_historical_timeline_window(
        flow_summaries=[flow, flow, _flow(flow_reference="flow-redacted-later", first_seen=T3, last_seen=T3)],
        generated_at=T3,
        max_events=2,
    ).to_dict()

    timestamps = [event["timestamp"] for event in window["events"]]

    assert timestamps == sorted(timestamps)
    assert window["event_count"] == 2
    assert window["bounded"] is True
    assert window["max_events"] == 2


def test_empty_timeline_behavior_and_malformed_inputs():
    empty = empty_timeline_window(generated_at=T1).to_dict()

    assert empty["event_count"] == 0
    assert empty["events"] == []
    assert empty["bounded"] is True
    assert empty["export_safe"] is True

    with pytest.raises(TimelineVisualizationError):
        build_historical_timeline_window(flow_summaries=object(), generated_at=T1)


def test_timeline_serialization_redacts_private_identifiers():
    sensitive_reference = "sensitive/ref/value"
    window = build_historical_timeline_window(
        flow_summaries=[
            _flow(
                flow_reference=sensitive_reference,
                local_endpoint_class="workstation",
                remote_endpoint_class="server",
                first_seen=T1,
                last_seen=T1,
            )
        ],
        generated_at=T1,
    )
    payload = deterministic_timeline_json(window)

    assert payload == json.dumps(window.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    assert sensitive_reference not in payload
    assert "hostname" not in payload
    assert "payload_content" not in payload
    assert '"raw_payload_stored":false' in payload
    assert '"raw_dns_history_stored":false' in payload
