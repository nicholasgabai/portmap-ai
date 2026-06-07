import json

import pytest

from core_engine.visualization import (
    VisualizationReadinessError,
    build_visualization_operator_summary,
    build_visualization_readiness,
    deterministic_visualization_readiness_json,
    deterministic_visualization_summary_json,
    empty_visualization_operator_summary,
    empty_visualization_readiness,
    readiness_state_from_components,
)


T1 = "2026-01-01T00:00:00+00:00"


def _topology(**overrides):
    base = {
        "graph_id": "graph-redacted-001",
        "summary": {"node_count": 2, "edge_count": 1},
        "nodes": [{"node_id": "node-redacted-worker", "source_mode": "live"}],
        "edges": [{"edge_id": "edge-redacted-001", "source_mode": "live"}],
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def _timeline(**overrides):
    base = {
        "timeline_window_id": "timeline-redacted-001",
        "event_count": 2,
        "events": [{"event_id": "event-redacted-001", "source_mode": "replay"}],
        "source_mode": "replay",
    }
    base.update(overrides)
    return base


def _asset_inventory(**overrides):
    base = {
        "inventory_id": "inventory-redacted-001",
        "asset_count": 2,
        "assets": [{"asset_id": "asset-redacted-001", "source_modes": ["live"]}],
        "source_modes": ["live"],
    }
    base.update(overrides)
    return base


def _risk_dashboard(**overrides):
    base = {
        "dashboard_id": "risk-redacted-001",
        "risk_state": "elevated",
        "card_count": 2,
        "recommendation_count": 1,
        "blocked_action_count": 1,
        "cards": [{"card_id": "card-redacted-001", "source_modes": ["fixture"]}],
        "source_modes": ["fixture"],
    }
    base.update(overrides)
    return base


def _fleet(**overrides):
    base = {
        "fleet_panel_id": "fleet-redacted-001",
        "node_count": 2,
        "degraded_state": False,
        "nodes": [{"fleet_node_id": "fleet-node-redacted-001", "source_mode": "simulated"}],
        "source_modes": ["simulated"],
    }
    base.update(overrides)
    return base


def _runtime(**overrides):
    base = {
        "runtime_id": "runtime-redacted-001",
        "health_state": "active",
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def test_operator_summary_generation_rolls_up_all_components():
    summary = build_visualization_operator_summary(
        topology_graphs=[_topology()],
        timeline_windows=[_timeline()],
        asset_inventory=_asset_inventory(),
        risk_dashboards=[_risk_dashboard()],
        fleet_visibility=_fleet(),
        runtime_health_summaries=[_runtime()],
        generated_at=T1,
    ).to_dict()

    assert summary["record_type"] == "visualization_operator_summary"
    assert summary["visualization_state"] == "degraded"
    assert summary["readiness_state"] == "degraded"
    assert summary["topology_summary"]["node_count"] == 2
    assert summary["timeline_summary"]["event_count"] == 2
    assert summary["asset_inventory_summary"]["asset_count"] == 2
    assert summary["risk_dashboard_summary"]["card_count"] == 2
    assert summary["fleet_visibility_summary"]["node_count"] == 2
    assert summary["runtime_summary"]["runtime_summary_count"] == 1
    assert "risk_dashboard" in summary["degraded_components"]
    assert summary["recommendation_summary"]["recommendation_count"] == 1
    assert summary["recommendation_summary"]["blocked_action_count"] == 1
    assert {"live", "fixture", "replay", "simulated"} <= set(summary["source_modes"])
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["export_safe"] is True
    assert summary["browser_ui_started"] is False
    assert summary["remote_control_enabled"] is False


def test_ready_degraded_empty_and_unavailable_states():
    ready = build_visualization_operator_summary(
        topology_graphs=[_topology()],
        timeline_windows=[_timeline()],
        asset_inventory=_asset_inventory(),
        risk_dashboards=[_risk_dashboard(risk_state="nominal", recommendation_count=0, blocked_action_count=0)],
        fleet_visibility=_fleet(),
        runtime_health_summaries=[_runtime()],
        generated_at=T1,
    ).to_dict()
    degraded = build_visualization_operator_summary(
        topology_graphs=[_topology()],
        timeline_windows=[_timeline(event_count=0, events=[])],
        asset_inventory=_asset_inventory(),
        risk_dashboards=[_risk_dashboard(risk_state="nominal", recommendation_count=0, blocked_action_count=0)],
        fleet_visibility=_fleet(degraded_state=True),
        runtime_health_summaries=[_runtime(health_state="degraded")],
        generated_at=T1,
    ).to_dict()
    empty = empty_visualization_operator_summary(generated_at=T1).to_dict()
    unavailable = build_visualization_operator_summary(
        topology_graphs=[_topology()],
        generated_at=T1,
    ).to_dict()

    assert ready["visualization_state"] == "ready"
    assert ready["readiness_state"] == "ready"
    assert degraded["visualization_state"] == "degraded"
    assert "timeline" in degraded["empty_components"]
    assert "fleet_visibility" in degraded["degraded_components"]
    assert "runtime" in degraded["degraded_components"]
    assert empty["visualization_state"] == "empty"
    assert empty["readiness_state"] == "blocked"
    assert unavailable["visualization_state"] == "unavailable"
    assert unavailable["readiness_state"] == "blocked"


def test_visualization_readiness_generation_and_empty_summary():
    readiness = build_visualization_readiness(
        available_components=["topology", "timeline", "asset_inventory"],
        missing_components=["risk_dashboard", "fleet_visibility", "runtime"],
        degraded_components=["timeline"],
        empty_components=["asset_inventory"],
    ).to_dict()
    empty = empty_visualization_readiness().to_dict()

    assert readiness["record_type"] == "visualization_readiness"
    assert readiness["readiness_state"] == "blocked"
    assert readiness["dashboard_api_ready"] is False
    assert readiness["export_ready"] is True
    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    assert "risk_dashboard" in readiness["missing_components"]
    assert "timeline" in readiness["degraded_components"]
    assert "asset_inventory" in readiness["empty_components"]
    assert empty["readiness_state"] == "blocked"
    assert len(empty["missing_components"]) >= 1
    assert readiness_state_from_components(missing_components=[], degraded_components=[], empty_components=[]) == "ready"
    assert readiness_state_from_components(missing_components=[], degraded_components=["runtime"], empty_components=[]) == "degraded"


def test_malformed_inputs_are_rejected():
    with pytest.raises(VisualizationReadinessError):
        build_visualization_operator_summary(topology_graphs=object(), generated_at=T1)
    with pytest.raises(VisualizationReadinessError):
        build_visualization_operator_summary(timeline_windows="not-a-list", generated_at=T1)

    summary = build_visualization_operator_summary(
        topology_graphs=[object(), _topology()],
        timeline_windows=[_timeline()],
        asset_inventory=_asset_inventory(),
        risk_dashboards=[_risk_dashboard(risk_state="nominal", recommendation_count=0, blocked_action_count=0)],
        fleet_visibility=_fleet(),
        runtime_health_summaries=[_runtime()],
        generated_at=T1,
    ).to_dict()

    assert summary["topology_summary"]["graph_count"] == 1


def test_visualization_summary_serialization_redacts_private_identifier_like_references():
    sensitive_reference = "sensitive/ref/value"
    summary = build_visualization_operator_summary(
        topology_graphs=[_topology(graph_id=sensitive_reference)],
        timeline_windows=[_timeline()],
        asset_inventory=_asset_inventory(inventory_id=sensitive_reference),
        risk_dashboards=[_risk_dashboard(risk_state="nominal", recommendation_count=0, blocked_action_count=0)],
        fleet_visibility=_fleet(fleet_panel_id=sensitive_reference),
        runtime_health_summaries=[_runtime(runtime_id=sensitive_reference)],
        generated_at=T1,
    )
    payload = deterministic_visualization_summary_json(summary)

    assert payload == json.dumps(summary.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    assert sensitive_reference not in payload
    assert "hostname" not in payload
    assert "payload_content" not in payload
    assert '"raw_payload_stored":false' in payload
    assert '"raw_dns_history_stored":false' in payload
    assert '"private_identifier_exported":false' in payload
    assert '"browser_ui_started":false' in payload


def test_visualization_readiness_serialization_is_export_safe():
    readiness = build_visualization_readiness(
        available_components=["topology", "timeline", "asset_inventory", "risk_dashboard", "fleet_visibility", "runtime"],
    )
    payload = deterministic_visualization_readiness_json(readiness)

    assert payload == json.dumps(readiness.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    assert '"readiness_state":"ready"' in payload
    assert '"destructive_action":false' in payload
    assert '"remote_call_performed":false' in payload
