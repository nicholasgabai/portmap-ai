import json

import pytest

from core_engine.visualization import (
    FleetVisibilityError,
    build_fleet_visibility_panel,
    deterministic_fleet_visibility_json,
    empty_fleet_visibility_panel,
    fleet_node_from_summary,
    make_fleet_group_summary,
    make_fleet_node_record,
    normalize_fleet_state,
    normalize_node_role,
    normalize_version_state,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:05:00+00:00"


def _node(**overrides):
    base = {
        "node_reference": "node-redacted-worker",
        "node_label": "worker node",
        "node_role": "worker",
        "site_reference": "site-redacted-main",
        "group_references": ["group-redacted-edge"],
        "runtime_state": "active",
        "health_state": "active",
        "version_state": "current",
        "last_checkin": T1,
        "telemetry_age_seconds": 30,
        "collector_status": "active",
        "observed_asset_count": 4,
        "observed_flow_count": 9,
        "risk_state": "nominal",
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def test_fleet_node_record_generation_is_export_safe():
    node = make_fleet_node_record(
        node_reference="node-redacted-worker",
        node_label="worker node",
        node_role="worker",
        site_reference="site-redacted-main",
        group_references=["group-redacted-edge"],
        runtime_state="active",
        health_state="active",
        version_state="current",
        last_checkin=T1,
        telemetry_freshness="active",
        collector_status="active",
        observed_asset_count=3,
        observed_flow_count=8,
        risk_state="elevated",
        source_mode="live",
    ).to_dict()

    assert node["record_type"] == "visual_fleet_node"
    assert node["node_role"] == "worker"
    assert node["runtime_state"] == "active"
    assert node["health_state"] == "active"
    assert node["version_state"] == "current"
    assert node["telemetry_freshness"] == "active"
    assert node["collector_status"] == "active"
    assert node["observed_asset_count"] == 3
    assert node["observed_flow_count"] == 8
    assert node["source_mode"] == "live"
    assert node["preview_only"] is True
    assert node["destructive_action"] is False
    assert node["cloud_sync_enabled"] is False
    assert node["remote_control_enabled"] is False
    assert node["fleet_database_written"] is False


def test_role_state_freshness_and_version_helpers():
    assert normalize_node_role("edge-collector") == "edge_collector"
    assert normalize_node_role("not-real") == "unknown"
    assert normalize_fleet_state("healthy") == "active"
    assert normalize_fleet_state("offline") == "offline"
    assert normalize_version_state("compatible") == "compatible"
    assert normalize_version_state("bad-state") == "unknown"

    fresh = fleet_node_from_summary(_node(telemetry_age_seconds=60), generated_at=T2).to_dict()
    stale = fleet_node_from_summary(_node(node_reference="node-redacted-stale", telemetry_age_seconds=600), generated_at=T2).to_dict()
    offline = fleet_node_from_summary(_node(node_reference="node-redacted-offline", telemetry_age_seconds=2000), generated_at=T2).to_dict()

    assert fresh["telemetry_freshness"] == "active"
    assert stale["telemetry_freshness"] == "stale"
    assert offline["telemetry_freshness"] == "offline"


def test_site_and_group_summary_generation_counts_health_states():
    active = make_fleet_node_record(node_reference="node-redacted-active", node_role="worker", runtime_state="active", health_state="active", site_reference="site-redacted-main", group_references=["group-redacted-edge"], risk_state="nominal")
    degraded = make_fleet_node_record(node_reference="node-redacted-degraded", node_role="edge_collector", runtime_state="active", health_state="degraded", site_reference="site-redacted-main", group_references=["group-redacted-edge"], risk_state="high")
    summary = make_fleet_group_summary(summary_type="site", site_reference="site-redacted-main", nodes=[active, degraded]).to_dict()

    assert summary["record_type"] == "visual_fleet_group_summary"
    assert summary["summary_type"] == "site"
    assert summary["node_count"] == 2
    assert summary["active_count"] == 1
    assert summary["degraded_count"] == 1
    assert summary["highest_risk_state"] == "high"
    assert summary["export_safe"] is True


def test_fleet_visibility_panel_deduplicates_groups_bounds_and_summarizes():
    panel = build_fleet_visibility_panel(
        runtime_node_summaries=[
            _node(),
            _node(last_checkin=T2, observed_flow_count=12),
            _node(node_reference="node-redacted-master", node_role="master", group_references=["group-redacted-core"], runtime_state="active", health_state="active", risk_state="elevated"),
            _node(node_reference="node-redacted-edge", node_role="edge_collector", group_references=["group-redacted-edge"], health_state="degraded", collector_status="degraded", risk_state="high"),
        ],
        asset_inventory={"asset_count": 5, "assets": []},
        risk_dashboard={"risk_state": "high", "cards": [{"related_flow_references": ["flow-redacted-web"]}]},
        generated_at=T2,
        max_nodes=2,
    ).to_dict()

    assert panel["record_type"] == "visual_fleet_visibility_panel"
    assert panel["node_count"] == 2
    assert panel["bounded"] is True
    assert panel["max_nodes"] == 2
    assert panel["site_count"] >= 1
    assert panel["group_count"] >= 1
    assert panel["highest_risk_state"] in {"elevated", "high"}
    assert panel["empty_state"] is False
    assert panel["preview_only"] is True
    assert panel["destructive_action"] is False
    assert all(node["preview_only"] is True for node in panel["nodes"])


def test_empty_degraded_offline_and_stale_fleet_behavior():
    empty = empty_fleet_visibility_panel(generated_at=T1).to_dict()

    assert empty["node_count"] == 0
    assert empty["empty_state"] is True
    assert empty["nodes"] == []
    assert empty["site_summaries"] == []
    assert empty["group_summaries"] == []

    panel = build_fleet_visibility_panel(
        runtime_node_summaries=[
            _node(node_reference="node-redacted-degraded", health_state="degraded", collector_status="degraded"),
            _node(node_reference="node-redacted-stale", telemetry_freshness="stale", runtime_state="stale"),
            _node(node_reference="node-redacted-offline", health_state="offline", collector_status="offline"),
        ],
        generated_at=T1,
    ).to_dict()

    assert panel["degraded_state"] is True
    assert panel["degraded_count"] >= 1
    assert panel["stale_count"] >= 1
    assert panel["offline_count"] >= 1


def test_fleet_visibility_malformed_inputs_and_cross_platform_sources():
    with pytest.raises(FleetVisibilityError):
        build_fleet_visibility_panel(runtime_node_summaries=object(), generated_at=T1)
    with pytest.raises(FleetVisibilityError):
        build_fleet_visibility_panel(federation_summaries="not-a-list", generated_at=T1)

    panel = build_fleet_visibility_panel(
        runtime_node_summaries=[
            object(),
            _node(node_reference="node-redacted-mac", source_mode="live"),
            _node(node_reference="node-redacted-win", source_mode="simulated", group_references=["group-redacted-windows"]),
            _node(node_reference="node-redacted-pi", source_mode="fixture", node_role="edge_collector"),
        ],
        generated_at=T1,
    ).to_dict()

    modes = {node["source_mode"] for node in panel["nodes"]}

    assert {"live", "simulated", "fixture"} <= modes
    assert panel["node_count"] == 3


def test_fleet_visibility_serialization_redacts_private_identifier_like_references():
    sensitive_reference = "sensitive/ref/value"
    panel = build_fleet_visibility_panel(
        runtime_node_summaries=[_node(node_reference=sensitive_reference, node_label=sensitive_reference)],
        generated_at=T1,
    )
    payload = deterministic_fleet_visibility_json(panel)

    assert payload == json.dumps(panel.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    assert sensitive_reference not in payload
    assert "hostname" not in payload
    assert "payload_content" not in payload
    assert '"raw_payload_stored":false' in payload
    assert '"private_identifier_exported":false' in payload
    assert '"cloud_sync_enabled":false' in payload
    assert '"remote_control_enabled":false' in payload
