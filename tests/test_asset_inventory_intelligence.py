import json

import pytest

from core_engine.visualization import (
    AssetInventoryError,
    build_asset_inventory,
    build_asset_inventory_record,
    classify_asset_role,
    deterministic_asset_inventory_json,
    empty_asset_inventory,
    normalize_asset_role,
    score_asset_role_confidence,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:10:00+00:00"
T3 = "2026-01-01T00:20:00+00:00"


def _node(**overrides):
    base = {
        "node_id": "node-redacted-workstation",
        "node_class": "workstation",
        "asset_category": "WORKSTATION",
        "source_mode": "live",
        "first_seen": T1,
        "last_seen": T2,
        "observation_count": 2,
    }
    base.update(overrides)
    return base


def _flow(**overrides):
    base = {
        "flow_reference": "flow-redacted-web",
        "local_node_id": "node-redacted-workstation",
        "remote_node_id": "node-redacted-server",
        "flow_direction": "outbound",
        "local_endpoint_class": "workstation",
        "remote_endpoint_class": "server",
        "local_port": 52444,
        "remote_port": 443,
        "protocol": "tcp",
        "service_hint": "https",
        "risk_score": 0.3,
        "source_mode": "live",
        "first_seen": T1,
        "last_seen": T3,
    }
    base.update(overrides)
    return base


def test_asset_role_classification_uses_services_ports_and_endpoint_classes():
    assert classify_asset_role(_node(node_class="workstation")) == "workstation"
    assert classify_asset_role({"endpoint_class": "external", "service_hint": "cdn", "source_mode": "fixture"}) == "cloud_service"
    assert classify_asset_role({"endpoint_class": "server", "service_hint": "dns", "local_port": 53}) == "server"
    assert classify_asset_role({"service_hint": "resolver", "local_port": 53}) == "dns_resolver"
    assert classify_asset_role({"service_hint": "ipp", "local_port": 631}) == "printer"
    assert classify_asset_role({"service_hint": "smb", "local_port": 445}) == "nas"
    assert classify_asset_role({"service_hint": "sip", "local_port": 5060}) == "phone"
    assert classify_asset_role({"service_hint": "mqtt", "local_port": 1883}) == "iot"
    assert classify_asset_role({"service_hint": "ssh", "local_port": 22}) == "server"
    assert normalize_asset_role("invalid-live-label") == "unknown"


def test_inventory_record_generation_tracks_seen_windows_counts_and_source_modes():
    record = build_asset_inventory_record(
        _node(),
        related_flows=[_flow(), _flow(flow_reference="flow-redacted-dns", remote_port=53, service_hint="dns")],
        related_timeline_events=[
            {
                "event_id": "timeline-redacted-asset",
                "source_reference": "node-redacted-workstation",
                "event_category": "asset",
                "severity_level": "low",
                "source_mode": "replay",
                "timestamp": T2,
            }
        ],
        generated_at=T3,
    ).to_dict()

    assert record["record_type"] == "visual_asset_inventory_record"
    assert record["asset_role"] == "workstation"
    assert record["asset_state"] == "recurring"
    assert record["first_seen"] == T1
    assert record["last_seen"] == T3
    assert record["observed_service_count"] == 2
    assert record["observed_flow_count"] == 2
    assert record["related_node_references"] == ["node-redacted-workstation"]
    assert "flow-redacted-web" in record["related_flow_references"]
    assert record["source_modes"] == ["live", "replay"]
    assert record["role_evidence"]["metadata_only"] is True
    assert record["risk_summary"]["preview_only"] is True
    assert record["destructive_action"] is False
    assert record["inventory_database_written"] is False


def test_asset_inventory_deduplicates_counts_roles_and_states():
    summary = build_asset_inventory(
        topology_nodes=[
            _node(),
            _node(observation_count=4, last_seen=T3),
            _node(node_id="node-redacted-router", node_class="router", asset_category="ROUTER"),
            _node(node_id="node-redacted-printer", node_class="printer", local_port=631, asset_category="PRINTER"),
        ],
        flows=[_flow(), _flow(flow_reference="flow-redacted-admin", remote_port=22, service_hint="ssh")],
        generated_at=T3,
    ).to_dict()

    assert summary["record_type"] == "visual_asset_inventory_summary"
    assert summary["asset_count"] >= 3
    assert summary["bounded"] is True
    assert summary["max_assets"] >= summary["asset_count"]
    assert summary["role_counts"]["workstation"] == 1
    assert summary["role_counts"]["router"] == 1
    assert summary["role_counts"]["printer"] == 1
    assert summary["state_counts"]
    assert 0.0 <= summary["confidence_summary"]["min"] <= summary["confidence_summary"]["max"] <= 1.0
    assert all(asset["source_modes"] == ["live"] for asset in summary["assets"])


def test_asset_inventory_applies_max_assets_bound():
    summary = build_asset_inventory(
        topology_nodes=[
            _node(node_id=f"node-redacted-{index}", node_class="server", asset_category="SERVER")
            for index in range(8)
        ],
        generated_at=T3,
        max_assets=3,
    ).to_dict()

    assert summary["asset_count"] == 3
    assert summary["bounded"] is True
    assert summary["max_assets"] == 3


def test_empty_inventory_and_malformed_input_handling():
    empty = empty_asset_inventory(generated_at=T1).to_dict()

    assert empty["asset_count"] == 0
    assert empty["assets"] == []
    assert empty["bounded"] is True
    assert empty["export_safe"] is True

    with pytest.raises(AssetInventoryError):
        build_asset_inventory_record("not-an-object", generated_at=T1)
    with pytest.raises(AssetInventoryError):
        build_asset_inventory(topology_nodes=object(), generated_at=T1)

    summary = build_asset_inventory(topology_nodes=[object(), _node()], flows=[object()], generated_at=T1).to_dict()
    assert summary["asset_count"] == 1


def test_confidence_scores_are_bounded_and_malformed_risk_degrades():
    role_score = score_asset_role_confidence({"service_hint": "unknown", "risk_score": "bad"})
    summary = build_asset_inventory(
        topology_nodes=[_node(node_id="node-redacted-low", node_class="unknown", risk_score="bad")],
        flows=[_flow(risk_score="also-bad")],
        generated_at=T1,
    ).to_dict()

    assert 0.0 <= role_score <= 1.0
    assert 0.0 <= summary["assets"][0]["confidence_score"] <= 1.0
    assert summary["assets"][0]["risk_summary"]["max_risk_score"] == 0.0


def test_inventory_serialization_redacts_private_identifier_like_references():
    sensitive_reference = "sensitive/ref/value"
    summary = build_asset_inventory(
        topology_nodes=[
            _node(
                node_id=sensitive_reference,
                node_class="server",
                service_hint="https",
                first_seen=T1,
                last_seen=T1,
            )
        ],
        flows=[_flow(local_node_id=sensitive_reference, flow_reference=sensitive_reference)],
        generated_at=T1,
    )
    payload = deterministic_asset_inventory_json(summary)

    assert payload == json.dumps(summary.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    assert sensitive_reference not in payload
    assert "hostname" not in payload
    assert "payload_content" not in payload
    assert '"raw_payload_stored":false' in payload
    assert '"raw_dns_history_stored":false' in payload
    assert '"private_identifier_exported":false' in payload


def test_inventory_preserves_fixture_source_mode_without_live_dummy_labels():
    summary = build_asset_inventory(
        topology_nodes=[
            _node(
                node_id="node-redacted-fixture",
                node_class="server",
                service_hint="dummy_fixture_service",
                source_mode="fixture",
            )
        ],
        generated_at=T1,
    ).to_dict()

    assert summary["assets"][0]["source_modes"] == ["fixture"]
    assert summary["assets"][0]["asset_role"] == "server"
    assert "dummy_app" not in deterministic_asset_inventory_json(summary)
    assert "dummy_db" not in deterministic_asset_inventory_json(summary)
