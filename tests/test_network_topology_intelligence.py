import json

import pytest

from core_engine.topology import (
    DependencyMappingError,
    TrustZoneError,
    build_dependency_map,
    build_dependency_record,
    build_node_relationship_record,
    build_trust_zone_report,
    classify_relationship_trust_zone,
    deterministic_dependency_json,
    deterministic_trust_zone_json,
    infer_trust_zones,
    normalize_dependency_type,
    normalize_trust_zone_class,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _relationship(**overrides):
    base = {
        "source_node_class": "master",
        "target_node_class": "worker",
        "relationship_type": "runtime_heartbeat",
        "flow_reference": "flow-redacted-001",
        "session_reference": "session-redacted-001",
        "shared_service_state": "shared",
        "relationship_state": "recurring",
        "observation_count": 7,
        "topology_distance": 1,
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def test_trust_zone_inference_preserves_source_mode_and_safety():
    zones = infer_trust_zones(
        [
            _relationship(),
            _relationship(
                source_node_class="worker",
                target_node_class="external",
                relationship_type="external_service_adjacency",
                shared_service_state="not_shared",
                topology_distance=3,
                source_mode="replay",
            ),
            _relationship(
                source_node_class="edge",
                target_node_class="worker",
                relationship_type="peer_relationship",
                shared_service_state="not_shared",
                topology_distance=1,
            ),
        ],
        generated_at=FIXED_TIME,
    )
    by_class = {row["zone_class"]: row for row in zones}

    assert {"management", "external", "internal"} <= set(by_class)
    assert by_class["management"]["relationship_count"] == 1
    assert by_class["external"]["source_modes"] == ["replay"]
    assert 0.0 <= by_class["management"]["confidence_score"] <= 1.0
    assert by_class["management"]["raw_packet_stored"] is False
    assert by_class["management"]["packet_payload_inspected"] is False
    assert by_class["management"]["enforcement_enabled"] is False


def test_trust_zone_report_summarizes_topology_intelligence():
    report = build_trust_zone_report(
        [
            _relationship(),
            _relationship(
                source_node_class="worker",
                target_node_class="worker",
                relationship_type="shared_service_dependency",
                shared_service_state="shared",
                drift_detected=True,
            ),
        ],
        generated_at=FIXED_TIME,
    )

    assert report["summary"]["zone_count"] == 2
    assert report["summary"]["management_count"] == 1
    assert report["summary"]["service_count"] == 1
    assert report["summary"]["drift_detected_count"] == 1
    assert report["dashboard_status"]["panel"] == "network_trust_zones"
    assert report["dashboard_status"]["recommended_review"] is True
    assert report["api_status"]["trust_zones"]


def test_dependency_mapping_and_topology_adjacency():
    dependency = build_dependency_record(
        build_node_relationship_record(_relationship(), generated_at=FIXED_TIME),
        generated_at=FIXED_TIME,
    )
    adjacency = build_dependency_record(
        _relationship(
            source_node_class="edge",
            target_node_class="worker",
            relationship_type="peer_relationship",
            shared_service_state="not_shared",
            topology_distance=1,
            observation_count=1,
        ),
        generated_at=FIXED_TIME,
    )

    assert dependency["dependency_type"] == "management_dependency"
    assert dependency["topology_adjacency"] is True
    assert 0.0 <= dependency["relationship_strength"] <= 1.0
    assert 0.0 <= dependency["confidence_score"] <= 1.0
    assert adjacency["dependency_type"] == "topology_adjacency"
    assert adjacency["source_mode"] == "live"


def test_dependency_map_summarizes_service_and_external_dependencies():
    dependency_map = build_dependency_map(
        [
            _relationship(
                source_node_class="worker",
                target_node_class="worker",
                relationship_type="shared_service_dependency",
                shared_service_state="shared",
            ),
            _relationship(
                source_node_class="worker",
                target_node_class="external",
                relationship_type="external_service_adjacency",
                shared_service_state="not_shared",
                topology_distance=4,
                drift_detected=True,
                source_mode="fixture",
            ),
        ],
        generated_at=FIXED_TIME,
    )

    assert dependency_map["summary"]["dependency_count"] == 2
    assert dependency_map["summary"]["service_dependency_count"] == 1
    assert dependency_map["summary"]["external_dependency_count"] == 1
    assert dependency_map["summary"]["drift_detected_count"] == 1
    assert dependency_map["dashboard_status"]["panel"] == "network_dependencies"
    assert dependency_map["dashboard_status"]["recommended_review"] is True
    assert "fixture" in dependency_map["summary"]["source_modes"]


def test_classification_helpers_and_export_serialization_are_safe():
    report = build_trust_zone_report([_relationship(source_mode="fixture")], generated_at=FIXED_TIME)
    dependency_map = build_dependency_map([_relationship(source_mode="fixture")], generated_at=FIXED_TIME)
    zone_json = deterministic_trust_zone_json(report)
    dependency_json = deterministic_dependency_json(dependency_map)

    assert normalize_trust_zone_class("management") == "management"
    assert normalize_trust_zone_class("not-a-zone") == "unknown"
    assert normalize_dependency_type("service-dependency") == "service_dependency"
    assert normalize_dependency_type("not-a-dependency") == "unknown"
    assert classify_relationship_trust_zone({"target_node_class": "external"}) == "external"
    assert zone_json == json.dumps(report, sort_keys=True, separators=(",", ":"), default=str)
    assert dependency_json == json.dumps(dependency_map, sort_keys=True, separators=(",", ":"), default=str)
    assert '"source_mode":"fixture"' in dependency_json
    assert '"graph_db_dependency":false' in dependency_json
    assert "payload_content" not in zone_json
    assert "hostname" not in dependency_json


def test_malformed_topology_handling_and_unknown_records():
    with pytest.raises(TrustZoneError):
        infer_trust_zones(object(), generated_at=FIXED_TIME)
    with pytest.raises(DependencyMappingError):
        build_dependency_record("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(DependencyMappingError):
        build_dependency_map(object(), generated_at=FIXED_TIME)

    zones = infer_trust_zones([{"source_mode": "unknown"}], generated_at=FIXED_TIME)
    dependency_map = build_dependency_map([{"source_mode": "unknown"}], generated_at=FIXED_TIME)

    assert zones[0]["zone_class"] == "unknown"
    assert zones[0]["source_modes"] == ["unknown"]
    assert dependency_map["dependencies"][0]["dependency_type"] == "unknown"
    assert dependency_map["dependencies"][0]["source_mode"] == "unknown"
