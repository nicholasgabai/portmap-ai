from __future__ import annotations

import socket
from copy import deepcopy

from core_engine.control_plane import (
    compare_control_plane_versions,
    compare_health_transition,
    compare_synchronization_state,
    create_control_plane,
    deterministic_control_plane_json,
    merge_control_plane_metadata,
    summarize_control_plane,
    validate_control_plane,
)


def control_plane_payload(**overrides):
    payload = {
        "organization_id": "org-local",
        "deployment_id": "deployment-local",
        "deployment_name": "Local Deployment",
        "deployment_status": "local_cluster",
        "deployment_mode": "local_cluster",
        "node_count": 3,
        "worker_count": 2,
        "coordinator_version": "1.0.0",
        "schema_version": "1",
        "feature_set": ["behavior_graph", "licensing"],
        "license_edition": "professional",
        "health_status": "healthy",
        "synchronization_state": "synchronized",
        "policy_version": "policy-1",
        "configuration_version": "config-1",
        "created_at": "2026-06-27T00:00:00+00:00",
        "updated_at": "2026-06-27T12:00:00+00:00",
        "metadata": {"site": "lab", "owner": "operator"},
    }
    payload.update(overrides)
    return payload


def test_valid_control_plane_model():
    record = create_control_plane(**control_plane_payload())
    summary = record.to_dict()
    validation = validate_control_plane(record, expected_schema_version="1")

    assert summary["record_type"] == "control_plane_model"
    assert summary["deployment_status"] == "local_cluster"
    assert summary["feature_set"] == ["behavior_graph", "licensing"]
    assert summary["network_called"] is False
    assert summary["hosted_api_started"] is False
    assert validation["valid"] is True
    assert validation["validation_status"] == "valid"
    assert validation["validation_reasons"] == ["control plane metadata is valid"]


def test_invalid_control_plane_model():
    validation = validate_control_plane(
        create_control_plane(
            organization_id="",
            deployment_id="",
            deployment_status="bad-state",
            schema_version="",
            health_status="unknown",
            synchronization_state="unknown",
        )
    )

    assert validation["validation_status"] == "invalid"
    assert validation["valid"] is False
    assert validation["missing_identifiers"] == ["organization_id", "deployment_id"]
    assert validation["invalid_schema"] is True
    assert validation["invalid_deployment_state"] is True
    assert "deployment state is invalid or unknown" in validation["validation_reasons"]


def test_deterministic_summaries():
    payload = control_plane_payload(feature_set=["zeta", "alpha"], metadata={"z": 1, "a": 2})

    first = summarize_control_plane(payload)
    second = summarize_control_plane(payload)

    assert first == second
    assert first["feature_set"] == ["alpha", "zeta"]
    assert list(first["metadata"].keys()) == ["a", "z"]
    assert deterministic_control_plane_json(payload) == deterministic_control_plane_json(payload)


def test_merge_behavior_does_not_mutate_inputs():
    base = control_plane_payload(feature_set=["licensing"], metadata={"base": "yes"})
    overlay = {
        "node_count": 5,
        "feature_set": ["behavior_graph", "licensing"],
        "metadata": {"overlay": "yes"},
        "organization_id": "should-not-change",
    }
    base_before = deepcopy(base)
    overlay_before = deepcopy(overlay)

    merged = merge_control_plane_metadata(base, overlay)

    assert base == base_before
    assert overlay == overlay_before
    assert merged["organization_id"] == "org-local"
    assert merged["node_count"] == 5
    assert merged["feature_set"] == ["behavior_graph", "licensing"]
    assert merged["metadata"] == {"base": "yes", "overlay": "yes"}
    assert merged["runtime_state_mutated"] is False


def test_version_comparison():
    left = control_plane_payload(coordinator_version="1.0.0", policy_version="policy-1")
    right = control_plane_payload(coordinator_version="1.1.0", policy_version="policy-2")

    comparison = compare_control_plane_versions(left, right)

    assert comparison["coordinator_version_changed"] is True
    assert comparison["policy_version_changed"] is True
    assert comparison["version_mismatch"] is True
    assert comparison["synchronization_mismatch"] is False
    assert comparison["network_called"] is False


def test_synchronization_comparison():
    assert compare_synchronization_state("synchronized", "out_of_sync") == "degraded"
    assert compare_synchronization_state("out_of_sync", "synchronized") == "improved"
    assert compare_synchronization_state("partially_synchronized", "partially_synchronized") == "same"
    assert compare_synchronization_state("unknown", "synchronized") == "unknown"


def test_health_evaluation_and_transitions():
    assert compare_health_transition("healthy", "degraded") == "degraded"
    assert compare_health_transition("degraded", "unavailable") == "unavailable"
    assert compare_health_transition("degraded", "healthy") == "improved"
    assert compare_health_transition("healthy", "healthy") == "none"

    validation = validate_control_plane(
        control_plane_payload(health_status="degraded"),
        previous_control_plane=control_plane_payload(health_status="healthy"),
    )

    assert validation["validation_status"] == "degraded"
    assert validation["health_transition"] == "degraded"
    assert "health transitioned to degraded" in validation["validation_reasons"]


def test_deployment_state_transitions():
    for state in ["standalone", "local_cluster", "enterprise_cluster", "disconnected", "maintenance"]:
        summary = summarize_control_plane(control_plane_payload(deployment_status=state))
        validation = validate_control_plane(summary)

        assert summary["deployment_status"] == state
        assert validation["invalid_deployment_state"] is False

    invalid = validate_control_plane(control_plane_payload(deployment_status="hosted_cloud"))
    assert invalid["invalid_deployment_state"] is True
    assert invalid["validation_status"] == "invalid"


def test_validation_detects_mismatches():
    validation = validate_control_plane(
        control_plane_payload(
            coordinator_version="1.1.0",
            schema_version="2",
            policy_version="policy-2",
            configuration_version="config-2",
            synchronization_state="out_of_sync",
        ),
        expected_coordinator_version="1.0.0",
        expected_schema_version="1",
        expected_policy_version="policy-1",
        expected_configuration_version="config-1",
        expected_synchronization_state="synchronized",
    )

    assert validation["validation_status"] == "degraded"
    assert validation["version_mismatch"] is True
    assert validation["schema_mismatch"] is True
    assert validation["policy_mismatch"] is True
    assert validation["configuration_mismatch"] is True
    assert validation["synchronization_mismatch"] is True
    assert validation["validation_reasons"] == sorted(validation["validation_reasons"])


def test_repeated_identical_input_produces_identical_output():
    payload = control_plane_payload()

    assert validate_control_plane(payload) == validate_control_plane(payload)
    assert compare_control_plane_versions(payload, payload) == compare_control_plane_versions(payload, payload)


def test_no_network_access(monkeypatch):
    calls: list[tuple[object, ...]] = []

    def fake_create_connection(*args, **kwargs):
        calls.append(args)
        raise AssertionError("control plane model must remain local")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    summary = summarize_control_plane(control_plane_payload())
    validation = validate_control_plane(summary)

    assert calls == []
    assert summary["network_called"] is False
    assert validation["network_called"] is False
    assert validation["hosted_api_started"] is False
    assert validation["http_server_started"] is False
    assert validation["socket_opened"] is False


def test_no_runtime_mutation():
    payload = control_plane_payload()
    before = deepcopy(payload)

    summary = summarize_control_plane(payload)
    validation = validate_control_plane(payload)

    assert payload == before
    assert summary["runtime_state_mutated"] is False
    assert summary["worker_orchestration_changed"] is False
    assert validation["runtime_state_mutated"] is False
    assert validation["remote_execution_enabled"] is False
