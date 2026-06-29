from __future__ import annotations

import socket
from copy import deepcopy

from core_engine.control_plane import create_control_plane
from core_engine.licensing import summarize_license
from core_engine.provisioning import (
    assign_customer_features,
    assign_customer_limits,
    attach_control_plane_to_customer,
    attach_license_to_customer,
    create_customer_profile,
    deterministic_customer_profile_json,
    evaluate_customer_readiness,
    summarize_customer_profile,
    validate_customer_profile,
)


NOW = "2026-06-29T12:00:00+00:00"


def license_payload(**overrides):
    payload = {
        "license_id": "lic-customer-001",
        "edition": "professional",
        "issued_to": "Acme Local",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-12-31T00:00:00+00:00",
        "features": ["behavior_graph", "local_dashboard"],
        "limits": {"nodes": 10, "workers": 10},
        "signature_status": "placeholder_valid",
        "metadata": {"customer_id": "cust-001"},
    }
    payload.update(overrides)
    return payload


def license_summary(**overrides):
    return summarize_license(license_payload(**overrides), current_time=NOW)


def control_plane_summary(**overrides):
    payload = {
        "organization_id": "org-001",
        "deployment_id": "dep-001",
        "deployment_name": "Acme Local Deployment",
        "deployment_status": "local_cluster",
        "deployment_mode": "local_cluster",
        "node_count": 3,
        "worker_count": 2,
        "coordinator_version": "1.0.0",
        "schema_version": "1",
        "feature_set": ["behavior_graph", "local_dashboard"],
        "license_edition": "professional",
        "health_status": "healthy",
        "synchronization_state": "synchronized",
        "policy_version": "policy-1",
        "configuration_version": "config-1",
        "created_at": "2026-06-29T00:00:00+00:00",
        "updated_at": "2026-06-29T12:00:00+00:00",
    }
    payload.update(overrides)
    return create_control_plane(**payload).to_dict()


def customer_profile(**overrides):
    payload = {
        "customer_id": "cust-001",
        "customer_name": "Acme Local",
        "organization_id": "org-001",
        "tenant_id": "tenant-001",
        "deployment_id": "dep-001",
        "license_id": "lic-customer-001",
        "edition": "professional",
        "provisioning_status": "active",
        "provisioning_stage": "ready",
        "created_at": "2026-06-29T00:00:00+00:00",
        "updated_at": "2026-06-29T12:00:00+00:00",
        "activated_at": "2026-06-29T12:00:00+00:00",
        "expires_at": "2026-12-31T00:00:00+00:00",
        "assigned_features": ["behavior_graph", "local_dashboard"],
        "assigned_limits": {"nodes": 10, "workers": 10},
        "contact_metadata": {"owner": "local operator"},
        "deployment_region": "local",
        "notes": ["metadata-only provisioning profile"],
        "schema_version": "1",
    }
    payload.update(overrides)
    return create_customer_profile(**payload)


def test_valid_customer_profile():
    profile = customer_profile()
    validation = validate_customer_profile(
        profile,
        license_summary=license_summary(),
        control_plane_summary=control_plane_summary(),
    )

    assert profile.to_dict()["record_type"] == "customer_provisioning_profile"
    assert validation["validation_status"] == "valid"
    assert validation["valid"] is True
    assert validation["validation_reasons"] == ["customer provisioning profile is valid"]
    assert validation["network_called"] is False
    assert validation["runtime_state_mutated"] is False


def test_invalid_customer_profile():
    validation = validate_customer_profile(
        create_customer_profile(
            customer_id="",
            organization_id="",
            tenant_id="",
            deployment_id="",
            provisioning_status="bad",
            provisioning_stage="bad",
        )
    )

    assert validation["validation_status"] == "invalid"
    assert validation["valid"] is False
    assert validation["missing_identifiers"] == ["customer_id", "organization_id", "tenant_id", "deployment_id"]
    assert validation["invalid_status"] is True
    assert validation["invalid_stage"] is True


def test_license_attachment():
    profile = create_customer_profile(
        customer_id="cust-001",
        customer_name="Acme Local",
        organization_id="org-001",
        tenant_id="tenant-001",
        deployment_id="dep-001",
    )

    attached = attach_license_to_customer(profile, license_summary())

    assert attached["license_id"] == "lic-customer-001"
    assert attached["edition"] == "professional"
    assert attached["provisioning_stage"] == "license_attached"
    assert attached["assigned_features"] == sorted(attached["assigned_features"])
    assert "behavior_graph" in attached["assigned_features"]
    assert attached["assigned_limits"]["nodes"] == 10


def test_control_plane_attachment():
    profile = create_customer_profile(customer_id="cust-001", tenant_id="tenant-001")

    attached = attach_control_plane_to_customer(profile, control_plane_summary())

    assert attached["organization_id"] == "org-001"
    assert attached["deployment_id"] == "dep-001"
    assert attached["provisioning_stage"] == "control_plane_attached"


def test_feature_assignment():
    profile = customer_profile(assigned_features=["z_feature"])

    assigned = assign_customer_features(profile, ["a_feature", "z_feature"])

    assert assigned["assigned_features"] == ["a_feature", "z_feature"]
    assert assigned["provisioning_stage"] == "ready"


def test_limit_assignment():
    profile = customer_profile(assigned_limits={"workers": 2})

    assigned = assign_customer_limits(profile, {"nodes": 5, "workers": 4})

    assert assigned["assigned_limits"] == {"nodes": 5, "workers": 4}
    assert assigned["provisioning_stage"] == "ready"


def test_readiness_ready():
    readiness = evaluate_customer_readiness(
        customer_profile(),
        license_summary=license_summary(),
        control_plane_summary=control_plane_summary(),
    )

    assert readiness["readiness_status"] == "ready"
    assert readiness["readiness_ready"] is True
    assert readiness["readiness_blockers"] == []


def test_readiness_blocked():
    readiness = evaluate_customer_readiness(
        create_customer_profile(customer_id="cust-001", provisioning_status="pending"),
        license_summary=None,
        control_plane_summary=None,
    )

    assert readiness["readiness_status"] == "blocked"
    assert readiness["readiness_ready"] is False
    assert readiness["readiness_blockers"] == sorted(readiness["readiness_blockers"])
    assert "license is not attached" in readiness["readiness_blockers"]
    assert "control plane is not attached" in readiness["readiness_blockers"]


def test_expired_license_behavior():
    expired = license_summary(expires_at="2026-01-01T00:00:00+00:00")
    validation = validate_customer_profile(
        customer_profile(),
        license_summary=expired,
        control_plane_summary=control_plane_summary(),
    )

    assert expired["status"] == "expired"
    assert validation["validation_status"] == "blocked"
    assert validation["expired_license"] is True
    assert "attached license is expired" in validation["validation_reasons"]


def test_license_customer_mismatch():
    validation = validate_customer_profile(
        customer_profile(),
        license_summary=license_summary(metadata={"customer_id": "cust-other"}),
        control_plane_summary=control_plane_summary(),
    )

    assert validation["validation_status"] == "invalid"
    assert validation["license_customer_mismatch"] is True
    assert "license/customer mismatch" in validation["validation_reasons"]


def test_control_plane_customer_mismatch():
    validation = validate_customer_profile(
        customer_profile(),
        license_summary=license_summary(),
        control_plane_summary=control_plane_summary(organization_id="org-other"),
    )

    assert validation["validation_status"] == "invalid"
    assert validation["control_plane_customer_mismatch"] is True
    assert "control-plane/customer mismatch" in validation["validation_reasons"]


def test_deterministic_summaries():
    profile = customer_profile(assigned_features=["z", "a"], contact_metadata={"z": 1, "a": 2})

    first = summarize_customer_profile(profile)
    second = summarize_customer_profile(profile)

    assert first == second
    assert first["assigned_features"] == ["a", "z"]
    assert list(first["contact_metadata"].keys()) == ["a", "z"]
    assert deterministic_customer_profile_json(profile) == deterministic_customer_profile_json(profile)


def test_no_network_access(monkeypatch):
    calls: list[tuple[object, ...]] = []

    def fake_create_connection(*args, **kwargs):
        calls.append(args)
        raise AssertionError("provisioning must remain local")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    validation = validate_customer_profile(
        customer_profile(),
        license_summary=license_summary(),
        control_plane_summary=control_plane_summary(),
    )

    assert calls == []
    assert validation["network_called"] is False
    assert validation["hosted_api_started"] is False
    assert validation["database_used"] is False
    assert validation["customer_portal_started"] is False


def test_no_runtime_mutation():
    profile = customer_profile().to_dict()
    license_data = license_summary()
    control_plane = control_plane_summary()
    before_profile = deepcopy(profile)
    before_license = deepcopy(license_data)
    before_control_plane = deepcopy(control_plane)

    validation = validate_customer_profile(
        profile,
        license_summary=license_data,
        control_plane_summary=control_plane,
    )

    assert profile == before_profile
    assert license_data == before_license
    assert control_plane == before_control_plane
    assert validation["runtime_state_mutated"] is False
    assert validation["automatic_provisioning_action"] is False
    assert validation["remote_execution_enabled"] is False


def test_repeated_identical_input_produces_identical_output():
    profile = customer_profile()
    license_data = license_summary()
    control_plane = control_plane_summary()

    first = validate_customer_profile(profile, license_summary=license_data, control_plane_summary=control_plane)
    second = validate_customer_profile(profile, license_summary=license_data, control_plane_summary=control_plane)

    assert first == second
    assert evaluate_customer_readiness(profile, license_summary=license_data, control_plane_summary=control_plane) == evaluate_customer_readiness(
        profile,
        license_summary=license_data,
        control_plane_summary=control_plane,
    )
