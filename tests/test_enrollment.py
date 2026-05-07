import pytest

from core_engine.enrollment import (
    EnrollmentPackage,
    TenantIdentity,
    build_agent_identity,
    build_local_enrollment_request,
    redact_enrollment_package,
    validate_agent_identity,
    validate_enrollment_package,
    validate_enrollment_request,
)


def test_build_local_enrollment_request_has_valid_tenant_node_shape():
    request = build_local_enrollment_request(
        tenant_id="tenant.local",
        org_id="org.security",
        node_id="worker-001",
        role="worker",
        capabilities=["scan", "remediation-prompt"],
    )

    payload = request.to_dict()

    assert payload["tenant"]["tenant_id"] == "tenant.local"
    assert payload["tenant"]["org_id"] == "org.security"
    assert payload["tenant"]["environment"] == "local"
    assert payload["node_id"] == "worker-001"
    assert payload["role"] == "worker"
    assert validate_enrollment_request(payload) == []


def test_enrollment_request_rejects_invalid_identity_and_role():
    errors = validate_enrollment_request(
        {
            "tenant": {"tenant_id": "x", "org_id": "org.security"},
            "node_id": "bad node id",
            "role": "control-plane",
            "capabilities": ["scan", ""],
        }
    )

    assert any("tenant_id must be" in error for error in errors)
    assert any("node_id must be" in error for error in errors)
    assert any("role must be one of" in error for error in errors)
    assert "capabilities must be a list of non-empty strings" in errors


def test_enrollment_package_validation_requires_token_and_control_plane_url():
    package = EnrollmentPackage(
        tenant=TenantIdentity(tenant_id="tenant.local", org_id="org.security"),
        node_id="worker-001",
        role="worker",
        enrollment_token="short",
        control_plane_url="ftp://control.example.test",
    )

    errors = validate_enrollment_package(package)

    assert "enrollment_token must be 16-256 URL-safe characters" in errors
    assert "control_plane_url must be an http(s) URL" in errors


def test_build_agent_identity_stores_only_token_fingerprint():
    package = EnrollmentPackage(
        tenant=TenantIdentity(tenant_id="tenant.local", org_id="org.security", environment="prod"),
        node_id="worker-001",
        role="worker",
        enrollment_token="token-value-1234567890",
        control_plane_url="https://control.example.test",
    )

    identity = build_agent_identity(package)
    payload = identity.to_dict()

    assert validate_agent_identity(payload) == []
    assert payload["tenant"]["environment"] == "prod"
    assert payload["control_plane_url"] == "https://control.example.test"
    assert payload["enrollment_token_fingerprint"]
    assert package.enrollment_token not in str(payload)


def test_build_agent_identity_raises_on_invalid_package():
    with pytest.raises(ValueError, match="enrollment_token"):
        build_agent_identity(
            {
                "tenant": {"tenant_id": "tenant.local", "org_id": "org.security"},
                "node_id": "worker-001",
                "role": "worker",
                "enrollment_token": "short",
                "control_plane_url": "https://control.example.test",
            }
        )


def test_redact_enrollment_package_keeps_package_shape_without_plain_secret():
    package = EnrollmentPackage(
        tenant=TenantIdentity(tenant_id="tenant.local", org_id="org.security"),
        node_id="worker-001",
        role="worker",
        enrollment_token="token-value-1234567890",
        control_plane_url="https://control.example.test",
    )

    redacted = redact_enrollment_package(package)

    assert redacted["node_id"] == "worker-001"
    assert redacted["enrollment_token"].startswith("<redacted:")
    assert "token-value-1234567890" not in str(redacted)
