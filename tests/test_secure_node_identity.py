import json

import pytest

from core_engine.security import (
    SecureEnrollmentError,
    SecureNodeIdentity,
    SecureNodeIdentityError,
    SecureTrustChainError,
    TrustRelationshipSummary,
    build_trust_chain_summary,
    create_secure_node_identity,
    create_trust_relationship_summary,
    create_worker_enrollment_preview,
    identity_regeneration_preview,
    identity_rotation_preview,
)


ISSUED = "2026-01-01T00:00:00+00:00"


def _identity():
    return create_secure_node_identity(
        installation_reference="fixture-installation-reference",
        logical_node_class="worker",
        issued_timestamp=ISSUED,
    )


def test_deterministic_logical_identity_generation_avoids_raw_identifiers():
    first = _identity()
    second = _identity()
    exported = first.to_dict()
    serialized = json.dumps(exported, sort_keys=True)

    assert first.node_uuid == second.node_uuid
    assert exported["logical_node_class"] == "worker"
    assert exported["hardware_identifiers_stored"] is False
    assert exported["plaintext_secrets_stored"] is False
    assert exported["raw_hardware_identifiers_used"] is False
    assert "fixture-installation-reference" not in serialized
    assert "hostname" not in serialized.lower()
    assert "username" not in serialized.lower()
    assert "mac_address" not in serialized.lower()
    assert "serial_number" not in serialized.lower()


def test_identity_serialization_and_malformed_identity_handling():
    identity = _identity()
    loaded = SecureNodeIdentity.from_dict(identity.to_dict())

    assert loaded == identity
    with pytest.raises(SecureNodeIdentityError):
        SecureNodeIdentity.from_dict({"node_uuid": "not-a-uuid", "logical_node_class": "worker"})
    with pytest.raises(SecureNodeIdentityError):
        SecureNodeIdentity.from_dict({**identity.to_dict(), "hardware_identifiers_stored": True})
    with pytest.raises(SecureNodeIdentityError):
        create_secure_node_identity(installation_reference="", logical_node_class="worker")


def test_identity_regeneration_and_rotation_are_preview_only():
    identity = _identity()
    regeneration = identity_regeneration_preview(identity, reason="test_rotation", requested_timestamp=ISSUED)
    rotation = identity_rotation_preview(identity.to_dict(), target_version="secure-node-identity-v2", requested_timestamp=ISSUED)

    assert regeneration["preview_type"] == "identity_regeneration"
    assert regeneration["current_node_uuid"] == identity.node_uuid
    assert regeneration["preview_node_uuid"] != identity.node_uuid
    assert regeneration["dry_run_only"] is True
    assert regeneration["destructive_action"] is False
    assert rotation["preview_type"] == "identity_rotation"
    assert rotation["target_identity_version"] == "secure-node-identity-v2"
    assert rotation["preview_node_uuid"] != identity.node_uuid
    assert rotation["plaintext_secrets_stored"] is False


def test_worker_enrollment_preview_states_and_export_safety():
    identity = _identity()
    preview = create_worker_enrollment_preview(
        identity=identity,
        enrollment_state="pending",
        trust_level="candidate",
        enrollment_method="manual_preview",
        issued_timestamp=ISSUED,
        expires_in_seconds=3600,
    )
    exported = preview.to_dict()

    assert exported["enrollment_id"].startswith("enroll-")
    assert exported["node_identity_reference"] == identity.node_uuid
    assert exported["enrollment_state"] == "pending"
    assert exported["credential_exchange_performed"] is False
    assert exported["privileged_registration_performed"] is False
    assert exported["dry_run_only"] is True
    assert create_worker_enrollment_preview(identity=identity, enrollment_state="trusted", trust_level="trusted").enrollment_state == "trusted"
    assert create_worker_enrollment_preview(identity=identity, enrollment_state="rejected", trust_level="rejected").enrollment_state == "rejected"
    assert create_worker_enrollment_preview(identity=identity, enrollment_state="rotated", trust_level="limited").enrollment_state == "rotated"
    assert create_worker_enrollment_preview(identity=identity, enrollment_state="expired", trust_level="none").enrollment_state == "expired"
    assert create_worker_enrollment_preview(identity=identity.to_dict()).node_identity_reference == identity.node_uuid
    assert create_worker_enrollment_preview(identity=identity, issued_timestamp=ISSUED).expiration_preview == "2026-01-02T00:00:00+00:00"
    with pytest.raises(SecureEnrollmentError):
        create_worker_enrollment_preview(identity=identity, enrollment_state="registered")
    with pytest.raises(SecureEnrollmentError):
        create_worker_enrollment_preview(identity=identity, expires_in_seconds=0)
    with pytest.raises(SecureEnrollmentError):
        create_worker_enrollment_preview(identity={**identity.to_dict(), "plaintext_secrets_stored": True})


def test_enrollment_serialization_rejects_performed_actions():
    preview = create_worker_enrollment_preview(identity=_identity(), issued_timestamp=ISSUED)
    loaded = type(preview).from_dict(preview.to_dict())

    assert loaded == preview
    with pytest.raises(SecureEnrollmentError):
        type(preview).from_dict({**preview.to_dict(), "credential_exchange_performed": True})
    with pytest.raises(SecureEnrollmentError):
        type(preview).from_dict({**preview.to_dict(), "privileged_registration_performed": True})


def test_trust_relationships_and_chain_summary_states():
    trusted = create_trust_relationship_summary(
        source_role="orchestrator",
        destination_role="master",
        trust_state="trusted",
        trust_reason="signed enrollment preview accepted",
        verification_mode="signed_summary_preview",
        rotation_ready=True,
    )
    degraded = create_trust_relationship_summary(
        source_role="master",
        destination_role="worker",
        trust_state="degraded",
        trust_reason="manual review required",
        verification_mode="manual_preview",
        rotation_ready=False,
        degraded_reason="pending operator approval",
    )
    summary = build_trust_chain_summary([trusted, degraded.to_dict()])

    assert trusted.to_dict()["export_safe"] is True
    assert summary["aggregate_trust_state"] == "degraded"
    assert summary["by_state"]["trusted"] == 1
    assert summary["by_state"]["degraded"] == 1
    assert summary["credential_exchange_performed"] is False
    assert summary["remote_enrollment_performed"] is False


def test_trust_state_validation_and_serialization_safety():
    relationship = TrustRelationshipSummary.from_dict(
        {
            "source_role": "master",
            "destination_role": "edge",
            "trust_state": "unknown",
            "trust_reason": "operator review pending",
            "verification_mode": "unknown",
            "rotation_ready": False,
        }
    )

    assert relationship.trust_state == "unknown"
    with pytest.raises(SecureTrustChainError):
        create_trust_relationship_summary(source_role="router", destination_role="worker")
    with pytest.raises(SecureTrustChainError):
        TrustRelationshipSummary.from_dict({**relationship.to_dict(), "credential_exchange_performed": True})
