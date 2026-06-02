import json

import pytest

from core_engine.security import (
    SessionNegotiationError,
    SessionNegotiationPreview,
    TransportSecurityError,
    TransportSecurityProfile,
    create_session_negotiation_preview,
    create_transport_security_profile,
    summarize_session_negotiations,
    summarize_transport_profiles,
)


def test_transport_profile_generation_and_export_safety():
    profile = create_transport_security_profile("mtls_ready")
    exported = profile.to_dict()
    serialized = json.dumps(exported, sort_keys=True)

    assert exported["profile_name"] == "mtls_ready"
    assert exported["encryption_state"] == "ready"
    assert exported["authentication_state"] == "mutual_auth_ready"
    assert exported["certificate_generated"] is False
    assert exported["private_key_material_present"] is False
    assert exported["network_listener_changed"] is False
    assert exported["live_auth_exchange_performed"] is False
    assert "PRIVATE KEY" not in serialized
    assert "BEGIN CERTIFICATE" not in serialized


def test_plaintext_dev_is_degraded_and_downgrade_allowed():
    profile = create_transport_security_profile("plaintext_dev")

    assert profile.encryption_state == "degraded"
    assert profile.authentication_state == "none"
    assert profile.downgrade_allowed is True
    assert "development" in profile.downgrade_warning
    assert profile.rotation_supported is False


def test_production_profile_requires_encrypted_mutual_auth():
    profile = create_transport_security_profile("production_required")

    assert profile.encryption_state == "required"
    assert profile.authentication_state == "required"
    assert profile.downgrade_allowed is False
    assert profile.certificate_mode == "managed_preview"
    assert "production" in profile.downgrade_warning


def test_transport_profile_serialization_rejects_generated_material():
    profile = create_transport_security_profile("tls_ready")
    loaded = TransportSecurityProfile.from_dict(profile.to_dict())

    assert loaded == profile
    with pytest.raises(TransportSecurityError):
        create_transport_security_profile("ssh_tunnel")
    with pytest.raises(TransportSecurityError):
        TransportSecurityProfile.from_dict({**profile.to_dict(), "private_key_material_present": True})
    with pytest.raises(TransportSecurityError):
        TransportSecurityProfile.from_dict({**profile.to_dict(), "certificate_generated": True})
    with pytest.raises(TransportSecurityError):
        TransportSecurityProfile.from_dict({**profile.to_dict(), "network_listener_changed": True})


def test_transport_summary_counts_profiles_without_side_effects():
    summary = summarize_transport_profiles(["plaintext_dev", "mtls_ready", "production_required"])

    assert summary["profile_count"] == 3
    assert summary["by_encryption_state"]["degraded"] == 1
    assert summary["by_encryption_state"]["ready"] == 1
    assert summary["by_encryption_state"]["required"] == 1
    assert summary["certificate_generated"] is False
    assert summary["private_key_material_present"] is False


def test_session_negotiation_preview_generation_for_supported_pairs():
    preview = create_session_negotiation_preview(
        source_role="orchestrator",
        target_role="master",
        requested_transport="mtls_ready",
        trust_state="trusted",
    )
    exported = preview.to_dict()

    assert exported["session_id"].startswith("session-preview-")
    assert exported["source_role"] == "orchestrator"
    assert exported["target_role"] == "master"
    assert exported["requested_transport"] == "mtls_ready"
    assert exported["negotiated_transport"] == "mtls_ready"
    assert exported["encryption_required"] is True
    assert exported["mutual_auth_required"] is True
    assert exported["downgrade_detected"] is False
    assert exported["operator_action_required"] is False
    assert exported["dry_run_only"] is True
    assert exported["credential_exchange_performed"] is False
    assert exported["mtls_handshake_performed"] is False


def test_session_negotiation_detects_downgrade_and_requires_operator_action():
    preview = create_session_negotiation_preview(
        source_role="master",
        target_role="worker",
        requested_transport="production_required",
        negotiated_transport="plaintext_dev",
        trust_state="degraded",
    )

    assert preview.downgrade_detected is True
    assert preview.operator_action_required is True
    assert preview.encryption_required is True
    assert preview.mutual_auth_required is True
    assert "plaintext" in preview.downgrade_reason


def test_session_negotiation_summary_and_serialization_safety():
    first = create_session_negotiation_preview(
        source_role="orchestrator",
        target_role="worker",
        requested_transport="tls_ready",
        trust_state="unknown",
    )
    second = create_session_negotiation_preview(
        source_role="edge",
        target_role="orchestrator",
        requested_transport="pinned_cert_ready",
        trust_state="trusted",
    )
    summary = summarize_session_negotiations([first.to_dict(), second])

    assert summary["preview_count"] == 2
    assert summary["operator_action_count"] == 1
    assert summary["mutual_auth_required_count"] == 1
    assert summary["credential_exchange_performed"] is False
    assert summary["mtls_handshake_performed"] is False
    assert SessionNegotiationPreview.from_dict(first.to_dict()) == first
    with pytest.raises(SessionNegotiationError):
        SessionNegotiationPreview.from_dict({**first.to_dict(), "credential_exchange_performed": True})
    with pytest.raises(SessionNegotiationError):
        SessionNegotiationPreview.from_dict({**first.to_dict(), "mtls_handshake_performed": True})


def test_malformed_role_and_transport_handling():
    with pytest.raises(SessionNegotiationError):
        create_session_negotiation_preview(
            source_role="worker",
            target_role="orchestrator",
            requested_transport="mtls_ready",
        )
    with pytest.raises(SessionNegotiationError):
        create_session_negotiation_preview(
            source_role="orchestrator",
            target_role="master",
            requested_transport="raw_tcp",
        )
    with pytest.raises(SessionNegotiationError):
        create_session_negotiation_preview(
            source_role="orchestrator",
            target_role="master",
            requested_transport="mtls_ready",
            trust_state="accepted",
        )
