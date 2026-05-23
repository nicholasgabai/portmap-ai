import json
import re

import pytest

from core_engine.federation import (
    TrustedNodeTrustError,
    TrustedTransportError,
    build_approved_peer_record,
    build_handshake_summary,
    build_local_node_trust_profile,
    build_transport_session_summary,
    create_trusted_transport_session,
    deterministic_transport_json,
    deterministic_trust_json,
    is_peer_approved,
    summarize_trust_profile,
    validate_local_node_trust_profile,
    validate_trusted_transport_session,
)
from core_engine.nodes import create_node_capabilities, create_node_identity
from core_engine.runtime import (
    build_runtime_checkpoint,
    build_runtime_health_summary,
    create_runtime_session,
    default_runtime_profile,
    normalize_node_runtime_state,
    summarize_runtime_session,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _node(node_id="node-master", role="master"):
    identity = create_node_identity(role=role, node_id=node_id, now=GENERATED_AT)
    capabilities = create_node_capabilities(
        node_id=node_id,
        role=role,
        platform="linux",
        architecture="arm64" if role == "worker" else "x86_64",
        supported_features=["runtime", "health", "federation"],
    )
    return {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "identity": identity.to_dict(),
        "capabilities": capabilities.to_dict(),
        "source_refs": [f"node-summary:{node_id}"],
    }


def _distributed_state(node_id="node-worker", role="worker"):
    profile = default_runtime_profile(generated_at=GENERATED_AT)
    session = create_runtime_session(
        session_id=f"session-{node_id}",
        mode="dry-run",
        started_at=GENERATED_AT,
        enabled_components=["runtime_session", "health"],
    )
    checkpoint = build_runtime_checkpoint(
        session=session,
        profile_summary={"profile_id": profile.profile_id},
        status="complete",
        created_at="2026-01-01T00:01:00+00:00",
    )
    health = build_runtime_health_summary(
        dashboard_provider={"status": "ok", "ready": True},
        generated_at="2026-01-01T00:01:00+00:00",
    )
    return normalize_node_runtime_state(
        {
            **_node(node_id, role),
            "lifecycle_state": "online",
            "last_seen_at": "2026-01-01T00:01:00+00:00",
            "session_summary": summarize_runtime_session(session),
            "profile_summary": profile.to_dict(),
            "health_summary": health,
            "checkpoint": checkpoint,
        },
        generated_at="2026-01-01T00:02:00+00:00",
    )


def _trust_profile():
    return build_local_node_trust_profile(
        _node("node-master", "master"),
        approved_peers=[
            build_approved_peer_record(
                _distributed_state("node-worker-a", "worker"),
                trust_scope_labels=["runtime-summary", "health-summary", "operator-visibility"],
                allowed_transport_modes=["local-file", "loopback-api"],
                approved_at=GENERATED_AT,
                expires_at="2026-01-01T01:00:00+00:00",
            )
        ],
        created_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def test_build_local_node_trust_profile_from_node_identity_and_peer_state():
    profile = _trust_profile()
    summary = summarize_trust_profile(profile, generated_at="2026-01-01T00:05:00+00:00")

    assert profile["record_type"] == "local_node_trust_profile"
    assert profile["local_node"]["node_id"] == "node-master"
    assert profile["approved_peer_ids"] == ["node-worker-a"]
    assert profile["replay_window_seconds"] == 300
    assert profile["network_listener_enabled"] is False
    assert profile["cryptographic_signing_enabled"] is False
    assert profile["remote_control_enabled"] is False
    assert summary["approved_peer_count"] == 1
    assert validate_local_node_trust_profile(profile, generated_at=GENERATED_AT)["ok"] is True


def test_peer_approval_respects_scope_transport_and_expiration():
    profile = _trust_profile()

    assert is_peer_approved(
        profile,
        "node-worker-a",
        trust_scope_label="runtime-summary",
        transport_mode="local-file",
        generated_at=GENERATED_AT,
    )
    assert not is_peer_approved(
        profile,
        "node-worker-a",
        trust_scope_label="export-summary",
        transport_mode="local-file",
        generated_at=GENERATED_AT,
    )
    assert not is_peer_approved(
        profile,
        "node-worker-a",
        trust_scope_label="runtime-summary",
        transport_mode="trusted-lan-preview",
        generated_at=GENERATED_AT,
    )
    assert not is_peer_approved(
        profile,
        "node-worker-a",
        trust_scope_label="runtime-summary",
        transport_mode="local-file",
        generated_at="2026-01-01T02:00:00+00:00",
    )


def test_create_trusted_transport_session_has_handshake_and_replay_metadata():
    profile = _trust_profile()
    session = create_trusted_transport_session(
        source_node=_node("node-master", "master"),
        destination_node=_distributed_state("node-worker-a", "worker"),
        trust_profile=profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
    )

    assert session["record_type"] == "trusted_node_transport_session"
    assert session["source_node_id"] == "node-master"
    assert session["destination_node_id"] == "node-worker-a"
    assert session["status"] == "planned"
    assert session["expires_at"] == "2026-01-01T00:05:00+00:00"
    assert session["handshake_summary"]["handshake_status"] == "pending"
    assert session["replay_window"]["replay_safe_records"] is True
    assert session["replay_window"]["nonce_required"] is True
    assert session["network_listener_enabled"] is False
    assert session["cryptographic_signing_enabled"] is False
    assert validate_trusted_transport_session(session, generated_at=GENERATED_AT)["ok"] is True


def test_unapproved_peer_transport_is_rejected_safely():
    profile = _trust_profile()

    with pytest.raises(TrustedTransportError):
        create_trusted_transport_session(
            source_node=_node("node-master", "master"),
            destination_node=_distributed_state("node-worker-b", "worker"),
            trust_profile=profile,
            transport_mode="local-file",
            trust_scope_label="runtime-summary",
            started_at=GENERATED_AT,
        )


def test_invalid_trust_scope_is_rejected():
    with pytest.raises(TrustedNodeTrustError):
        build_approved_peer_record(
            _distributed_state("node-worker-a", "worker"),
            trust_scope_labels=["unsupported-scope"],
            approved_at=GENERATED_AT,
        )


def test_transport_session_summary_is_deterministic():
    profile = _trust_profile()
    session = create_trusted_transport_session(
        source_node=_node("node-master", "master"),
        destination_node=_distributed_state("node-worker-a", "worker"),
        trust_profile=profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
    )
    closed = {**session, "session_id": "transport-session-closed", "status": "closed"}
    summary = build_transport_session_summary([closed, session], generated_at="2026-01-01T00:01:00+00:00")

    assert summary["session_count"] == 2
    assert summary["by_status"] == {"closed": 1, "planned": 1}
    assert [row["session_id"] for row in summary["sessions"]] == sorted(row["session_id"] for row in [closed, session])
    assert deterministic_transport_json(summary) == deterministic_transport_json(summary)


def test_handshake_summary_can_record_rejection_without_side_effects():
    profile = _trust_profile()
    session = create_trusted_transport_session(
        source_node=_node("node-master", "master"),
        destination_node=_distributed_state("node-worker-a", "worker"),
        trust_profile=profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
    )
    rejected = build_handshake_summary(
        session,
        status="rejected",
        generated_at="2026-01-01T00:02:00+00:00",
        message="operator approval required",
    )

    assert rejected["handshake_status"] == "rejected"
    assert rejected["source_node_id"] == "node-master"
    assert rejected["destination_node_id"] == "node-worker-a"
    assert rejected["remote_control_enabled"] is False


def test_trusted_transport_json_has_no_private_identifiers():
    profile = _trust_profile()
    session = create_trusted_transport_session(
        source_node=_node("node-master", "master"),
        destination_node=_distributed_state("node-worker-a", "worker"),
        trust_profile=profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
    )
    payload = json.dumps({"profile": profile, "session": session}, sort_keys=True)

    assert deterministic_trust_json(profile) == deterministic_trust_json(profile)
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
