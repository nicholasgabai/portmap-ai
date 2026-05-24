import json
import re

import pytest

from core_engine.federation import (
    TrustedPeerLifecycleError,
    apply_peer_lifecycle_transition,
    build_approved_peer_record,
    build_local_node_trust_profile,
    build_peer_lifecycle_record,
    build_trusted_peer_registry,
    create_trusted_transport_session,
    deterministic_peer_lifecycle_json,
    deterministic_peer_registry_json,
    update_peer_trust_scopes,
    validate_peer_lifecycle_transition,
)
from core_engine.nodes import create_node_capabilities, create_node_identity


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _node(node_id="node-worker-a", role="worker"):
    identity = create_node_identity(role=role, node_id=node_id, now=GENERATED_AT)
    capabilities = create_node_capabilities(
        node_id=node_id,
        role=role,
        platform="linux",
        architecture="arm64" if role == "worker" else "x86_64",
        supported_features=["runtime", "health", "events", "federation"],
    )
    return {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "identity": identity.to_dict(),
        "capabilities": capabilities.to_dict(),
        "source_refs": [f"node-summary:{node_id}"],
    }


def _peer(node_id="node-master", *, status="approved", expires_at="2026-01-01T01:00:00+00:00"):
    return build_approved_peer_record(
        _node(node_id, "master"),
        trust_scope_labels=["runtime-summary", "event-summary"],
        allowed_transport_modes=["local-file"],
        approval_status=status,
        approved_at=GENERATED_AT,
        expires_at=expires_at,
    )


def _profile(peer=None):
    return build_local_node_trust_profile(
        _node("node-worker-a", "worker"),
        approved_peers=[peer or _peer()],
        trust_scope_labels=["runtime-summary", "event-summary"],
        default_transport_modes=["local-file"],
        created_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def _transport(profile):
    return create_trusted_transport_session(
        source_node=_node("node-worker-a", "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
    )


def test_peer_lifecycle_record_and_scope_update():
    record = build_peer_lifecycle_record(
        _peer(),
        last_seen_at="2026-01-01T00:01:00+00:00",
        last_verified_at="2026-01-01T00:01:30+00:00",
        generated_at="2026-01-01T00:02:00+00:00",
    )
    updated = update_peer_trust_scopes(
        record,
        ["runtime-summary", "health-summary"],
        transitioned_at="2026-01-01T00:03:00+00:00",
        note="Limit lifecycle test peer scopes.",
    )

    assert record["record_type"] == "trusted_peer_lifecycle"
    assert record["lifecycle_state"] == "approved"
    assert updated["lifecycle_state"] == "approved"
    assert updated["trust_scope_labels"] == ["health-summary", "runtime-summary"]
    assert updated["lifecycle_history"][-1]["action"] == "update_scopes"
    assert updated["remote_command_execution"] is False
    assert updated["network_listener_enabled"] is False


def test_pause_resume_revoke_and_invalid_transition_validation():
    record = build_peer_lifecycle_record(_peer(), generated_at=GENERATED_AT)
    paused = apply_peer_lifecycle_transition(record, "pause", transitioned_at="2026-01-01T00:01:00+00:00")
    resumed = apply_peer_lifecycle_transition(paused, "resume", transitioned_at="2026-01-01T00:02:00+00:00")
    revoked = apply_peer_lifecycle_transition(resumed, "revoke", transitioned_at="2026-01-01T00:03:00+00:00")

    assert paused["lifecycle_state"] == "paused"
    assert resumed["lifecycle_state"] == "approved"
    assert revoked["lifecycle_state"] == "revoked"
    assert validate_peer_lifecycle_transition("revoked", "resume")["ok"] is False
    with pytest.raises(TrustedPeerLifecycleError):
        apply_peer_lifecycle_transition(revoked, "resume", transitioned_at="2026-01-01T00:04:00+00:00")


def test_peer_registry_links_transport_sessions_and_api_dashboard_records():
    profile = _profile()
    transport = _transport(profile)
    registry = build_trusted_peer_registry(
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:02:00+00:00",
    )

    assert registry["record_type"] == "trusted_peer_registry"
    assert registry["summary"]["peer_count"] == 1
    assert registry["summary"]["approved_peer_count"] == 1
    assert registry["peer_records"][0]["transport_session_ids"] == [transport["session_id"]]
    assert registry["dashboard_status"]["metrics"]["peer_count"] == 1
    assert registry["api_status"]["count"] == 1
    assert registry["background_daemon_enabled"] is False


def test_registry_reports_stale_expired_and_revoked_peers():
    stale = build_peer_lifecycle_record(
        _peer("node-master"),
        last_seen_at="2026-01-01T00:00:00+00:00",
        generated_at="2026-01-01T00:01:00+00:00",
    )
    expired = build_peer_lifecycle_record(
        _peer("node-expired", expires_at="2026-01-01T00:00:30+00:00"),
        lifecycle_state="expired",
        generated_at="2026-01-01T00:01:00+00:00",
    )
    revoked = build_peer_lifecycle_record(
        _peer("node-revoked", status="revoked"),
        generated_at="2026-01-01T00:01:00+00:00",
    )
    registry = build_trusted_peer_registry(
        peer_lifecycle_records=[stale, expired, revoked],
        stale_after_seconds=60,
        generated_at="2026-01-01T00:02:00+00:00",
    )

    assert registry["summary"]["status"] == "review_required"
    assert registry["summary"]["stale_peer_count"] == 1
    assert registry["summary"]["expired_peer_count"] == 1
    assert registry["summary"]["revoked_peer_count"] == 1
    assert registry["dashboard_status"]["recommended_review"] is True


def test_peer_lifecycle_outputs_are_deterministic_and_private_safe():
    profile = _profile()
    registry = build_trusted_peer_registry(
        trust_profile=profile,
        transport_sessions=[_transport(profile)],
        generated_at="2026-01-01T00:02:00+00:00",
    )
    payload = json.dumps(registry, sort_keys=True)

    assert deterministic_peer_registry_json(registry) == deterministic_peer_registry_json(registry)
    assert deterministic_peer_lifecycle_json(registry["peer_records"][0]) == deterministic_peer_lifecycle_json(registry["peer_records"][0])
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
