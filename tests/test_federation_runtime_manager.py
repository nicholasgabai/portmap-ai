import json
import re

import pytest

from core_engine.events import create_event
from core_engine.federation import (
    FederationRuntimeStateError,
    build_approved_peer_record,
    build_default_federation_loop_plans,
    build_distributed_event_envelope,
    build_event_propagation_window,
    build_federation_loop_plan,
    build_federation_runtime_manager,
    build_federation_runtime_state,
    build_local_node_trust_profile,
    build_signed_runtime_summary_envelope,
    build_synchronization_window,
    create_trusted_transport_session,
    deterministic_federation_runtime_manager_json,
)
from core_engine.federation.event_propagation import apply_distributed_event_batch
from core_engine.federation.synchronization import apply_signed_summary_updates
from core_engine.nodes import create_node_capabilities, create_node_identity
from core_engine.runtime import build_runtime_health_summary, create_runtime_session, normalize_node_runtime_state


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


def _runtime_summary(node_id="node-worker-a"):
    return normalize_node_runtime_state(
        {
            **_node(node_id, "worker"),
            "lifecycle_state": "online",
            "last_seen_at": "2026-01-01T00:01:00+00:00",
            "observed_at": "2026-01-01T00:02:00+00:00",
            "health_summary": build_runtime_health_summary(
                dashboard_provider={"status": "ok", "ready": True},
                generated_at="2026-01-01T00:01:00+00:00",
            ),
        },
        generated_at="2026-01-01T00:02:00+00:00",
    )


def _profile():
    peer = build_approved_peer_record(
        _node("node-master", "master"),
        trust_scope_labels=["runtime-summary", "event-summary"],
        allowed_transport_modes=["local-file"],
        approved_at=GENERATED_AT,
        expires_at="2026-01-01T01:00:00+00:00",
    )
    return build_local_node_trust_profile(
        _node("node-worker-a", "worker"),
        approved_peers=[peer],
        trust_scope_labels=["runtime-summary", "event-summary"],
        default_transport_modes=["local-file"],
        created_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def _transport(profile, *, scope="runtime-summary"):
    return create_trusted_transport_session(
        source_node=_node("node-worker-a", "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_mode="local-file",
        trust_scope_label=scope,
        started_at=GENERATED_AT,
    )


def _signed_envelope(profile, transport, *, sequence=1, nonce="runtime-nonce-001"):
    return build_signed_runtime_summary_envelope(
        _runtime_summary("node-worker-a"),
        source_node=_node("node-worker-a", "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_session=transport,
        trust_scope_label="runtime-summary",
        sequence=sequence,
        nonce=nonce,
        issued_at=GENERATED_AT,
        key_reference="keyref:node-worker-a-runtime",
        signature_value=f"signature-placeholder-{sequence}",
    )


def _event_envelope(profile, transport, *, sequence=1, nonce="event-nonce-001"):
    event = create_event(
        "system_notice",
        severity="info",
        source="federation.runtime.test",
        message="Sanitized federation runtime event.",
        metadata={"fixture": "runtime-manager"},
    ).to_dict() | {"event_id": "evt-sanitized-runtime-001", "timestamp": GENERATED_AT}
    return build_distributed_event_envelope(
        event,
        source_node=_node("node-worker-a", "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_session=transport,
        sequence=sequence,
        nonce=nonce,
        issued_at=GENERATED_AT,
        key_reference="keyref:node-worker-a-events",
        signature_value=f"signature-placeholder-event-{sequence}",
    )


def _runtime_inputs():
    profile = _profile()
    runtime_transport = _transport(profile)
    event_transport = _transport(profile, scope="event-summary")
    envelope = _signed_envelope(profile, runtime_transport)
    sync = apply_signed_summary_updates(
        [envelope],
        sync_window=build_synchronization_window(
            trusted_node_ids=["node-worker-a", "node-master"],
            opened_at=GENERATED_AT,
            replay_window_seconds=300,
        ),
        trust_profile=profile,
        transport_sessions=[runtime_transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    event_batch = apply_distributed_event_batch(
        [_event_envelope(profile, event_transport)],
        propagation_window=build_event_propagation_window(
            trusted_node_ids=["node-worker-a", "node-master"],
            opened_at=GENERATED_AT,
            replay_window_seconds=300,
        ),
        trust_profile=profile,
        transport_sessions=[event_transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    runtime_session = create_runtime_session(
        session_id="runtime-session-federation",
        mode="dry-run",
        started_at=GENERATED_AT,
        enabled_components=["federation", "runtime", "events"],
    )
    return {
        "trust_profile": profile,
        "transport_sessions": [runtime_transport, event_transport],
        "signed_exchanges": [envelope],
        "sync_result": sync,
        "event_batch": event_batch,
        "runtime_session": runtime_session,
        "generated_at": "2026-01-01T00:03:00+00:00",
    }


def test_federation_runtime_manager_builds_active_runtime_summary():
    manager = build_federation_runtime_manager(state="active", **_runtime_inputs())

    assert manager["record_type"] == "active_federation_runtime_manager"
    assert manager["state"] == "active"
    assert manager["summary"]["peer_count"] == 1
    assert manager["summary"]["active_peer_count"] == 1
    assert manager["summary"]["loop_plan_count"] == 3
    assert manager["runtime_state"]["last_success_at"]
    assert manager["runtime_session_ref"]["session_id"] == "runtime-session-federation"
    assert manager["dashboard_status"]["metrics"]["peer_count"] == 1
    assert manager["api_status"]["runtime_state"]["state"] == "active"
    assert manager["network_listener_enabled"] is False
    assert manager["background_daemon_enabled"] is False
    assert manager["remote_command_execution"] is False


def test_default_loop_plans_cover_signed_sync_and_events():
    plans = build_default_federation_loop_plans(
        trust_profile=_profile(),
        state="paused",
        generated_at="2026-01-01T00:03:00+00:00",
    )

    assert [plan["loop_type"] for plan in plans] == ["signed_exchange", "synchronization", "event_propagation"]
    assert all(plan["state"] == "paused" for plan in plans)
    assert all(plan["loop_execution_enabled"] is False for plan in plans)


def test_runtime_state_reports_error_status_without_executing_loops():
    state = build_federation_runtime_state(
        trust_profile=_profile(),
        state="active",
        errors=["signed exchange loop failed"],
        generated_at="2026-01-01T00:03:00+00:00",
    )

    assert state["state"] == "error"
    assert state["summary"]["status"] == "error"
    assert state["summary"]["error_count"] == 1
    assert state["dashboard_status"]["recommended_review"] is True
    assert all(plan["loop_execution_enabled"] is False for plan in state["loop_plans"])


def test_invalid_runtime_state_and_loop_type_are_rejected():
    with pytest.raises(FederationRuntimeStateError):
        build_federation_runtime_state(state="running")

    with pytest.raises(FederationRuntimeStateError):
        build_federation_loop_plan("unsupported-loop")


def test_runtime_manager_output_is_deterministic_and_private_safe():
    manager = build_federation_runtime_manager(state="active", **_runtime_inputs())
    payload = json.dumps(manager, sort_keys=True)

    assert deterministic_federation_runtime_manager_json(manager) == deterministic_federation_runtime_manager_json(manager)
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
