import json
import re

from core_engine.federation import (
    apply_signed_summary_updates,
    build_approved_peer_record,
    build_local_node_trust_profile,
    build_signed_runtime_summary_envelope,
    build_synchronization_window,
    create_trusted_transport_session,
    deterministic_sync_json,
)
from core_engine.nodes import create_node_capabilities, create_node_identity
from core_engine.runtime import build_runtime_health_summary, normalize_node_runtime_state


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
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


def _runtime_summary(node_id="node-worker-a", *, status="ok", observed_at="2026-01-01T00:02:00+00:00"):
    return normalize_node_runtime_state(
        {
            **_node(node_id, "worker"),
            "lifecycle_state": "online",
            "last_seen_at": "2026-01-01T00:01:00+00:00",
            "observed_at": observed_at,
            "health_summary": build_runtime_health_summary(
                dashboard_provider={"status": status, "ready": status == "ok"},
                generated_at="2026-01-01T00:01:00+00:00",
            ),
        },
        generated_at=observed_at,
    )


def _worker_profile(worker_id="node-worker-a"):
    peer = build_approved_peer_record(
        _node("node-master", "master"),
        trust_scope_labels=["runtime-summary", "health-summary"],
        allowed_transport_modes=["local-file"],
        approved_at=GENERATED_AT,
        expires_at="2026-01-01T01:00:00+00:00",
    )
    return build_local_node_trust_profile(
        _node(worker_id, "worker"),
        approved_peers=[peer],
        created_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def _transport(profile, worker_id="node-worker-a"):
    return create_trusted_transport_session(
        source_node=_node(worker_id, "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
    )


def _envelope(sequence=1, nonce="nonce-001", *, worker_id="node-worker-a", status="ok", issued_at=GENERATED_AT):
    profile = _worker_profile(worker_id)
    transport = _transport(profile, worker_id)
    envelope = build_signed_runtime_summary_envelope(
        _runtime_summary(worker_id, status=status),
        source_node=_node(worker_id, "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_session=transport,
        trust_scope_label="runtime-summary",
        sequence=sequence,
        nonce=nonce,
        issued_at=issued_at,
        key_reference=f"keyref:{worker_id}",
        signature_value=f"signature-placeholder-{sequence}",
    )
    return profile, transport, envelope


def _window():
    return build_synchronization_window(
        trusted_node_ids=["node-worker-a", "node-worker-b"],
        runtime_session_ref={"session_id": "session-master", "status": "running"},
        opened_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def test_synchronization_window_record_is_deterministic_and_safe():
    window = _window()

    assert window["record_type"] == "live_cluster_synchronization_window"
    assert window["trusted_node_ids"] == ["node-worker-a", "node-worker-b"]
    assert window["runtime_session_ref"]["session_id"] == "session-master"
    assert window["network_listener_enabled"] is False
    assert window["remote_control_enabled"] is False
    assert window["summary"]["accepted_update_count"] == 0
    assert deterministic_sync_json(window) == deterministic_sync_json(window)


def test_apply_signed_summary_update_accepts_and_merges_runtime_state():
    profile, transport, envelope = _envelope(sequence=1)
    result = apply_signed_summary_updates(
        [envelope],
        sync_window=_window(),
        trust_profile=profile,
        transport_sessions=[transport],
        expected_nodes=["node-worker-a", "node-worker-b"],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert result["summary"]["accepted_update_count"] == 1
    assert result["summary"]["rejected_update_count"] == 0
    assert result["sync_window"]["last_sequence_by_node"] == {"node-worker-a": 1}
    assert result["merged_cluster_state"]["summary"]["runtime_node_count"] == 1
    assert result["merged_cluster_state"]["distributed_runtime_state"]["summary"]["missing_node_count"] == 1
    assert result["dashboard_status"]["panel"] == "live_cluster_synchronization"
    assert result["api_status"]["cluster_summary"]["runtime_node_count"] == 1


def test_replayed_update_is_rejected_by_replay_window_validation():
    profile, transport, envelope = _envelope(sequence=1, nonce="nonce-dup")
    window = _window()
    window["seen_nonces"] = ["nonce-dup"]
    result = apply_signed_summary_updates(
        [envelope],
        sync_window=window,
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert result["summary"]["accepted_update_count"] == 0
    assert result["summary"]["replayed_update_count"] == 1
    assert result["rejected_updates"][0]["update_status"] == "replayed"
    assert result["conflicts"][0]["conflict_type"] == "replayed_update"


def test_out_of_order_sequence_is_rejected():
    profile, transport, envelope = _envelope(sequence=2, nonce="nonce-002")
    window = _window()
    window["last_sequence_by_node"] = {"node-worker-a": 2}
    result = apply_signed_summary_updates(
        [envelope],
        sync_window=window,
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert result["rejected_updates"][0]["update_status"] == "replayed"
    assert "sequence is not greater than last accepted sequence" in result["rejected_updates"][0]["classification_reason"]


def test_stale_update_is_rejected():
    profile, transport, envelope = _envelope(sequence=1)
    stale = {**envelope, "expires_at": "2026-01-01T00:00:30+00:00"}
    result = apply_signed_summary_updates(
        [stale],
        sync_window=_window(),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert result["summary"]["stale_update_count"] == 1
    assert result["conflicts"][0]["conflict_type"] == "stale_update"


def test_missing_transport_session_is_malformed_rejection():
    profile, _, envelope = _envelope(sequence=1)
    result = apply_signed_summary_updates(
        [envelope],
        sync_window=_window(),
        trust_profile=profile,
        transport_sessions=[],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert result["rejected_updates"][0]["update_status"] == "malformed"
    assert "transport session was not provided" in result["rejected_updates"][0]["classification_reason"]
    assert result["conflicts"][0]["conflict_type"] == "malformed_update"


def test_digest_drift_is_reported_for_changed_node_summary():
    profile, transport, first = _envelope(sequence=1, nonce="nonce-001", status="ok")
    _, _, second = _envelope(sequence=2, nonce="nonce-002", status="degraded")
    result = apply_signed_summary_updates(
        [first, second],
        sync_window=_window(),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert result["summary"]["accepted_update_count"] == 2
    assert result["summary"]["drift_count"] == 1
    assert result["drift"][0]["conflict_type"] == "summary_digest_drift"
    assert result["sync_window"]["last_sequence_by_node"]["node-worker-a"] == 2


def test_live_sync_output_has_no_private_identifiers():
    profile, transport, envelope = _envelope(sequence=1)
    result = apply_signed_summary_updates(
        [envelope],
        sync_window=_window(),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    payload = json.dumps(result, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
