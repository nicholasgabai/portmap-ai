import json
import re

from core_engine.events import create_event, event_to_dict
from core_engine.federation import (
    apply_distributed_event_batch,
    build_approved_peer_record,
    build_distributed_event_envelope,
    build_event_propagation_window,
    build_local_node_trust_profile,
    create_trusted_transport_session,
    deterministic_event_propagation_json,
    deterministic_event_window_json,
)
from core_engine.nodes import create_node_capabilities, create_node_identity


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


def _node(node_id="node-worker-a", role="worker"):
    identity = create_node_identity(role=role, node_id=node_id, now=GENERATED_AT)
    capabilities = create_node_capabilities(
        node_id=node_id,
        role=role,
        platform="linux",
        architecture="arm64" if role == "worker" else "x86_64",
        supported_features=["runtime", "events", "federation"],
    )
    return {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "identity": identity.to_dict(),
        "capabilities": capabilities.to_dict(),
        "source_refs": [f"node-summary:{node_id}"],
    }


def _event(event_id="evt-sanitized-001"):
    return create_event(
        "system_notice",
        severity="info",
        source="runtime.test",
        message="Sanitized runtime notice.",
        metadata={"fixture": "event-propagation"},
    ).to_dict() | {"event_id": event_id, "timestamp": GENERATED_AT}


def _profile(worker_id="node-worker-a"):
    peer = build_approved_peer_record(
        _node("node-master", "master"),
        trust_scope_labels=["event-summary"],
        allowed_transport_modes=["local-file"],
        approved_at=GENERATED_AT,
        expires_at="2026-01-01T01:00:00+00:00",
    )
    return build_local_node_trust_profile(
        _node(worker_id, "worker"),
        approved_peers=[peer],
        trust_scope_labels=["event-summary"],
        default_transport_modes=["local-file"],
        created_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def _transport(profile=None, worker_id="node-worker-a"):
    trust_profile = profile or _profile(worker_id)
    return create_trusted_transport_session(
        source_node=_node(worker_id, "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=trust_profile,
        transport_mode="local-file",
        trust_scope_label="event-summary",
        started_at=GENERATED_AT,
    )


def _envelope(sequence=1, nonce="event-nonce-001", *, event_id="evt-sanitized-001", worker_id="node-worker-a", issued_at=GENERATED_AT):
    profile = _profile(worker_id)
    transport = _transport(profile, worker_id)
    envelope = build_distributed_event_envelope(
        _event(event_id),
        source_node=_node(worker_id, "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_session=transport,
        sequence=sequence,
        nonce=nonce,
        issued_at=issued_at,
        key_reference=f"keyref:{worker_id}-events",
        signature_value=f"signature-placeholder-{sequence}",
    )
    return profile, transport, envelope


def _window():
    return build_event_propagation_window(
        trusted_node_ids=["node-worker-a", "node-worker-b"],
        runtime_session_ref={"session_id": "session-master", "status": "running"},
        opened_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def test_event_propagation_window_is_deterministic_and_safe():
    window = _window()

    assert window["record_type"] == "distributed_event_propagation_window"
    assert window["trusted_node_ids"] == ["node-worker-a", "node-worker-b"]
    assert window["network_listener_enabled"] is False
    assert window["remote_control_enabled"] is False
    assert window["summary"]["accepted_event_count"] == 0
    assert deterministic_event_window_json(window) == deterministic_event_window_json(window)


def test_build_distributed_event_envelope_reuses_local_event_shape():
    profile, transport, envelope = _envelope()

    assert envelope["record_type"] == "distributed_event_envelope"
    assert envelope["source_node_id"] == "node-worker-a"
    assert envelope["destination_node_id"] == "node-master"
    assert envelope["event_sequence"] == 1
    assert envelope["event_digest"].startswith("sha256:")
    assert envelope["event"] == event_to_dict(create_event(
        "system_notice",
        severity="info",
        source="runtime.test",
        message="Sanitized runtime notice.",
        metadata={"fixture": "event-propagation"},
    )) | {"event_id": "evt-sanitized-001", "timestamp": GENERATED_AT}
    assert envelope["signed_exchange_envelope"]["trust_scope_label"] == "event-summary"
    assert envelope["transport_session_id"] == transport["session_id"]
    assert profile["trust_scope_labels"] == ["event-summary"]


def test_apply_event_batch_accepts_verified_event_and_updates_window():
    profile, transport, envelope = _envelope()
    batch = apply_distributed_event_batch(
        [envelope],
        propagation_window=_window(),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert batch["summary"]["accepted_event_count"] == 1
    assert batch["summary"]["rejected_event_count"] == 0
    assert batch["propagation_window"]["last_sequence_by_node"] == {"node-worker-a": 1}
    assert batch["propagation_window"]["last_event_digest_by_node"]["node-worker-a"] == envelope["event_digest"]
    assert batch["accepted_events"][0]["local_event_storage_ready"] is True
    assert batch["cluster_event_rollup"]["accepted_event_count"] == 1
    assert batch["dashboard_status"]["panel"] == "distributed_event_propagation"
    assert batch["api_status"]["summary"]["accepted_event_count"] == 1


def test_duplicate_event_digest_is_rejected():
    profile, transport, envelope = _envelope()
    window = _window()
    window["seen_event_digests"] = [envelope["event_digest"]]
    batch = apply_distributed_event_batch(
        [envelope],
        propagation_window=window,
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert batch["summary"]["duplicate_event_count"] == 1
    assert batch["rejected_events"][0]["propagation_status"] == "duplicate"
    assert batch["rejected_events"][0]["local_event_storage_ready"] is False


def test_replayed_nonce_and_sequence_are_duplicate_classification():
    profile, transport, envelope = _envelope(sequence=2, nonce="event-nonce-002")
    window = _window()
    window["seen_nonces"] = ["event-nonce-002"]
    window["last_sequence_by_node"] = {"node-worker-a": 2}
    batch = apply_distributed_event_batch(
        [envelope],
        propagation_window=window,
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert batch["summary"]["duplicate_event_count"] == 1
    assert "nonce has already been seen" in batch["rejected_events"][0]["classification_reason"]
    assert "sequence is not greater" in batch["rejected_events"][0]["classification_reason"]


def test_stale_event_is_classified_as_stale():
    profile, transport, envelope = _envelope()
    stale = {**envelope, "signed_exchange_envelope": {**envelope["signed_exchange_envelope"], "expires_at": "2026-01-01T00:00:30+00:00"}}
    batch = apply_distributed_event_batch(
        [stale],
        propagation_window=_window(),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert batch["summary"]["stale_event_count"] == 1
    assert batch["rejected_events"][0]["propagation_status"] == "stale"


def test_missing_transport_session_is_malformed_event_rejection():
    profile, _, envelope = _envelope()
    batch = apply_distributed_event_batch(
        [envelope],
        propagation_window=_window(),
        trust_profile=profile,
        transport_sessions=[],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert batch["summary"]["malformed_event_count"] == 1
    assert batch["rejected_events"][0]["propagation_status"] == "malformed"
    assert "transport session was not provided" in batch["rejected_events"][0]["classification_reason"]


def test_event_batch_rollup_is_deterministic_and_private_safe():
    profile, transport, envelope = _envelope()
    batch = apply_distributed_event_batch(
        [envelope],
        propagation_window=_window(),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    payload = json.dumps(batch, sort_keys=True)

    assert deterministic_event_propagation_json(batch) == deterministic_event_propagation_json(batch)
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
