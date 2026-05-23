import json
import re

from core_engine.federation import (
    build_approved_peer_record,
    build_exchange_summary,
    build_local_node_trust_profile,
    build_signed_runtime_summary_envelope,
    canonical_json,
    create_trusted_transport_session,
    deterministic_digest,
    deterministic_exchange_json,
    validate_signed_runtime_summary_envelope,
    verify_signed_runtime_summary_envelope,
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


def _runtime_summary(node_id="node-worker-a"):
    return normalize_node_runtime_state(
        {
            **_node(node_id, "worker"),
            "lifecycle_state": "online",
            "last_seen_at": "2026-01-01T00:01:00+00:00",
            "health_summary": build_runtime_health_summary(generated_at="2026-01-01T00:01:00+00:00"),
        },
        generated_at="2026-01-01T00:02:00+00:00",
    )


def _trust_profile():
    peer = build_approved_peer_record(
        _runtime_summary("node-worker-a"),
        trust_scope_labels=["runtime-summary", "health-summary"],
        allowed_transport_modes=["local-file"],
        approved_at=GENERATED_AT,
        expires_at="2026-01-01T01:00:00+00:00",
    )
    return build_local_node_trust_profile(
        _node("node-master", "master"),
        approved_peers=[peer],
        created_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def _transport(profile=None):
    trust_profile = profile or _trust_profile()
    return create_trusted_transport_session(
        source_node=_node("node-master", "master"),
        destination_node=_runtime_summary("node-worker-a"),
        trust_profile=trust_profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
    )


def _envelope():
    profile = _trust_profile()
    transport = _transport(profile)
    envelope = build_signed_runtime_summary_envelope(
        _runtime_summary("node-worker-a"),
        source_node=_node("node-master", "master"),
        destination_node=_runtime_summary("node-worker-a"),
        trust_profile=profile,
        transport_session=transport,
        trust_scope_label="runtime-summary",
        sequence=7,
        nonce="nonce-007",
        issued_at=GENERATED_AT,
        key_reference="keyref:node-master-runtime",
        signature_value="signature-placeholder-007",
    )
    return profile, transport, envelope


def test_canonical_json_and_digest_are_deterministic():
    left = {"b": 2, "a": {"d": 4, "c": 3}}
    right = {"a": {"c": 3, "d": 4}, "b": 2}

    assert canonical_json(left) == canonical_json(right)
    assert deterministic_digest(left) == deterministic_digest(right)
    assert deterministic_digest(left).startswith("sha256:")


def test_build_signed_runtime_summary_envelope_has_digest_signature_and_attribution():
    profile, transport, envelope = _envelope()

    assert envelope["record_type"] == "signed_runtime_summary_envelope"
    assert envelope["source_node_id"] == "node-master"
    assert envelope["destination_node_id"] == "node-worker-a"
    assert envelope["transport_session_id"] == transport["session_id"]
    assert envelope["trust_profile_id"] == profile["profile_id"]
    assert envelope["payload_digest"].startswith("sha256:")
    assert envelope["signature_metadata"]["key_reference"] == "keyref:node-master-runtime"
    assert envelope["signing_status"]["status"] == "signed"
    assert envelope["private_signing_material_stored"] is False
    assert envelope["raw_private_key_stored"] is False
    assert envelope["network_listener_enabled"] is False


def test_verification_accepts_trusted_peer_and_replay_window():
    profile, transport, envelope = _envelope()
    verified = verify_signed_runtime_summary_envelope(
        envelope,
        trust_profile=profile,
        transport_session=transport,
        seen_nonces=[],
        last_sequence_by_node={"node-master": 6},
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert verified["exchange_status"] == "accepted"
    assert verified["verification_status"]["verification_status"] == "metadata-valid"
    assert verified["verification_status"]["cryptographic_signature_verified"] is False


def test_verification_rejects_digest_tampering():
    profile, transport, envelope = _envelope()
    tampered = {**envelope, "summary_payload": {**envelope["summary_payload"], "sync_status": "stale"}}
    verification = validate_signed_runtime_summary_envelope(
        tampered,
        trust_profile=profile,
        transport_session=transport,
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert verification["verification_status"] == "metadata-invalid"
    assert "summary payload digest does not match payload_digest" in verification["errors"]


def test_verification_rejects_untrusted_destination_hook():
    profile, transport, envelope = _envelope()
    tampered = {**envelope, "destination_node_id": "node-worker-unapproved"}
    verified = verify_signed_runtime_summary_envelope(
        tampered,
        trust_profile=profile,
        transport_session=transport,
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert verified["exchange_status"] == "untrusted"
    assert "destination node is not approved by trust profile" in verified["verification_status"]["errors"]


def test_replay_window_validation_rejects_seen_nonce_and_old_sequence():
    profile, transport, envelope = _envelope()
    verified = verify_signed_runtime_summary_envelope(
        envelope,
        trust_profile=profile,
        transport_session=transport,
        seen_nonces=["nonce-007"],
        last_sequence_by_node={"node-master": 7},
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert verified["exchange_status"] == "replayed"
    assert "nonce has already been seen in replay window" in verified["verification_status"]["errors"]
    assert "sequence is not greater than last accepted sequence for source node" in verified["verification_status"]["errors"]


def test_replay_window_validation_rejects_stale_envelope():
    profile, transport, envelope = _envelope()
    stale = {**envelope, "expires_at": "2026-01-01T00:00:30+00:00"}
    verified = verify_signed_runtime_summary_envelope(
        stale,
        trust_profile=profile,
        transport_session=transport,
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert verified["exchange_status"] == "stale"
    assert "exchange envelope is expired" in verified["verification_status"]["errors"]


def test_exchange_summary_is_deterministic_and_exchange_ready():
    profile, transport, envelope = _envelope()
    accepted = verify_signed_runtime_summary_envelope(
        envelope,
        trust_profile=profile,
        transport_session=transport,
        generated_at="2026-01-01T00:01:00+00:00",
    )
    summary = build_exchange_summary([envelope, accepted], generated_at="2026-01-01T00:02:00+00:00")

    assert summary["envelope_count"] == 2
    assert summary["by_status"] == {"accepted": 1, "exchange-ready": 1}
    assert summary["source_node_ids"] == ["node-master"]
    assert deterministic_exchange_json(summary) == deterministic_exchange_json(summary)


def test_signed_exchange_output_has_no_private_identifiers_or_private_material():
    _, _, envelope = _envelope()
    payload = json.dumps(envelope, sort_keys=True)

    assert "private-signing-material" not in payload
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
