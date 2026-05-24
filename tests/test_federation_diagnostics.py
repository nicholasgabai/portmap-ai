import json
import re

from core_engine.events import create_event
from core_engine.federation import (
    build_approved_peer_record,
    build_distributed_event_envelope,
    build_event_propagation_window,
    build_federation_diagnostics,
    build_federation_health_summary,
    build_local_node_trust_profile,
    build_signed_runtime_summary_envelope,
    build_synchronization_window,
    create_trusted_transport_session,
    deterministic_federation_diagnostics_json,
)
from core_engine.federation.event_propagation import apply_distributed_event_batch
from core_engine.federation.synchronization import apply_signed_summary_updates
from core_engine.nodes import create_node_capabilities, create_node_identity
from core_engine.runtime import build_runtime_health_summary, normalize_node_runtime_state
from core_engine.runtime.cluster_health import build_cluster_runtime_health


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


def _runtime_summary(node_id="node-worker-a", *, health_status="ok"):
    return normalize_node_runtime_state(
        {
            **_node(node_id, "worker"),
            "lifecycle_state": "online",
            "last_seen_at": "2026-01-01T00:01:00+00:00",
            "observed_at": "2026-01-01T00:02:00+00:00",
            "health_summary": build_runtime_health_summary(
                dashboard_provider={"status": health_status, "ready": health_status == "ok"},
                generated_at="2026-01-01T00:01:00+00:00",
            ),
        },
        generated_at="2026-01-01T00:02:00+00:00",
    )


def _profile(worker_id="node-worker-a", *, peer_expires_at="2026-01-01T01:00:00+00:00"):
    peer = build_approved_peer_record(
        _node("node-master", "master"),
        trust_scope_labels=["runtime-summary", "event-summary"],
        allowed_transport_modes=["local-file"],
        approved_at=GENERATED_AT,
        expires_at=peer_expires_at,
    )
    return build_local_node_trust_profile(
        _node(worker_id, "worker"),
        approved_peers=[peer],
        trust_scope_labels=["runtime-summary", "event-summary"],
        default_transport_modes=["local-file"],
        created_at=GENERATED_AT,
        replay_window_seconds=300,
    )


def _transport(profile=None, worker_id="node-worker-a", *, expires_at=None):
    trust_profile = profile or _profile(worker_id)
    return create_trusted_transport_session(
        source_node=_node(worker_id, "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=trust_profile,
        transport_mode="local-file",
        trust_scope_label="runtime-summary",
        started_at=GENERATED_AT,
        expires_at=expires_at,
    )


def _event_transport(profile=None, worker_id="node-worker-a"):
    trust_profile = profile or _profile(worker_id)
    return create_trusted_transport_session(
        source_node=_node(worker_id, "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=trust_profile,
        transport_mode="local-file",
        trust_scope_label="event-summary",
        started_at=GENERATED_AT,
    )


def _signed_envelope(profile, transport, *, sequence=1, nonce="runtime-nonce-001", health_status="ok", expires_at=None):
    return build_signed_runtime_summary_envelope(
        _runtime_summary("node-worker-a", health_status=health_status),
        source_node=_node("node-worker-a", "worker"),
        destination_node=_node("node-master", "master"),
        trust_profile=profile,
        transport_session=transport,
        trust_scope_label="runtime-summary",
        sequence=sequence,
        nonce=nonce,
        issued_at=GENERATED_AT,
        expires_at=expires_at,
        key_reference="keyref:node-worker-a-runtime",
        signature_value=f"signature-placeholder-{sequence}",
    )


def _event_envelope(profile, transport, *, sequence=1, nonce="event-nonce-001", event_id="evt-sanitized-001"):
    event = create_event(
        "system_notice",
        severity="info",
        source="federation.test",
        message="Sanitized federation event.",
        metadata={"fixture": "diagnostics"},
    ).to_dict() | {"event_id": event_id, "timestamp": GENERATED_AT}
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


def _healthy_inputs():
    profile = _profile()
    transport = _transport(profile)
    event_transport = _event_transport(profile)
    envelope = _signed_envelope(profile, transport)
    sync = apply_signed_summary_updates(
        [envelope],
        sync_window=build_synchronization_window(
            trusted_node_ids=["node-worker-a"],
            opened_at=GENERATED_AT,
            replay_window_seconds=300,
        ),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    event_envelope = _event_envelope(profile, event_transport)
    event_batch = apply_distributed_event_batch(
        [event_envelope],
        propagation_window=build_event_propagation_window(
            trusted_node_ids=["node-worker-a"],
            opened_at=GENERATED_AT,
            replay_window_seconds=300,
        ),
        trust_profile=profile,
        transport_sessions=[event_transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    cluster_health = build_cluster_runtime_health(
        [_runtime_summary("node-worker-a")],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    return profile, transport, event_transport, envelope, sync, event_batch, cluster_health


def test_federation_health_summary_reports_ready_state():
    profile, transport, event_transport, envelope, sync, event_batch, cluster_health = _healthy_inputs()
    health = build_federation_health_summary(
        trust_profile=profile,
        transport_sessions=[transport, event_transport],
        signed_exchanges=[envelope],
        sync_result=sync,
        event_batch=event_batch,
        cluster_health=cluster_health,
        generated_at="2026-01-01T00:02:00+00:00",
    )

    assert health["record_type"] == "federation_health_summary"
    assert health["status"] == "ok"
    assert health["readiness"]["score"] >= 80
    assert health["summary"]["degraded_count"] == 0
    assert health["network_listener_enabled"] is False
    assert health["remote_control_enabled"] is False


def test_federation_diagnostics_builds_dashboard_api_event_and_recommendations():
    profile, transport, event_transport, envelope, sync, event_batch, cluster_health = _healthy_inputs()
    diagnostics = build_federation_diagnostics(
        trust_profile=profile,
        transport_sessions=[transport, event_transport],
        signed_exchanges=[envelope],
        sync_result=sync,
        event_batch=event_batch,
        cluster_health=cluster_health,
        generated_at="2026-01-01T00:02:00+00:00",
    )

    assert diagnostics["record_type"] == "federation_diagnostics"
    assert diagnostics["status"] == "ok"
    assert diagnostics["dashboard_status"]["panel"] == "federation_diagnostics"
    assert diagnostics["api_status"]["readiness"]["score"] >= 80
    assert diagnostics["health_event"]["event_type"] == "runtime_health"
    assert diagnostics["recommendations"] == []


def test_degraded_diagnostics_counts_stale_duplicate_and_rejected_records():
    profile = _profile()
    transport = _transport(profile)
    event_transport = _event_transport(profile)
    stale_envelope = _signed_envelope(
        profile,
        transport,
        sequence=1,
        nonce="stale-runtime",
        expires_at="2026-01-01T00:00:30+00:00",
    )
    sync = apply_signed_summary_updates(
        [stale_envelope],
        sync_window=build_synchronization_window(opened_at=GENERATED_AT, replay_window_seconds=300),
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    event_envelope = _event_envelope(profile, event_transport, sequence=2, nonce="dup-event")
    event_window = build_event_propagation_window(opened_at=GENERATED_AT, replay_window_seconds=300)
    event_window["seen_nonces"] = ["dup-event"]
    event_window["last_sequence_by_node"] = {"node-worker-a": 2}
    event_batch = apply_distributed_event_batch(
        [event_envelope],
        propagation_window=event_window,
        trust_profile=profile,
        transport_sessions=[event_transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    diagnostics = build_federation_diagnostics(
        trust_profile=profile,
        transport_sessions=[transport, event_transport],
        signed_exchanges=[{**stale_envelope, "exchange_status": "stale"}],
        sync_result=sync,
        event_batch=event_batch,
        generated_at="2026-01-01T00:02:00+00:00",
    )

    metrics = diagnostics["dashboard_status"]["metrics"]
    assert diagnostics["status"] == "degraded"
    assert metrics["stale_update_count"] == 1
    assert metrics["duplicate_event_count"] == 2
    assert metrics["rejected_update_count"] == 1
    assert diagnostics["recommendations"]
    assert diagnostics["api_status"]["status"] == "degraded"


def test_unavailable_inputs_are_reported_without_crashing():
    diagnostics = build_federation_diagnostics(generated_at="2026-01-01T00:02:00+00:00")

    assert diagnostics["status"] == "degraded"
    assert diagnostics["health"]["summary"]["unavailable_count"] >= 4
    assert any(item["check_name"] == "trusted_peers" for item in diagnostics["recommendations"])


def test_expired_peer_and_transport_session_are_degraded():
    profile = _profile(peer_expires_at="2026-01-01T00:00:30+00:00")
    transport = _transport(_profile(), expires_at="2026-01-01T00:00:30+00:00")
    diagnostics = build_federation_diagnostics(
        trust_profile=profile,
        transport_sessions=[transport],
        generated_at="2026-01-01T00:02:00+00:00",
    )

    check_names = {item["name"]: item for item in diagnostics["health"]["checks"]}
    assert check_names["trusted_peers"]["status"] == "degraded"
    assert check_names["transport_sessions"]["status"] == "degraded"


def test_edge_device_thresholds_are_included():
    diagnostics = build_federation_diagnostics(edge_device=True, generated_at="2026-01-01T00:02:00+00:00")

    assert diagnostics["health"]["resource_thresholds"]["readiness_degraded_below"] == 75


def test_federation_diagnostics_output_is_deterministic_and_private_safe():
    profile, transport, event_transport, envelope, sync, event_batch, cluster_health = _healthy_inputs()
    diagnostics = build_federation_diagnostics(
        trust_profile=profile,
        transport_sessions=[transport, event_transport],
        signed_exchanges=[envelope],
        sync_result=sync,
        event_batch=event_batch,
        cluster_health=cluster_health,
        generated_at="2026-01-01T00:02:00+00:00",
    )
    payload = json.dumps(diagnostics, sort_keys=True)

    assert deterministic_federation_diagnostics_json(diagnostics) == deterministic_federation_diagnostics_json(diagnostics)
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
