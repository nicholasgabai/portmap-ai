import re

from core_engine.events import create_event
from core_engine.federation import (
    build_active_federation_validation,
    build_approved_peer_record,
    build_distributed_event_envelope,
    build_event_propagation_job,
    build_event_propagation_window,
    build_federation_runtime_manager,
    build_local_node_trust_profile,
    build_runtime_exchange_scheduler,
    build_signed_runtime_summary_envelope,
    build_synchronization_window,
    create_trusted_transport_session,
    deterministic_active_federation_validation_json,
)
from core_engine.federation.event_propagation import apply_distributed_event_batch
from core_engine.federation.synchronization import apply_signed_summary_updates
from core_engine.nodes import create_node_capabilities, create_node_identity
from core_engine.runtime import build_runtime_health_summary, normalize_node_runtime_state


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


def _event_envelope(profile, transport, *, sequence=1, nonce="event-nonce-001", event_id="evt-sanitized-001"):
    event = create_event(
        "system_notice",
        severity="info",
        source="federation.validation.test",
        message="Sanitized federation validation event.",
        metadata={"fixture": "active-federation-validation"},
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
    manager = build_federation_runtime_manager(
        trust_profile=profile,
        transport_sessions=[runtime_transport, event_transport],
        signed_exchanges=[envelope],
        sync_result=sync,
        event_batch=event_batch,
        state="active",
        generated_at="2026-01-01T00:02:00+00:00",
    )
    scheduler = build_runtime_exchange_scheduler(
        runtime_manager=manager,
        trust_profile=profile,
        generated_at="2026-01-01T00:03:00+00:00",
    )
    return {
        "trust_profile": profile,
        "transport_sessions": [runtime_transport, event_transport],
        "signed_exchanges": [envelope],
        "sync_result": sync,
        "event_batch": event_batch,
        "runtime_manager": manager,
        "exchange_scheduler": scheduler,
        "generated_at": "2026-01-01T00:04:00+00:00",
    }


def test_active_federation_validation_reports_ready_state():
    validation = build_active_federation_validation(**_healthy_inputs())

    assert validation["record_type"] == "active_federation_validation"
    assert validation["status"] == "ready"
    assert validation["readiness"]["score"] >= 80
    assert validation["summary"]["check_count"] == 7
    assert validation["summary"]["degraded_count"] == 0
    assert validation["dashboard_status"]["metrics"]["ready_check_count"] == 7
    assert validation["api_status"]["status"] == "ready"
    assert validation["network_listener_enabled"] is False
    assert validation["background_daemon_enabled"] is False
    assert validation["job_execution_enabled"] is False


def test_validation_reports_scheduler_failures_for_operator_review():
    inputs = _healthy_inputs()
    failed_job = build_event_propagation_job(
        peer_node_id="node-master",
        failure_count=2,
        last_error_summary="event propagation retry window exceeded",
        generated_at="2026-01-01T00:04:00+00:00",
    )
    scheduler = build_runtime_exchange_scheduler(
        exchange_jobs=[failed_job],
        generated_at="2026-01-01T00:04:00+00:00",
    )

    validation = build_active_federation_validation(
        **{**inputs, "exchange_scheduler": scheduler, "generated_at": "2026-01-01T00:05:00+00:00"}
    )

    assert validation["status"] == "review_required"
    assert validation["summary"]["degraded_count"] == 1
    runtime_scheduler = next(check for check in validation["checks"] if check["name"] == "runtime_scheduler")
    assert runtime_scheduler["status"] == "degraded"
    assert runtime_scheduler["details"]["failure_count"] == 2
    assert validation["recommendations"]
    assert validation["dashboard_status"]["recommended_review"] is True


def test_validation_reports_replay_window_review_for_duplicate_events():
    inputs = _healthy_inputs()
    profile = inputs["trust_profile"]
    event_transport = inputs["transport_sessions"][1]
    duplicate_batch = apply_distributed_event_batch(
        [
            _event_envelope(profile, event_transport, sequence=1, nonce="event-nonce-duplicate", event_id="evt-duplicate"),
            _event_envelope(profile, event_transport, sequence=2, nonce="event-nonce-duplicate", event_id="evt-duplicate"),
        ],
        propagation_window=build_event_propagation_window(
            trusted_node_ids=["node-worker-a", "node-master"],
            opened_at=GENERATED_AT,
            replay_window_seconds=300,
        ),
        trust_profile=profile,
        transport_sessions=[event_transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )

    validation = build_active_federation_validation(
        **{**inputs, "event_batch": duplicate_batch, "generated_at": "2026-01-01T00:05:00+00:00"}
    )

    assert validation["status"] == "review_required"
    event_check = next(check for check in validation["checks"] if check["name"] == "event_propagation")
    replay_check = next(check for check in validation["checks"] if check["name"] == "replay_windows")
    assert event_check["status"] == "degraded"
    assert replay_check["status"] == "degraded"
    assert replay_check["details"]["duplicate_event_count"] >= 1


def test_validation_output_is_deterministic_and_private_safe():
    validation = build_active_federation_validation(**_healthy_inputs())

    first = deterministic_active_federation_validation_json(validation)
    second = deterministic_active_federation_validation_json(validation)

    assert first == second
    assert "active_federation_validation" in first
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(first)
