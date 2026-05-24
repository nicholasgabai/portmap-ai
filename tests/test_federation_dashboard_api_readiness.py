import json
import re

from core_engine.events import create_event
from core_engine.federation import (
    build_approved_peer_record,
    build_distributed_event_envelope,
    build_empty_federation_state_model,
    build_event_propagation_window,
    build_federation_diagnostics,
    build_federation_operator_view,
    build_local_node_trust_profile,
    build_signed_runtime_summary_envelope,
    build_synchronization_window,
    create_trusted_transport_session,
    deterministic_federation_operator_view_json,
)
from core_engine.federation.event_propagation import apply_distributed_event_batch
from core_engine.federation.synchronization import apply_signed_summary_updates
from core_engine.nodes import create_node_capabilities, create_node_identity
from core_engine.runtime import build_cluster_runtime_health, build_runtime_health_summary, normalize_node_runtime_state
from gui.web.federation_views import (
    build_empty_federation_dashboard_view,
    build_federation_dashboard_view,
    federation_dashboard_api_response,
    render_federation_dashboard_sections,
)


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


def _signed_envelope(profile, transport, *, sequence=1, nonce="runtime-nonce-001", expires_at=None):
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
        expires_at=expires_at,
        key_reference="keyref:node-worker-a-runtime",
        signature_value=f"signature-placeholder-{sequence}",
    )


def _event_envelope(profile, transport, *, sequence=1, nonce="event-nonce-001"):
    event = create_event(
        "system_notice",
        severity="info",
        source="federation.dashboard.test",
        message="Sanitized federation event.",
        metadata={"fixture": "dashboard"},
    ).to_dict() | {"event_id": "evt-sanitized-001", "timestamp": GENERATED_AT}
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


def _dashboard_inputs():
    profile = _profile()
    runtime_transport = _transport(profile)
    event_transport = _transport(profile, scope="event-summary")
    envelope = _signed_envelope(profile, runtime_transport)
    sync = apply_signed_summary_updates(
        [envelope],
        sync_window=build_synchronization_window(
            trusted_node_ids=["node-worker-a"],
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
    diagnostics = build_federation_diagnostics(
        trust_profile=profile,
        transport_sessions=[runtime_transport, event_transport],
        signed_exchanges=[envelope],
        sync_result=sync,
        event_batch=event_batch,
        cluster_health=cluster_health,
        generated_at="2026-01-01T00:02:00+00:00",
    )
    return {
        "trust_profile": profile,
        "transport_sessions": [runtime_transport, event_transport],
        "signed_exchanges": [envelope],
        "sync_result": sync,
        "event_batch": event_batch,
        "diagnostics": diagnostics,
        "cluster_health": cluster_health,
        "generated_at": "2026-01-01T00:03:00+00:00",
    }


def test_federation_operator_view_builds_dashboard_api_panels():
    view = build_federation_operator_view(**_dashboard_inputs())

    assert view["record_type"] == "federation_operator_view"
    assert view["status"] == "ok"
    assert set(view["panels"]) == {
        "trusted_peers",
        "transport_sessions",
        "signed_exchanges",
        "synchronization",
        "event_propagation",
        "diagnostics",
        "readiness",
        "counters",
    }
    assert view["panels"]["trusted_peers"]["metrics"]["approved_peer_count"] == 1
    assert view["panels"]["transport_sessions"]["metrics"]["session_count"] == 2
    assert view["panels"]["signed_exchanges"]["metrics"]["envelope_count"] == 1
    assert view["panels"]["synchronization"]["metrics"]["accepted_update_count"] == 1
    assert view["panels"]["event_propagation"]["metrics"]["event_count"] == 1
    assert view["panels"]["diagnostics"]["metrics"]["readiness_score"] >= 80
    assert view["panels"]["readiness"]["metrics"]["readiness_score"] >= 80
    assert view["panels"]["counters"]["metrics"]["rejected_update_count"] == 0
    assert view["api"]["count"] == 8
    assert view["network_listener_enabled"] is False
    assert view["remote_control_enabled"] is False
    assert view["textual_tui_replaced"] is False


def test_degraded_counters_surface_stale_duplicate_and_rejected_records():
    inputs = _dashboard_inputs()
    profile = inputs["trust_profile"]
    runtime_transport = inputs["transport_sessions"][0]
    event_transport = inputs["transport_sessions"][1]
    stale_envelope = _signed_envelope(
        profile,
        runtime_transport,
        sequence=2,
        nonce="stale-runtime",
        expires_at="2026-01-01T00:00:30+00:00",
    )
    sync = apply_signed_summary_updates(
        [stale_envelope],
        sync_window=build_synchronization_window(opened_at=GENERATED_AT, replay_window_seconds=300),
        trust_profile=profile,
        transport_sessions=[runtime_transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    event_window = build_event_propagation_window(opened_at=GENERATED_AT, replay_window_seconds=300)
    event_window["seen_nonces"] = ["duplicate-event"]
    event_window["last_sequence_by_node"] = {"node-worker-a": 2}
    event_batch = apply_distributed_event_batch(
        [_event_envelope(profile, event_transport, sequence=2, nonce="duplicate-event")],
        propagation_window=event_window,
        trust_profile=profile,
        transport_sessions=[event_transport],
        generated_at="2026-01-01T00:01:00+00:00",
    )
    diagnostics = build_federation_diagnostics(
        trust_profile=profile,
        transport_sessions=inputs["transport_sessions"],
        signed_exchanges=[{**stale_envelope, "exchange_status": "stale"}],
        sync_result=sync,
        event_batch=event_batch,
        generated_at="2026-01-01T00:02:00+00:00",
    )
    view = build_federation_operator_view(
        trust_profile=profile,
        transport_sessions=inputs["transport_sessions"],
        signed_exchanges=[{**stale_envelope, "exchange_status": "stale"}],
        sync_result=sync,
        event_batch=event_batch,
        diagnostics=diagnostics,
        generated_at="2026-01-01T00:03:00+00:00",
    )

    assert view["status"] == "review_required"
    assert view["panels"]["counters"]["metrics"]["stale_update_count"] == 1
    assert view["panels"]["counters"]["metrics"]["duplicate_event_count"] >= 1
    assert view["panels"]["signed_exchanges"]["metrics"]["rejected_exchange_count"] == 1
    assert view["panels"]["diagnostics"]["recommended_review"] is True


def test_empty_state_models_are_local_api_compatible():
    empty = build_empty_federation_state_model(generated_at="2026-01-01T00:03:00+00:00")
    view = build_federation_operator_view(generated_at="2026-01-01T00:03:00+00:00")
    dashboard = build_empty_federation_dashboard_view(generated_at="2026-01-01T00:03:00+00:00")

    assert empty["status"] == "empty"
    assert view["status"] == "empty"
    assert view["api"]["status"] == "empty"
    assert view["api"]["count"] == 0
    assert all(panel["status"] == "empty" for panel in view["panels"].values())
    assert len(dashboard["sections"]) == 8
    assert dashboard["remote_control_enabled"] is False


def test_web_federation_view_sections_render_and_api_response():
    dashboard = build_federation_dashboard_view(**_dashboard_inputs())
    api = federation_dashboard_api_response(dashboard)
    rendered = render_federation_dashboard_sections(dashboard)

    assert len(dashboard["sections"]) == 8
    assert api["count"] == 8
    assert api["public_exposure_enabled"] is False
    assert "Trusted Peers" in rendered
    assert "Federation Diagnostics" in rendered
    assert "Readiness Score" in rendered


def test_federation_dashboard_output_is_deterministic_and_private_safe():
    view = build_federation_operator_view(**_dashboard_inputs())
    payload = json.dumps(view, sort_keys=True)

    assert deterministic_federation_operator_view_json(view) == deterministic_federation_operator_view_json(view)
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
