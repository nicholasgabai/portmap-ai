import re

import pytest

from core_engine.federation import (
    FederationExchangeJobError,
    build_approved_peer_record,
    build_event_propagation_job,
    build_federation_runtime_manager,
    build_local_node_trust_profile,
    build_peer_lifecycle_record,
    build_runtime_exchange_scheduler,
    build_trusted_peer_registry,
    create_trusted_transport_session,
    deterministic_exchange_scheduler_json,
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


def test_runtime_exchange_scheduler_builds_jobs_from_runtime_manager():
    profile = _profile()
    manager = build_federation_runtime_manager(
        trust_profile=profile,
        transport_sessions=[_transport(profile), _transport(profile, scope="event-summary")],
        state="active",
        generated_at="2026-01-01T00:01:00+00:00",
    )

    scheduler = build_runtime_exchange_scheduler(
        runtime_manager=manager,
        trust_profile=profile,
        generated_at="2026-01-01T00:02:00+00:00",
    )

    assert scheduler["record_type"] == "runtime_exchange_scheduler"
    assert scheduler["summary"]["job_count"] == 3
    assert scheduler["summary"]["enabled_job_count"] == 3
    assert scheduler["summary"]["by_job_type"] == {
        "cluster_state_sync": 1,
        "event_propagation": 1,
        "signed_summary_exchange": 1,
    }
    assert scheduler["per_peer_schedules"][0]["peer_node_id"] == "node-master"
    assert scheduler["per_peer_schedules"][0]["enabled_job_count"] == 3
    assert scheduler["dashboard_status"]["metrics"]["job_count"] == 3
    assert scheduler["api_status"]["status"] == "ready"
    assert scheduler["job_execution_enabled"] is False
    assert scheduler["network_listener_enabled"] is False
    assert scheduler["background_daemon_enabled"] is False


def test_paused_peer_lifecycle_disables_exchange_jobs():
    profile = _profile()
    peer = profile["approved_peers"][0]
    paused = build_peer_lifecycle_record(
        peer,
        lifecycle_state="paused",
        generated_at="2026-01-01T00:01:00+00:00",
    )
    registry = build_trusted_peer_registry(
        peer_lifecycle_records=[paused],
        generated_at="2026-01-01T00:02:00+00:00",
    )

    scheduler = build_runtime_exchange_scheduler(
        peer_registry=registry,
        trust_profile=profile,
        generated_at="2026-01-01T00:03:00+00:00",
    )

    assert scheduler["summary"]["status"] == "review_required"
    assert scheduler["summary"]["enabled_job_count"] == 0
    assert scheduler["summary"]["disabled_job_count"] == 3
    assert all(job["job_status"] == "disabled" for job in scheduler["jobs"])
    assert scheduler["per_peer_schedules"][0]["peer_lifecycle_state"] == "paused"


def test_failed_job_backoff_and_validation_are_deterministic():
    job = build_event_propagation_job(
        peer_node_id="node-master",
        interval_seconds=30,
        backoff_seconds=10,
        max_backoff_seconds=120,
        last_run_at="2026-01-01T00:00:00+00:00",
        failure_count=3,
        last_error_summary="event envelope verification failed",
        generated_at="2026-01-01T00:01:00+00:00",
    )

    assert job["job_status"] == "error"
    assert job["effective_backoff_seconds"] == 40
    assert job["next_run_at"] == "2026-01-01T00:01:10+00:00"
    assert job["validation"]["ok"] is True

    scheduler = build_runtime_exchange_scheduler(
        exchange_jobs=[job],
        generated_at="2026-01-01T00:02:00+00:00",
    )
    assert scheduler["summary"]["status"] == "review_required"
    assert scheduler["summary"]["failure_count"] == 3
    assert scheduler["dashboard_status"]["recommended_review"] is True


def test_exchange_job_rejects_invalid_intervals():
    with pytest.raises(FederationExchangeJobError):
        build_event_propagation_job(
            peer_node_id="node-master",
            interval_seconds=0,
            generated_at=GENERATED_AT,
        )


def test_scheduler_output_is_deterministic_and_private_safe():
    profile = _profile()
    scheduler = build_runtime_exchange_scheduler(
        trust_profile=profile,
        generated_at="2026-01-01T00:02:00+00:00",
    )

    first = deterministic_exchange_scheduler_json(scheduler)
    second = deterministic_exchange_scheduler_json(scheduler)

    assert first == second
    assert "node-master" in first
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(first)
