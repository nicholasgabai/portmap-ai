import json
import re

import pytest

from core_engine.nodes import NodeRegistry, create_node_capabilities, create_node_identity
from core_engine.runtime import (
    DistributedNodeStateError,
    build_cluster_runtime_state,
    build_runtime_checkpoint,
    classify_node_sync_status,
    default_runtime_profile,
    merge_node_runtime_states,
    normalize_node_runtime_state,
    normalize_node_runtime_states,
    summarize_cluster_runtime_state,
)
from core_engine.runtime.health import build_runtime_health_summary
from core_engine.runtime.session_state import create_runtime_session, summarize_runtime_session


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _session(node_id="node-master"):
    return create_runtime_session(
        session_id=f"session-{node_id}",
        mode="dry-run",
        started_at="2026-01-01T00:00:00+00:00",
        enabled_components=["storage", "scheduler", "reviews"],
        metadata={"node_id": node_id},
    )


def _health(status="ok"):
    return build_runtime_health_summary(
        scheduler={"scheduler_status": "running", "failed_job_count": 0, "executed_job_count": 1},
        event_queue=[],
        dashboard_provider={"status": status, "ready": status == "ok"},
        generated_at="2026-01-01T00:00:00+00:00",
    )


def _report(node_id="node-master", role="master", **overrides):
    session = _session(node_id)
    profile = default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00")
    checkpoint = build_runtime_checkpoint(
        session=session,
        profile_summary={"profile_id": profile.profile_id},
        status="complete",
        created_at="2026-01-01T00:05:00+00:00",
    )
    payload = {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "lifecycle_state": "online",
        "last_seen_at": "2026-01-01T00:05:00+00:00",
        "observed_at": "2026-01-01T00:05:00+00:00",
        "source_refs": [f"node-report:{node_id}"],
        "capabilities": {
            "platform": "linux",
            "architecture": "arm64" if role == "worker" else "x86_64",
            "supported_features": ["runtime", "health"],
            "runtime_version": "test-version",
        },
        "session_summary": summarize_runtime_session(session),
        "profile_summary": profile.to_dict(),
        "health_summary": _health("ok"),
        "checkpoint": checkpoint,
    }
    payload.update(overrides)
    return payload


def test_normalize_node_runtime_state_from_dict():
    state = normalize_node_runtime_state(
        _report(),
        generated_at="2026-01-01T00:06:00+00:00",
        stale_after_seconds=300,
    )

    assert state["record_type"] == "distributed_node_runtime_state"
    assert state["node_id"] == "node-master"
    assert state["role"] == "master"
    assert state["sync_status"] == "current"
    assert state["session_reference"]["record_id"] == "session-node-master"
    assert state["profile_reference"]["record_id"] == "runtime-default"
    assert state["checkpoint_reference"]["record_id"].startswith("runtime-checkpoint-")
    assert state["component_summary"]["enabled_component_count"] == 3
    assert state["raw_payload_stored"] is False
    assert state["automatic_changes"] is False
    assert state["administrator_controlled"] is True


def test_normalize_node_runtime_state_from_registry_entry():
    registry = NodeRegistry()
    identity = create_node_identity(
        role="worker",
        node_id="node-worker",
        now="2026-01-01T00:00:00+00:00",
    )
    capabilities = create_node_capabilities(
        node_id="node-worker",
        role="worker",
        platform="linux",
        architecture="arm64",
        supported_features=["runtime", "health"],
    )
    registry.register_node(identity, capabilities, now="2026-01-01T00:00:00+00:00")
    registry.update_heartbeat(
        "node-worker",
        now="2026-01-01T00:05:00+00:00",
        health_status="ok",
        scheduler_status="running",
        event_queue_depth=0,
    )

    state = normalize_node_runtime_states(
        registry,
        generated_at="2026-01-01T00:06:00+00:00",
        stale_after_seconds=300,
    )[0]

    assert state["node_id"] == "node-worker"
    assert state["role"] == "worker"
    assert state["capability_summary"]["platform"] == "linux"
    assert state["sync_status"] == "current"


def test_stale_and_missing_detection_in_cluster_state():
    cluster = build_cluster_runtime_state(
        [
            _report(
                "node-master",
                "master",
                last_seen_at="2026-01-01T00:00:00+00:00",
                observed_at="2026-01-01T00:00:00+00:00",
            )
        ],
        expected_nodes=["node-master", "node-worker"],
        generated_at="2026-01-01T00:10:00+00:00",
        stale_after_seconds=300,
    )

    assert cluster["summary"]["stale_node_count"] == 1
    assert cluster["summary"]["missing_node_count"] == 1
    assert {conflict["conflict_type"] for conflict in cluster["conflicts"]} == {"stale_node", "missing_node"}
    assert cluster["summary"]["administrator_review_required"] is True


def test_duplicate_node_state_conflicts_are_reported():
    first = normalize_node_runtime_state(
        _report("node-shared", "worker", node_label="worker-a"),
        generated_at="2026-01-01T00:06:00+00:00",
    )
    second = normalize_node_runtime_state(
        _report(
            "node-shared",
            "master",
            node_label="master-a",
            profile_summary={"profile_id": "runtime-alt", "status": "valid"},
            health_summary={"status": "degraded", "generated_at": "2026-01-01T00:04:00+00:00"},
        ),
        generated_at="2026-01-01T00:07:00+00:00",
    )

    merged = merge_node_runtime_states([first, second], generated_at="2026-01-01T00:08:00+00:00")
    conflict_types = {conflict["conflict_type"] for conflict in merged["conflicts"]}

    assert len(merged["nodes"]) == 1
    assert conflict_types >= {"duplicate_node", "role_conflict", "label_conflict", "profile_conflict", "health_conflict"}
    assert all(conflict["recommended_review"] is True for conflict in merged["conflicts"])


def test_cluster_summary_has_role_counts_and_deterministic_order():
    cluster = build_cluster_runtime_state(
        [_report("node-worker-b", "worker"), _report("node-master-a", "master")],
        generated_at="2026-01-01T00:06:00+00:00",
    )

    assert [node["node_id"] for node in cluster["nodes"]] == ["node-master-a", "node-worker-b"]
    assert cluster["summary"]["roles"]["master_count"] == 1
    assert cluster["summary"]["roles"]["worker_count"] == 1
    assert cluster["summary"]["current_node_count"] == 2


def test_classify_node_sync_status_handles_invalid_timestamps():
    assert (
        classify_node_sync_status(
            lifecycle_state="online",
            last_seen_at="not-a-timestamp",
            generated_at="2026-01-01T00:00:00+00:00",
            stale_after_seconds=300,
        )
        == "conflicting"
    )


def test_invalid_role_is_rejected():
    with pytest.raises(DistributedNodeStateError):
        normalize_node_runtime_state(_report(role="untrusted"))


def test_summarize_cluster_runtime_state_accepts_empty_state():
    summary = summarize_cluster_runtime_state([], generated_at="2026-01-01T00:00:00+00:00")

    assert summary["node_count"] == 0
    assert summary["roles"]["master_count"] == 0
    assert summary["administrator_review_required"] is False


def test_distributed_node_state_output_has_no_private_identifiers():
    cluster = build_cluster_runtime_state(
        [_report("node-master", "master"), _report("node-worker", "worker")],
        generated_at="2026-01-01T00:06:00+00:00",
    )
    payload = json.dumps(cluster, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
