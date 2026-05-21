import json
import re

from core_engine.runtime import (
    build_cluster_runtime_health,
    build_runtime_health_summary,
    default_runtime_profile,
)
from core_engine.runtime.cluster_health import (
    build_node_health_rollup,
    classify_node_health,
    summarize_cluster_component_health,
)
from core_engine.runtime.session_state import create_runtime_session, summarize_runtime_session


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _session_summary(node_id: str):
    return summarize_runtime_session(
        create_runtime_session(
            session_id=f"session-{node_id}",
            mode="dry-run",
            started_at="2026-01-01T00:00:00+00:00",
            enabled_components=["scheduler", "storage", "reviews", "exports"],
            metadata={"node_id": node_id},
        )
    )


def _health(*, queue_depth: int = 0, failed_jobs: int = 0, service_status: str = "ok", edge_device: bool = False):
    summary = build_runtime_health_summary(
        scheduler={"scheduler_status": "running", "failed_job_count": failed_jobs, "executed_job_count": 2},
        event_queue=[object()] * queue_depth,
        dashboard_provider={"status": "ok", "ready": True},
        edge_device=edge_device,
        generated_at="2026-01-01T00:05:00+00:00",
    )
    summary["checks"].append(
        {
            "name": "service_readiness",
            "status": service_status,
            "severity": "info" if service_status == "ok" else "medium",
            "message": "Service readiness preview checked.",
            "details": {"preview_only": True},
            "local_only": True,
            "raw_payload_stored": False,
            "automatic_changes": False,
            "administrator_controlled": True,
        }
    )
    summary["summary"] = {
        **summary["summary"],
        "check_count": len(summary["checks"]),
    }
    return summary


def _node_report(node_id: str, role: str = "worker", **overrides):
    profile = default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00")
    payload = {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "lifecycle_state": "online",
        "last_seen_at": "2026-01-01T00:05:00+00:00",
        "observed_at": "2026-01-01T00:05:00+00:00",
        "source_refs": [f"node-health:{node_id}"],
        "capabilities": {
            "platform": "linux",
            "architecture": "arm64" if role == "worker" else "x86_64",
            "supported_features": ["runtime", "health", "service-preview"],
            "runtime_version": "test-version",
        },
        "session_summary": _session_summary(node_id),
        "profile_summary": profile.to_dict(),
        "health_summary": _health(),
        "checkpoint_summary": {
            "latest_checkpoint_id": f"checkpoint-{node_id}",
            "status": "complete",
            "checkpoint_count": 1,
        },
    }
    payload.update(overrides)
    return payload


def test_cluster_runtime_health_rolls_up_master_and_worker_nodes():
    cluster = build_cluster_runtime_health(
        [_node_report("node-master-a", "master"), _node_report("node-worker-b", "worker")],
        generated_at="2026-01-01T00:06:00+00:00",
    )

    assert cluster["record_type"] == "cluster_runtime_health"
    assert cluster["status"] == "ok"
    assert [node["node_id"] for node in cluster["node_rollups"]] == ["node-master-a", "node-worker-b"]
    assert cluster["availability"]["roles"]["master_count"] == 1
    assert cluster["availability"]["roles"]["worker_count"] == 1
    assert cluster["component_rollups"]["scheduler"]["by_status"] == {"ok": 2}
    assert cluster["component_rollups"]["storage"]["by_status"] == {"unavailable": 2}
    assert cluster["component_rollups"]["service_readiness"]["by_status"] == {"ok": 2}
    assert cluster["health_event"]["event_type"] == "runtime_health"
    assert cluster["health_event"]["metadata"]["health_scope"] == "cluster"
    assert cluster["dashboard_panel"]["panel"] == "cluster_runtime_health"
    assert cluster["raw_payload_stored"] is False
    assert cluster["automatic_changes"] is False
    assert cluster["administrator_controlled"] is True


def test_cluster_runtime_health_classifies_degraded_stale_unavailable_and_malformed_nodes():
    cluster = build_cluster_runtime_health(
        [
            _node_report(
                "node-master-a",
                "master",
                last_seen_at="2026-01-01T00:06:00+00:00",
                health_summary=_health(failed_jobs=1),
            ),
            _node_report(
                "node-worker-stale",
                "worker",
                last_seen_at="2026-01-01T00:00:00+00:00",
                observed_at="2026-01-01T00:00:00+00:00",
            ),
            {"role": "worker", "health_summary": _health()},
        ],
        expected_nodes=["node-master-a", "node-worker-stale", "node-worker-missing"],
        generated_at="2026-01-01T00:10:00+00:00",
        stale_after_seconds=300,
    )

    by_id = {row["node_id"]: row for row in cluster["node_rollups"]}

    assert by_id["node-master-a"]["classification"] == "degraded"
    assert by_id["node-worker-stale"]["classification"] == "stale"
    assert by_id["node-worker-missing"]["classification"] == "unavailable"
    assert by_id["malformed-node-2"]["classification"] == "malformed"
    assert cluster["summary"]["degraded_node_count"] == 1
    assert cluster["summary"]["stale_node_count"] == 1
    assert cluster["summary"]["unavailable_node_count"] == 1
    assert cluster["summary"]["malformed_node_count"] == 1
    assert cluster["summary"]["administrator_review_required"] is True
    assert cluster["health_event"]["severity"] == "high"


def test_cluster_runtime_health_reports_resource_budget_warnings_for_edge_nodes():
    cluster = build_cluster_runtime_health(
        [_node_report("node-worker-edge", "worker", health_summary=_health(queue_depth=300, edge_device=True))],
        generated_at="2026-01-01T00:06:00+00:00",
        edge_device=True,
    )

    warnings = cluster["resource_budget_warnings"]["warnings"]
    warning_types = {warning["warning_type"] for warning in warnings}

    assert "event_queue_depth" in warning_types
    assert "event_queue_degraded" in warning_types
    assert cluster["resource_budgets"]["event_queue_warning_depth"] == 250
    assert cluster["summary"]["resource_warning_count"] >= 2
    assert cluster["dashboard_panel"]["metrics"]["resource_warning_count"] >= 2


def test_node_health_rollup_and_component_summary_are_deterministic():
    cluster = build_cluster_runtime_health(
        [_node_report("node-worker-b", "worker"), _node_report("node-master-a", "master")],
        generated_at="2026-01-01T00:06:00+00:00",
    )
    first = build_node_health_rollup(
        {
            "node_id": "node-sample",
            "node_label": "sample",
            "role": "worker",
            "sync_status": "current",
            "last_seen_at": "2026-01-01T00:05:00+00:00",
            "source_refs": ["node-health:sample"],
            "health_summary": _health(service_status="degraded"),
        },
        generated_at="2026-01-01T00:06:00+00:00",
    )
    components = summarize_cluster_component_health(cluster["node_rollups"])

    assert first["classification"] == "degraded"
    assert first["component_status"]["service_readiness"] == "degraded"
    assert list(components) == [
        "scheduler",
        "storage",
        "event_queue",
        "review_queue",
        "export_readiness",
        "service_readiness",
        "runtime_sessions",
    ]


def test_classify_node_health_handles_explicit_states():
    assert classify_node_health(sync_status="stale", health_status="ok") == "stale"
    assert classify_node_health(sync_status="missing", health_status="ok") == "unavailable"
    assert classify_node_health(sync_status="current", health_status="missing") == "unavailable"
    assert classify_node_health(sync_status="current", health_status="ok", malformed=True) == "malformed"


def test_cluster_runtime_health_output_has_no_private_identifiers():
    cluster = build_cluster_runtime_health(
        [_node_report("node-master-a", "master"), _node_report("node-worker-b", "worker")],
        generated_at="2026-01-01T00:06:00+00:00",
    )
    payload = json.dumps(cluster, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
