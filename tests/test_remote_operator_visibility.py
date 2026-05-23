import json
import re

from core_engine.export import build_coordinated_export_bundle_plan
from core_engine.policy import build_distributed_review_summary, build_review_record, create_policy
from core_engine.runtime import (
    build_cluster_runtime_health,
    build_operator_visibility_summary,
    build_runtime_health_summary,
    build_service_mode_readiness,
    build_stale_node_rendering_models,
    build_trusted_node_visibility_summaries,
    default_runtime_profile,
)
from core_engine.runtime.node_sync import build_cluster_runtime_state
from core_engine.runtime.session_state import create_runtime_session, summarize_runtime_session
from core_engine.topology.federated import build_federated_topology
from core_engine.topology.snapshots import build_topology_snapshot
from gui.web import (
    build_distributed_operator_view,
    distributed_operator_api_response,
    render_distributed_operator_sections,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _session_summary(node_id: str):
    return summarize_runtime_session(
        create_runtime_session(
            session_id=f"session-{node_id}",
            mode="dry-run",
            started_at="2026-01-01T00:00:00+00:00",
            enabled_components=["runtime", "health", "reviews"],
            metadata={"node_id": node_id},
        )
    )


def _health(failed_jobs: int = 0):
    summary = build_runtime_health_summary(
        scheduler={"scheduler_status": "running", "failed_job_count": failed_jobs, "executed_job_count": 1},
        event_queue=[],
        dashboard_provider={"status": "ok", "ready": True},
        generated_at="2026-01-01T00:05:00+00:00",
    )
    summary["checks"].append(
        {
            "name": "service_readiness",
            "status": "ok",
            "severity": "info",
            "message": "Service readiness preview checked.",
            "details": {"preview_only": True},
            "local_only": True,
            "raw_payload_stored": False,
            "automatic_changes": False,
            "administrator_controlled": True,
        }
    )
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
        "source_refs": [f"node-visibility:{node_id}"],
        "capabilities": {
            "platform": "linux",
            "architecture": "arm64" if role == "worker" else "x86_64",
            "supported_features": ["runtime", "health", "service-preview"],
        },
        "session_summary": _session_summary(node_id),
        "profile_summary": profile.to_dict(),
        "health_summary": _health(),
    }
    payload.update(overrides)
    return payload


def _snapshot(node_id: str):
    return build_topology_snapshot(
        assets=[{"asset_id": f"asset-{node_id}", "label": f"Asset {node_id}", "category": "workload", "confidence": 0.9}],
        services=[{"asset_id": f"asset-{node_id}", "service": "https", "port": 443}],
        topology_edges=[
            {
                "edge_id": f"edge-{node_id}",
                "source_asset": f"asset-{node_id}",
                "target_asset": "asset-shared",
                "relationship_type": "service_dependency",
            }
        ],
        findings=[{"finding_id": f"finding-{node_id}", "finding_type": "sample", "severity": "medium"}],
        label=f"snapshot-{node_id}",
        observed_at="2026-01-01T00:00:00+00:00",
    )


def _review(node_id: str):
    policy = create_policy(
        policy_id="policy-sample",
        name="Sample Policy",
        description="Review sample distributed visibility records.",
        now="2026-01-01T00:00:00+00:00",
    )
    return build_review_record(
        policy=policy,
        source_ref=f"finding:finding-{node_id}",
        category="visibility_review",
        severity="medium",
        title=f"Sample Review {node_id}",
        summary=f"Sample review summary {node_id}.",
        now="2026-01-01T00:00:00+00:00",
    ).to_dict()


def _node_export_payload(node_id: str, role: str = "worker"):
    snapshot = _snapshot(node_id)
    return {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "snapshots": [snapshot],
        "findings": snapshot["findings"],
        "reviews": [_review(node_id)],
        "runtime_summary": {"status": "ok", "session_id": f"session-{node_id}"},
        "health_summary": _health(),
    }


def _visibility_inputs():
    generated_at = "2026-01-01T00:09:00+00:00"
    node_reports = [_node_report("node-master-a", "master"), _node_report("node-worker-b", "worker")]
    distributed_state = build_cluster_runtime_state(node_reports, generated_at=generated_at)
    cluster_health = build_cluster_runtime_health(node_reports, generated_at=generated_at)
    federated_topology = build_federated_topology(
        [
            {"node_id": "node-master-a", "snapshot": _snapshot("node-master-a")},
            {"node_id": "node-worker-b", "snapshot": _snapshot("node-worker-b")},
        ],
        generated_at=generated_at,
    )
    distributed_review = build_distributed_review_summary(
        [
            {"node_id": "node-master-a", "role": "master", "reviews": [_review("node-master-a")]},
            {"node_id": "node-worker-b", "role": "worker", "reviews": [_review("node-worker-b")]},
        ],
        generated_at=generated_at,
    )
    coordinated_export = build_coordinated_export_bundle_plan(
        [_node_export_payload("node-master-a", "master"), _node_export_payload("node-worker-b", "worker")],
        generated_at=generated_at,
    )
    service_readiness = {
        "node-master-a": build_service_mode_readiness(generated_at=generated_at),
        "node-worker-b": build_service_mode_readiness(generated_at=generated_at),
    }
    return {
        "distributed_state": distributed_state,
        "cluster_health": cluster_health,
        "federated_topology": federated_topology,
        "distributed_review": distributed_review,
        "coordinated_export": coordinated_export,
        "service_readiness_by_node": service_readiness,
        "generated_at": generated_at,
    }


def test_operator_visibility_summary_builds_all_panels():
    model = build_operator_visibility_summary(**_visibility_inputs())

    assert model["record_type"] == "trusted_operator_visibility_summary"
    assert model["summary"]["node_count"] == 2
    assert set(model["panels"]) == {
        "cluster_runtime",
        "federated_topology",
        "distributed_review",
        "coordinated_export",
        "service_readiness",
    }
    assert model["panels"]["cluster_runtime"]["metrics"]["node_count"] == 2
    assert model["panels"]["federated_topology"]["metrics"]["source_node_count"] == 2
    assert model["panels"]["distributed_review"]["metrics"]["review_count"] == 2
    assert model["panels"]["coordinated_export"]["metrics"]["node_count"] == 2
    assert model["panels"]["service_readiness"]["metrics"]["node_count"] == 2
    assert model["remote_control_enabled"] is False
    assert model["public_exposure_enabled"] is False
    assert model["cloud_sync_enabled"] is False


def test_trusted_node_visibility_and_stale_rendering_models():
    generated_at = "2026-01-01T00:09:00+00:00"
    stale_report = _node_report(
        "node-worker-stale",
        "worker",
        last_seen_at="2026-01-01T00:00:00+00:00",
        observed_at="2026-01-01T00:00:00+00:00",
    )
    state = build_cluster_runtime_state(
        [_node_report("node-master-a", "master"), stale_report],
        generated_at=generated_at,
        stale_after_seconds=300,
    )
    health = build_cluster_runtime_health(
        [_node_report("node-master-a", "master"), stale_report],
        generated_at=generated_at,
        stale_after_seconds=300,
    )

    nodes = build_trusted_node_visibility_summaries(
        distributed_state=state,
        cluster_health=health,
        generated_at=generated_at,
    )
    stale = build_stale_node_rendering_models(distributed_state=state, cluster_health=health, generated_at=generated_at)

    assert [node["node_id"] for node in nodes] == ["node-master-a", "node-worker-stale"]
    assert stale[0]["node_id"] == "node-worker-stale"
    assert stale[0]["render_status"] == "stale"
    assert stale[0]["remote_control_enabled"] is False


def test_empty_state_visibility_model_is_api_compatible():
    model = build_operator_visibility_summary(generated_at="2026-01-02T00:00:00+00:00")

    assert model["summary"]["empty_state"] is True
    assert model["empty_state"]["status"] == "empty"
    assert model["api"]["status"] == "ok"
    assert model["api"]["count"] == 0
    assert all(panel["status"] == "empty" for panel in model["panels"].values())


def test_distributed_web_view_sections_and_api_response():
    view = build_distributed_operator_view(**_visibility_inputs())
    api = distributed_operator_api_response(view)
    rendered = render_distributed_operator_sections(view)

    assert len(view["sections"]) == 5
    assert api["count"] == 2
    assert api["remote_control_enabled"] is False
    assert "Cluster Runtime" in rendered
    assert "Service Readiness" in rendered


def test_operator_visibility_output_has_no_private_identifiers():
    model = build_operator_visibility_summary(**_visibility_inputs())
    payload = json.dumps(model, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
