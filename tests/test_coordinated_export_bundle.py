import json
import re

from core_engine.export import (
    build_coordinated_export_bundle_plan,
    build_node_evidence_manifest,
    detect_export_conflicts,
    export_coordinated_bundle_plan_json,
)
from core_engine.policy import build_review_record, create_policy
from core_engine.runtime.health import build_runtime_health_summary
from core_engine.topology.federated import build_federated_topology
from core_engine.topology.snapshots import build_topology_snapshot


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _snapshot(node_id: str):
    return build_topology_snapshot(
        assets=[
            {
                "asset_id": f"asset-{node_id}",
                "label": f"Asset {node_id}",
                "category": "workload",
                "confidence": 0.9,
            }
        ],
        services=[{"asset_id": f"asset-{node_id}", "service": "https", "port": 443}],
        topology_edges=[
            {
                "edge_id": f"edge-{node_id}",
                "source_asset": f"asset-{node_id}",
                "target_asset": "asset-shared",
                "relationship_type": "service_dependency",
                "service_label": "https",
            }
        ],
        findings=[
            {
                "finding_id": f"finding-{node_id}",
                "finding_type": "sample",
                "severity": "medium",
                "summary": "Sample finding.",
            }
        ],
        label=f"snapshot-{node_id}",
        observed_at="2026-01-01T00:00:00+00:00",
    )


def _review(node_id: str):
    policy = create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review coordinated export records.",
        now="2026-01-01T00:00:00+00:00",
    )
    return build_review_record(
        policy=policy,
        source_ref=f"finding:finding-{node_id}",
        category="coordinated_export_sample",
        severity="medium",
        title=f"Sample Review {node_id}",
        summary=f"Sample review summary {node_id}.",
        evidence_refs=[f"finding:finding-{node_id}"],
        now="2026-01-01T00:00:00+00:00",
    ).to_dict()


def _health():
    return build_runtime_health_summary(
        scheduler={"scheduler_status": "running", "failed_job_count": 0, "executed_job_count": 1},
        event_queue=[],
        dashboard_provider={"status": "ok", "ready": True},
        generated_at="2026-01-01T00:00:00+00:00",
    )


def _node_payload(node_id: str, role: str = "worker", **overrides):
    snapshot = _snapshot(node_id)
    federated = build_federated_topology(
        [{"node_id": node_id, "snapshot": snapshot}],
        generated_at="2026-01-01T00:00:00+00:00",
    )
    payload = {
        "node_id": node_id,
        "node_label": f"{role}-node",
        "role": role,
        "source_refs": [f"node-export:{node_id}"],
        "snapshots": [snapshot],
        "assets": federated["assets"],
        "services": federated["services"],
        "topology_edges": federated["topology_edges"],
        "topology_conflicts": federated["conflicts"],
        "findings": federated["findings"],
        "reviews": [_review(node_id)],
        "runtime_summary": {"status": "ok", "session_id": f"session-{node_id}"},
        "health_summary": _health(),
    }
    payload.update(overrides)
    return payload


def test_node_evidence_manifest_counts_and_redacts_private_identifiers():
    private_host = ".".join(["192", "168", "1", "10"])
    manifest = build_node_evidence_manifest(
        _node_payload(
            "node-worker-a",
            findings=[
                {
                    "finding_id": "finding-private",
                    "finding_type": "sample",
                    "severity": "medium",
                    "evidence": {"host": private_host, "path": "/" + "Users" + "/sample/data"},
                }
            ],
        ),
        generated_at="2026-01-02T00:00:00+00:00",
    )
    payload = json.dumps(manifest, sort_keys=True)

    assert manifest["record_type"] == "node_evidence_manifest"
    assert manifest["record_counts"]["snapshots"] == 1
    assert manifest["record_counts"]["topology_assets"] == 2
    assert manifest["record_counts"]["reviews"] == 1
    assert manifest["record_counts"]["runtime"] == 1
    assert manifest["record_counts"]["health"] == 1
    assert manifest["placeholder_validation"]["ok"] is True
    assert manifest["manifest_digest"].startswith("sha256:")
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)


def test_coordinated_export_plan_builds_manifest_digest_and_archive_plan(tmp_path):
    plan = build_coordinated_export_bundle_plan(
        [_node_payload("node-master-a", "master"), _node_payload("node-worker-b", "worker")],
        expected_nodes=["node-master-a", "node-worker-b"],
        output_path=tmp_path / "coordinated-export.zip",
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert plan["record_type"] == "coordinated_export_bundle_plan"
    assert plan["manifest"]["manifest_type"] == "coordinated_export_bundle"
    assert plan["manifest"]["source_node_ids"] == ["node-master-a", "node-worker-b"]
    assert plan["manifest"]["record_counts"]["totals"]["snapshots"] == 2
    assert plan["manifest"]["record_counts"]["totals"]["reviews"] == 2
    assert plan["manifest"]["digest_summary"]["cross_node_digest"].startswith("sha256:")
    assert plan["archive_plan"]["archive_requested"] is True
    assert plan["archive_plan"]["archive_name"] == "coordinated-export.zip"
    assert plan["archive_plan"]["write_performed"] is False
    assert plan["archive_plan"]["output_directory_stored"] is False
    assert plan["summary"]["status"] == "ok"
    assert plan["raw_payload_stored"] is False


def test_coordinated_export_plan_reports_missing_and_malformed_nodes():
    plan = build_coordinated_export_bundle_plan(
        [_node_payload("node-master-a", "master"), {"role": "worker"}],
        expected_nodes=["node-master-a", "node-worker-missing"],
        generated_at="2026-01-02T00:00:00+00:00",
    )
    conflict_types = {conflict["conflict_type"] for conflict in plan["conflicts"]}

    assert plan["summary"]["status"] == "review_required"
    assert plan["summary"]["missing_node_count"] == 1
    assert plan["manifest"]["missing_node_count"] == 1
    assert {"missing_node_manifest", "malformed_node_manifest"} <= conflict_types
    assert plan["missing_nodes"][0]["missing_node_id"] == "node-worker-missing"
    assert all(conflict["recommended_review"] is True for conflict in plan["conflicts"])


def test_duplicate_node_manifests_are_export_conflicts():
    manifests = [
        build_node_evidence_manifest(_node_payload("node-shared"), generated_at="2026-01-02T00:00:00+00:00"),
        build_node_evidence_manifest(_node_payload("node-shared"), generated_at="2026-01-02T00:00:00+00:00"),
    ]

    conflicts = detect_export_conflicts(manifests, generated_at="2026-01-02T00:00:00+00:00")

    assert {conflict["conflict_type"] for conflict in conflicts} == {"duplicate_node_manifest"}
    assert conflicts[0]["source_node_ids"] == ["node-shared"]


def test_coordinated_export_json_is_deterministic_for_sanitized_input():
    kwargs = {
        "node_payloads": [_node_payload("node-master-a", "master"), _node_payload("node-worker-b", "worker")],
        "expected_nodes": ["node-master-a", "node-worker-b"],
        "generated_at": "2026-01-02T00:00:00+00:00",
    }
    first = build_coordinated_export_bundle_plan(**kwargs)
    second = build_coordinated_export_bundle_plan(**kwargs)

    assert first["manifest"]["manifest_digest"] == second["manifest"]["manifest_digest"]
    assert export_coordinated_bundle_plan_json(first) == export_coordinated_bundle_plan_json(second)


def test_coordinated_export_output_has_no_private_identifiers():
    plan = build_coordinated_export_bundle_plan(
        [_node_payload("node-master-a", "master"), _node_payload("node-worker-b", "worker")],
        generated_at="2026-01-02T00:00:00+00:00",
    )
    payload = export_coordinated_bundle_plan_json(plan)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
