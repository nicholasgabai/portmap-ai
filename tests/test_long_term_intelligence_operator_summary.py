import json

from core_engine.history import (
    build_historical_snapshot,
    build_historical_timeline_replay,
    build_long_term_intelligence_summary,
    build_resource_aware_retention_report,
    deterministic_long_term_intelligence_json,
)
from core_engine.telemetry.behavior_summary import build_behavioral_intelligence_summary


NOW = "2026-05-15T00:00:00+00:00"


def _behavior_summary(generated_at: str = NOW):
    return build_behavioral_intelligence_summary(
        behavior_baseline_report={
            "summary": {
                "baseline_entry_count": 2,
                "stable_behavior_count": 2,
                "novel_behavior_count": 0,
                "average_confidence": 0.85,
            },
            "dashboard_status": {"metrics": {"baseline_entry_count": 2, "novel_behavior_count": 0, "average_confidence": 0.85}},
        },
        generated_at=generated_at,
    )


def _snapshot(index: int):
    ts = f"2026-05-{index + 1:02d}T00:00:00+00:00"
    return build_historical_snapshot(_behavior_summary(ts), source_label="long-term-fixture", generated_at=ts)


def _baseline_decay_report(*, stale=False):
    return {
        "record_type": "baseline_aging_decay_report",
        "report_id": "baseline-aging-decay-placeholder",
        "generated_at": NOW,
        "records": [{"source_id": "baseline-alpha", "record_kind": "baseline_entry"}],
        "summary": {
            "record_count": 1,
            "inactive_count": 0,
            "stale_count": 1 if stale else 0,
            "dormant_count": 0,
            "mature_count": 1 if not stale else 0,
            "malformed_record_count": 0,
        },
    }


def _topology_report(*, drift=False):
    return {
        "record_type": "long_term_topology_evolution_report",
        "report_id": "topology-evolution-placeholder",
        "generated_at": NOW,
        "relationship_summary": {
            "relationship_count": 1,
            "stable_relationship_count": 1 if not drift else 0,
            "transient_relationship_count": 0 if not drift else 1,
            "dormant_return_count": 0,
        },
        "drift_summary": {
            "status": "review_required" if drift else "stable",
            "added_relationship_count": 1 if drift else 0,
            "removed_relationship_count": 0,
            "dormant_return_count": 0,
        },
        "relationships": [{"relationship_id": "relationship-placeholder", "relationship_key": "asset-alpha->asset-beta"}],
    }


def _retention_report(*, low_resource=False):
    return build_resource_aware_retention_report(
        snapshots=[_snapshot(0), _snapshot(1)],
        historical_replay_report=build_historical_timeline_replay(historical_snapshots=[_snapshot(0)], generated_at=NOW),
        topology_evolution_report=_topology_report(),
        baseline_decay_report=_baseline_decay_report(),
        storage_summary={"free_mb": 64 if low_resource else 4096, "total_mb": 8192},
        memory_summary={"free_mb": 64 if low_resource else 1024, "total_mb": 2048},
        generated_at=NOW,
    )


def test_complete_long_term_summary_composition_is_supported():
    snapshots = [_snapshot(0), _snapshot(1)]
    replay = build_historical_timeline_replay(historical_snapshots=snapshots, generated_at=NOW)
    summary = build_long_term_intelligence_summary(
        historical_snapshots=snapshots,
        baseline_decay_report=_baseline_decay_report(),
        topology_evolution_report=_topology_report(),
        historical_replay_report=replay,
        resource_retention_report=_retention_report(),
        behavioral_intelligence_summary=_behavior_summary(),
        runtime_health={"status": "supported"},
        generated_at=NOW,
    )

    assert summary["status"] == "supported"
    assert summary["component_rollups"]["historical_snapshots"]["metrics"]["snapshot_count"] == 2
    assert summary["component_rollups"]["topology_evolution"]["metrics"]["relationship_count"] == 1
    assert summary["component_rollups"]["historical_replay"]["metrics"]["timeline_event_count"] > 0
    assert summary["component_rollups"]["resource_retention"]["state"] == "supported"
    assert summary["dashboard_status"]["panel"] == "long_term_intelligence"
    assert summary["api_status"]["status"] == "supported"
    assert summary["export_summary"]["digest"].startswith("sha256:")


def test_empty_inputs_are_unavailable_and_recommend_inputs():
    summary = build_long_term_intelligence_summary(generated_at=NOW)

    assert summary["status"] == "unavailable"
    assert summary["state_summary"]["unavailable_component_count"] == 5
    assert {row["action"] for row in summary["recommendations"]} == {"provide_historical_summary"}


def test_degraded_inputs_surface_operator_review_recommendations():
    summary = build_long_term_intelligence_summary(
        historical_snapshots=[_snapshot(0)],
        baseline_decay_report=_baseline_decay_report(stale=True),
        topology_evolution_report=_topology_report(drift=True),
        historical_replay_report=build_historical_timeline_replay(
            historical_snapshots=[{"record_type": "wrong", "snapshot_id": "bad"}],
            generated_at=NOW,
        ),
        resource_retention_report=_retention_report(low_resource=True),
        generated_at=NOW,
    )

    assert summary["status"] == "degraded"
    assert summary["component_rollups"]["baseline_decay"]["recommended_review_count"] > 0
    assert summary["component_rollups"]["topology_evolution"]["recommended_review_count"] > 0
    assert summary["component_rollups"]["resource_retention"]["state"] == "degraded"
    assert any(row["action"] == "operator_review_recommended" for row in summary["recommendations"])


def test_snapshot_topology_replay_and_retention_rollups_render_for_dashboard():
    snapshots = [_snapshot(0), _snapshot(1), _snapshot(2)]
    replay = build_historical_timeline_replay(historical_snapshots=snapshots, generated_at=NOW, max_events=4)
    summary = build_long_term_intelligence_summary(
        historical_snapshots=snapshots,
        baseline_decay_report=_baseline_decay_report(),
        topology_evolution_report=_topology_report(),
        historical_replay_report=replay,
        resource_retention_report=_retention_report(),
        generated_at=NOW,
    )
    rows = {row["component"]: row for row in summary["dashboard_status"]["component_rows"]}

    assert rows["historical_snapshots"]["record_count"] == 3
    assert rows["topology_evolution"]["record_count"] == 1
    assert rows["historical_replay"]["record_count"] == 4
    assert rows["resource_retention"]["record_count"] == 4


def test_privacy_fields_and_serialization_are_safe_and_deterministic():
    summary = build_long_term_intelligence_summary(
        historical_snapshots=[_snapshot(0)],
        baseline_decay_report=_baseline_decay_report(),
        topology_evolution_report=_topology_report(),
        historical_replay_report=build_historical_timeline_replay(historical_snapshots=[_snapshot(0)], generated_at=NOW),
        resource_retention_report=_retention_report(),
        generated_at=NOW,
    )
    left = deterministic_long_term_intelligence_json(summary)
    right = deterministic_long_term_intelligence_json(json.loads(left))

    assert left == right
    assert summary["privacy_safety_summary"]["payloads_stored"] is False
    assert summary["privacy_safety_summary"]["credentials_stored"] is False
    assert summary["privacy_safety_summary"]["raw_browsing_history_stored"] is False
    assert summary["automatic_enforcement"] is False
    assert summary["automatic_deletion"] is False
