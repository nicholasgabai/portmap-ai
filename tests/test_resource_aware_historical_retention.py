import json

from core_engine.history import (
    build_adaptive_retention_windows,
    build_baseline_aging_decay_report,
    build_historical_snapshot,
    build_historical_timeline_replay,
    build_resource_aware_retention_report,
    build_retention_policy_record,
    build_retention_recommendations,
    build_storage_budget_summary,
    deterministic_resource_retention_json,
    get_raspberry_pi_retention_policy,
)
from core_engine.history.resource_retention import build_memory_budget_summary
from core_engine.telemetry.behavior_summary import build_behavioral_intelligence_summary


NOW = "2026-05-01T00:00:00+00:00"


def _behavior_summary(generated_at=NOW):
    return build_behavioral_intelligence_summary(
        behavior_baseline_report={
            "summary": {
                "baseline_entry_count": 2,
                "stable_behavior_count": 1,
                "novel_behavior_count": 1,
                "average_confidence": 0.8,
            },
            "dashboard_status": {
                "metrics": {
                    "baseline_entry_count": 2,
                    "novel_behavior_count": 1,
                    "average_confidence": 0.8,
                }
            },
        },
        generated_at=generated_at,
    )


def _snapshot(index: int):
    return build_historical_snapshot(
        _behavior_summary(f"2026-04-{index + 1:02d}T00:00:00+00:00"),
        source_label="retention-fixture",
        generated_at=f"2026-04-{index + 1:02d}T00:00:00+00:00",
    )


def _topology_report(count=3):
    return {
        "record_type": "long_term_topology_evolution_report",
        "relationship_summary": {"relationship_count": count},
        "relationships": [
            {"relationship_id": f"relationship-{index}", "relationship_key": f"node-a->node-{index}"}
            for index in range(count)
        ],
    }


def _baseline_report(count=4):
    return build_baseline_aging_decay_report(
        baseline_entries=[
            {
                "baseline_id": f"baseline-{index}",
                "first_seen": "2026-04-01T00:00:00+00:00",
                "last_seen": "2026-04-30T00:00:00+00:00",
                "observation_count": 3,
                "confidence": 0.8,
                "stable_behavior": True,
            }
            for index in range(count)
        ],
        generated_at=NOW,
    )


def test_default_retention_policy_generation_is_safe_and_deterministic():
    policy = build_retention_policy_record(generated_at=NOW)
    rendered = json.loads(deterministic_resource_retention_json({"policy": policy}))

    assert policy["profile_label"] == "default"
    assert policy["category_limits"]["snapshots"] == 30
    assert policy["metadata_only"] is True
    assert policy["automatic_deletion"] is False
    assert rendered["policy"]["policy_id"] == policy["policy_id"]


def test_low_storage_degrades_retention_without_deleting():
    policy = build_retention_policy_record(generated_at=NOW)
    snapshots = [_snapshot(index) for index in range(6)]
    report = build_resource_aware_retention_report(
        snapshots=snapshots,
        retention_policy=policy,
        storage_summary={"free_mb": 64, "total_mb": 4096, "used_mb": 4032},
        memory_summary={"free_mb": 1024, "total_mb": 4096},
        generated_at=NOW,
    )

    assert report["storage_budget"]["status"] == "degraded"
    assert report["adaptive_windows"]["resource_factor"] < 1.0
    assert report["summary"]["status"] == "degraded"
    assert report["delete_performed"] is False
    assert report["automatic_deletion"] is False


def test_low_memory_degrades_replay_and_baseline_windows():
    policy = build_retention_policy_record(generated_at=NOW)
    replay = build_historical_timeline_replay(
        historical_snapshots=[_snapshot(0), _snapshot(1)],
        generated_at=NOW,
        max_events=10,
    )
    report = build_resource_aware_retention_report(
        historical_replay_report=replay,
        baseline_decay_report=_baseline_report(6),
        retention_policy=policy,
        storage_summary={"free_mb": 2048, "total_mb": 8192},
        memory_summary={"free_mb": 64, "total_mb": 1024},
        generated_at=NOW,
    )

    assert report["memory_budget"]["status"] == "degraded"
    assert report["adaptive_windows"]["adapted_category_limits"]["replay"] < policy["category_limits"]["replay"]
    assert report["adaptive_windows"]["adapted_category_limits"]["behavioral_baselines"] < policy["category_limits"]["behavioral_baselines"]


def test_raspberry_pi_profile_uses_smaller_bounded_defaults():
    default_policy = build_retention_policy_record(generated_at=NOW)
    pi_policy = get_raspberry_pi_retention_policy(generated_at=NOW)
    windows = build_adaptive_retention_windows(
        policy=pi_policy,
        storage_budget=build_storage_budget_summary({"free_mb": 4096, "total_mb": 8192}, policy=pi_policy, generated_at=NOW),
        memory_budget=build_memory_budget_summary({"free_mb": 1024, "total_mb": 2048}, policy=pi_policy, generated_at=NOW),
        platform_record={"platform_family": "raspberry-pi-linux-arm"},
        generated_at=NOW,
    )

    assert pi_policy["edge_device_profile"] is True
    assert pi_policy["category_limits"]["snapshots"] < default_policy["category_limits"]["snapshots"]
    assert windows["adapted_category_limits"]["snapshots"] <= pi_policy["category_limits"]["snapshots"]
    assert "raspberry_pi_edge_retention_profile_recommended" in windows["warnings"]


def test_adaptive_retention_recommendations_cover_all_history_categories():
    policy = build_retention_policy_record(overrides={"max_snapshots": 2, "max_replay_events": 2, "max_topology_relationships": 2, "max_baseline_records": 2}, generated_at=NOW)
    adaptive = build_adaptive_retention_windows(policy=policy, generated_at=NOW)
    recommendations = build_retention_recommendations(
        snapshots=[_snapshot(0), _snapshot(1), _snapshot(2)],
        historical_replay_report={"timeline_events": [{"event_id": "event-a"}, {"event_id": "event-b"}, {"event_id": "event-c"}]},
        topology_evolution_report=_topology_report(3),
        baseline_decay_report={"records": [{"baseline_id": "a"}, {"baseline_id": "b"}, {"baseline_id": "c"}]},
        adaptive_windows=adaptive,
        generated_at=NOW,
    )

    assert {row["category"] for row in recommendations} == {"snapshots", "replay", "topology_history", "behavioral_baselines"}
    assert all(row["over_recommended_limit"] is True for row in recommendations)
    assert all(row["deletion_preview_only"] is True for row in recommendations)
    assert all(row["delete_performed"] is False for row in recommendations)


def test_serialization_export_summary_is_safe_and_deterministic():
    report = build_resource_aware_retention_report(
        snapshots=[_snapshot(0)],
        topology_evolution_report=_topology_report(1),
        baseline_decay_report=_baseline_report(1),
        storage_summary={"free_mb": 2048, "total_mb": 4096},
        memory_summary={"free_mb": 512, "total_mb": 1024},
        generated_at=NOW,
    )
    left = deterministic_resource_retention_json(report)
    right = deterministic_resource_retention_json(json.loads(left))

    assert left == right
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert "payload" not in report["export_summary"]
    assert report["packet_payloads_stored"] is False
    assert report["credentials_stored"] is False


def test_malformed_resource_input_uses_safe_degraded_defaults():
    report = build_resource_aware_retention_report(
        snapshots=[],
        storage_summary="not-a-storage-summary",  # type: ignore[arg-type]
        memory_summary=["not-a-memory-summary"],  # type: ignore[arg-type]
        generated_at=NOW,
    )

    assert report["storage_budget"]["status"] == "unavailable"
    assert report["memory_budget"]["status"] == "unavailable"
    assert report["summary"]["status"] == "unavailable"
    assert report["path_modified"] is False
    assert report["delete_performed"] is False
