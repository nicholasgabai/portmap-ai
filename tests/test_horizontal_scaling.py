from __future__ import annotations

import json

from core_engine.scaling import (
    build_bus_envelope,
    build_horizontal_scaling_summary,
    build_retention_tier,
    build_storage_engine_summary,
    build_telemetry_bus_summary,
    build_worker_group,
    default_worker_groups,
    deterministic_scaling_json,
    deterministic_worker_group_json,
    empty_horizontal_scaling_summary,
    normalize_group_type,
    normalize_health_state,
    normalize_scaling_state,
    normalize_worker_group,
    plan_partition_count,
    plan_shard_count,
    recommended_cluster_size,
    worker_group_distribution,
)


GENERATED_AT = "2026-06-10T14:00:00+00:00"


def _group(**overrides):
    data = {
        "group_name": "Collector fixture group",
        "group_type": "collector",
        "worker_count": 2,
        "max_worker_count": 4,
        "source_modes": ["fixture"],
        "health_state": "healthy",
        "capacity_weight": 1.0,
    }
    data.update(overrides)
    return build_worker_group(**data)


def _bus(queue_depth=4, max_queue_depth=8, topic="worker_telemetry"):
    envelopes = [
        build_bus_envelope(
            topic=topic,
            message_type="runtime_summary",
            source_node="worker-alpha",
            source_mode="fixture",
            created_at=GENERATED_AT,
            payload={"count": index},
            payload_reference=f"runtime-{index}",
            delivery_state="queued",
        )
        for index in range(queue_depth)
    ]
    return build_telemetry_bus_summary(envelopes, max_queue_depth=max_queue_depth, generated_at=GENERATED_AT)


def _storage(records=10, capacity=100):
    return build_storage_engine_summary(
        [
            build_retention_tier(
                tier_name="Hot scaling tier",
                tier_type="hot",
                max_records=capacity,
                max_bytes=capacity * 1000,
                retention_window_seconds=3600,
                priority=10,
                compaction_policy="none",
                source_mode="fixture",
            )
        ],
        estimated_current_records=records,
        estimated_current_bytes=records * 1000,
        generated_at=GENERATED_AT,
        source_mode="fixture",
    )


def test_worker_group_creation_is_export_safe():
    group = _group().to_dict()

    assert group["record_type"] == "worker_group"
    assert group["group_type"] == "collector"
    assert group["worker_count"] == 2
    assert group["max_worker_count"] == 4
    assert group["source_modes"] == ["fixture"]
    assert group["health_state"] == "healthy"
    assert group["capacity_weight"] == 1.0
    assert group["preview_only"] is True
    assert group["destructive_action"] is False
    assert group["runtime_worker_count_modified"] is False
    assert group["infrastructure_provisioned"] is False
    assert group["cloud_dependency_required"] is False


def test_group_validation_normalizes_types_health_and_bounds():
    assert normalize_group_type("analysis") == "analysis"
    assert normalize_group_type("database") == "unknown"
    assert normalize_health_state("degraded") == "degraded"
    assert normalize_health_state("starting") == "unknown"

    group = _group(
        group_type="invalid",
        worker_count=10,
        max_worker_count=3,
        health_state="bad",
        capacity_weight=200,
    ).to_dict()

    assert group["group_type"] == "unknown"
    assert group["worker_count"] == 3
    assert group["max_worker_count"] == 3
    assert group["health_state"] == "unknown"
    assert group["capacity_weight"] == 100.0


def test_scaling_readiness_generation_with_defaults():
    summary = build_horizontal_scaling_summary(generated_at=GENERATED_AT, source_mode="fixture").to_dict()

    assert summary["record_type"] == "horizontal_scaling_summary"
    assert summary["scaling_state"] == "ready"
    assert summary["cluster_size"] == 4
    assert summary["recommended_cluster_size"] == 4
    assert summary["shard_count"] >= 1
    assert summary["partition_count"] >= 1
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["cluster_created"] is False
    assert summary["cloud_api_called"] is False


def test_capacity_calculations_and_recommended_cluster_size():
    assert recommended_cluster_size(cluster_size=4, max_cluster_size=10, utilization_ratio=0.1) == 4
    assert recommended_cluster_size(cluster_size=4, max_cluster_size=10, utilization_ratio=0.7) == 5
    assert recommended_cluster_size(cluster_size=4, max_cluster_size=10, utilization_ratio=0.9) == 5
    assert recommended_cluster_size(cluster_size=4, max_cluster_size=10, utilization_ratio=1.1) == 6
    assert recommended_cluster_size(cluster_size=4, max_cluster_size=5, utilization_ratio=1.1) == 5

    summary = build_horizontal_scaling_summary([_group(worker_count=4, max_worker_count=10)], storage_summaries=[_storage(90, 100)], generated_at=GENERATED_AT).to_dict()

    assert summary["utilization_ratio"] == 0.9
    assert summary["scaling_state"] == "capacity_pressure"
    assert summary["recommended_cluster_size"] == 5
    assert summary["capacity_summary"]["available_worker_slots"] == 6


def test_shard_and_partition_planning():
    storage = {"tier_count": 3}
    bus = {"topic_counts": {"worker_telemetry": 2, "runtime_health": 1}}

    assert plan_shard_count(cluster_size=4, utilization_ratio=0.4, storage_summary=storage) == 3
    assert plan_shard_count(cluster_size=4, utilization_ratio=0.9, storage_summary=storage) == 5
    assert plan_partition_count(shard_count=3, bus_summary=bus, storage_summary=storage) == 9


def test_worker_distribution_summaries():
    distribution = worker_group_distribution(
        [
            _group(group_type="collector", worker_count=2),
            _group(group_type="analysis", worker_count=1, health_state="degraded"),
            _group(group_type="visualization", worker_count=1, source_modes=["fixture", "replay"]),
        ]
    )

    assert distribution["group_count"] == 3
    assert distribution["worker_count"] == 4
    assert distribution["type_worker_counts"]["collector"] == 2
    assert distribution["health_state_counts"] == {"degraded": 1, "healthy": 2}
    assert distribution["source_modes"] == ["fixture", "replay"]


def test_storage_integration_drives_pressure_state():
    pressure = build_horizontal_scaling_summary(
        [_group(worker_count=3, max_worker_count=8), _group(group_type="analysis", worker_count=2, max_worker_count=6)],
        storage_summaries=[_storage(95, 100)],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert pressure["storage_summary"]["max_utilization_ratio"] == 0.95
    assert pressure["scaling_state"] == "capacity_pressure"
    assert pressure["recommended_cluster_size"] > pressure["cluster_size"]


def test_telemetry_bus_integration_drives_capacity_summary():
    bus = _bus(queue_depth=7, max_queue_depth=8, topic="flow_summary")
    summary = build_horizontal_scaling_summary(
        [_group(worker_count=2, max_worker_count=6), _group(group_type="analysis", worker_count=1, max_worker_count=5)],
        telemetry_bus_summaries=[bus],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["telemetry_bus_summary"]["queue_depth"] == 7
    assert summary["telemetry_bus_summary"]["topic_counts"]["flow_summary"] == 7
    assert summary["utilization_ratio"] == 0.875
    assert summary["scaling_state"] == "capacity_pressure"
    assert summary["capacity_summary"]["bus_queue_depth"] == 7


def test_scaling_state_transitions_and_fanout_readiness():
    ready = build_horizontal_scaling_summary(
        [_group(group_type="collector"), _group(group_type="analysis", worker_count=1, max_worker_count=3)],
        generated_at=GENERATED_AT,
    ).to_dict()
    growth = build_horizontal_scaling_summary([_group(worker_count=2, max_worker_count=4)], storage_summaries=[_storage(70, 100)], generated_at=GENERATED_AT).to_dict()
    degraded = build_horizontal_scaling_summary([_group(health_state="unavailable")], generated_at=GENERATED_AT).to_dict()
    empty = empty_horizontal_scaling_summary(generated_at=GENERATED_AT).to_dict()

    assert ready["scaling_state"] == "ready"
    assert ready["fanout_readiness"]["fanout_ready"] is True
    assert growth["scaling_state"] == "growth_ready"
    assert degraded["scaling_state"] == "degraded"
    assert empty["scaling_state"] == "unavailable"


def test_malformed_input_handling_degrades_safely():
    group = normalize_worker_group(object()).to_dict()
    summary = build_horizontal_scaling_summary([object()], telemetry_bus_summaries=[object()], storage_summaries=[object()], generated_at=GENERATED_AT).to_dict()

    assert group["group_type"] == "unknown"
    assert summary["scaling_state"] == "degraded"
    assert summary["cluster_size"] == 0
    assert summary["worker_groups"][0]["health_state"] == "unknown"


def test_source_mode_preservation():
    summary = build_horizontal_scaling_summary(
        [
            _group(source_modes=["fixture", "replay"]),
            _group(group_type="analysis", source_modes=["live"], worker_count=1, max_worker_count=3),
        ],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["capacity_summary"]["worker_distribution"]["source_modes"] == ["fixture", "live", "replay"]


def test_preview_and_destructive_flags_are_fixed():
    summary = build_horizontal_scaling_summary([_group()], generated_at=GENERATED_AT).to_dict()

    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert all(row["preview_only"] is True for row in summary["worker_groups"])
    assert all(row["destructive_action"] is False for row in summary["worker_groups"])
    assert summary["runtime_worker_count_modified"] is False
    assert summary["telemetry_routing_modified"] is False
    assert summary["orchestration_executed"] is False


def test_export_safe_serialization_is_json_safe():
    group = _group()
    summary = build_horizontal_scaling_summary([group], generated_at=GENERATED_AT)

    json.loads(deterministic_worker_group_json(group))
    json.loads(deterministic_scaling_json(summary))
    json.dumps(summary.to_dict(), sort_keys=True)


def test_no_provisioning_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    summary = build_horizontal_scaling_summary([_group()], generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["infrastructure_provisioned"] is False
    assert summary["cluster_created"] is False
    assert summary["cloud_api_called"] is False
    assert summary["telemetry_routing_modified"] is False


def test_cross_platform_safe_record_shape():
    groups = default_worker_groups(source_mode="fixture")
    summary = build_horizontal_scaling_summary(
        [
            *groups,
            _group(group_name="Windows worker group", group_type="collector", source_modes=["fixture"]),
            _group(group_name="macOS worker group", group_type="analysis", source_modes=["fixture"]),
            _group(group_name="Linux ARM worker group", group_type="intelligence", source_modes=["fixture"]),
        ],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["cluster_size"] >= 7
    assert summary["capacity_summary"]["worker_distribution"]["source_modes"] == ["fixture"]
    assert normalize_scaling_state("capacity pressure") == "capacity_pressure"
