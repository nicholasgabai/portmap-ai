from __future__ import annotations

import json

from core_engine.scaling import (
    build_bus_envelope,
    build_horizontal_scaling_summary,
    build_resource_budget,
    build_resource_optimization_summary,
    build_retention_tier,
    build_storage_engine_summary,
    build_telemetry_bus_summary,
    build_worker_group,
    default_resource_budgets,
    deterministic_resource_budget_json,
    deterministic_resource_optimization_json,
    empty_resource_optimization_summary,
    normalize_budget_type,
    normalize_optimization_state,
    normalize_resource_budget,
    resource_budget_totals,
    utilization_ratio,
)


GENERATED_AT = "2026-06-10T16:00:00+00:00"


def _budget(**overrides):
    data = {
        "budget_name": "Workstation fixture budget",
        "budget_type": "workstation",
        "cpu_budget_percent": 60.0,
        "memory_budget_mb": 2048,
        "storage_budget_mb": 10_000,
        "telemetry_budget_per_minute": 100,
        "worker_budget_count": 4,
        "source_modes": ["fixture"],
    }
    data.update(overrides)
    return build_resource_budget(**data)


def _bus(queue_depth=20, max_queue_depth=100):
    envelopes = [
        build_bus_envelope(
            topic="worker_telemetry",
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
                tier_name="Hot resource tier",
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


def _scaling(cluster_size=2, max_worker_count=4, storage_records=10):
    return build_horizontal_scaling_summary(
        [
            build_worker_group(
                group_type="collector",
                worker_count=cluster_size,
                max_worker_count=max_worker_count,
                source_modes=["fixture"],
                health_state="healthy",
            ),
            build_worker_group(
                group_type="analysis",
                worker_count=1,
                max_worker_count=max_worker_count,
                source_modes=["fixture"],
                health_state="healthy",
            ),
        ],
        storage_summaries=[_storage(storage_records, 100)],
        generated_at=GENERATED_AT,
        source_mode="fixture",
    )


def test_resource_budget_creation_is_export_safe():
    budget = _budget().to_dict()

    assert budget["record_type"] == "resource_budget"
    assert budget["budget_type"] == "workstation"
    assert budget["cpu_budget_percent"] == 60.0
    assert budget["memory_budget_mb"] == 2048
    assert budget["storage_budget_mb"] == 10_000
    assert budget["telemetry_budget_per_minute"] == 100
    assert budget["worker_budget_count"] == 4
    assert budget["source_modes"] == ["fixture"]
    assert budget["preview_only"] is True
    assert budget["destructive_action"] is False
    assert budget["runtime_enforcement_enabled"] is False
    assert budget["telemetry_throttled"] is False
    assert budget["sampling_changed"] is False


def test_budget_validation_normalizes_types_and_bounds():
    assert normalize_budget_type("edge") == "edge"
    assert normalize_budget_type("cloud") == "unknown"

    budget = _budget(
        budget_type="invalid",
        cpu_budget_percent=200,
        memory_budget_mb=-1,
        storage_budget_mb="bad",
        telemetry_budget_per_minute=-50,
        worker_budget_count=50_000,
    ).to_dict()

    assert budget["budget_type"] == "unknown"
    assert budget["cpu_budget_percent"] == 100.0
    assert budget["memory_budget_mb"] == 0
    assert budget["storage_budget_mb"] == 0
    assert budget["telemetry_budget_per_minute"] == 0
    assert budget["worker_budget_count"] == 10_000


def test_optimization_readiness_generation_with_defaults():
    summary = build_resource_optimization_summary(generated_at=GENERATED_AT, source_mode="fixture").to_dict()

    assert summary["record_type"] == "resource_optimization_summary"
    assert summary["optimization_state"] == "optimized"
    assert summary["resource_budgets"][0]["budget_type"] == "workstation"
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["runtime_behavior_modified"] is False
    assert summary["sampling_changed"] is False


def test_utilization_calculations():
    summary = build_resource_optimization_summary(
        [_budget()],
        cpu_used_percent=30,
        memory_used_mb=1024,
        storage_used_mb=5000,
        telemetry_events_per_minute=50,
        worker_count=2,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert utilization_ratio(30, 60) == 0.5
    assert summary["cpu_utilization_ratio"] == 0.5
    assert summary["memory_utilization_ratio"] == 0.5
    assert summary["storage_utilization_ratio"] == 0.5
    assert summary["telemetry_utilization_ratio"] == 0.5
    assert summary["worker_utilization_ratio"] == 0.5


def test_adaptive_sampling_preview_generation():
    summary = build_resource_optimization_summary(
        [_budget()],
        telemetry_bus_summaries=[_bus(queue_depth=85, max_queue_depth=100)],
        telemetry_events_per_minute=85,
        generated_at=GENERATED_AT,
    ).to_dict()

    preview = summary["adaptive_sampling_preview"]
    assert preview["recommended"] is True
    assert preview["highest_utilization_ratio"] == 0.85
    assert preview["sampling_changed"] is False
    assert preview["collection_logic_changed"] is False


def test_load_shedding_preview_generation():
    summary = build_resource_optimization_summary(
        [_budget()],
        cpu_used_percent=58,
        memory_used_mb=1900,
        telemetry_events_per_minute=95,
        generated_at=GENERATED_AT,
    ).to_dict()

    preview = summary["load_shedding_preview"]
    assert summary["optimization_state"] == "constrained"
    assert preview["recommended"] is True
    assert preview["telemetry_throttled"] is False
    assert preview["runtime_behavior_modified"] is False


def test_scaling_integration_sets_worker_ratio():
    scaling = _scaling(cluster_size=3, max_worker_count=4, storage_records=70)
    summary = build_resource_optimization_summary(
        [_budget(worker_budget_count=4)],
        scaling_summaries=[scaling],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["scaling_summary"]["cluster_size"] == 4
    assert summary["worker_utilization_ratio"] == 1.0
    assert summary["optimization_state"] == "constrained"


def test_storage_integration_sets_storage_ratio():
    storage = _storage(records=90, capacity=100)
    summary = build_resource_optimization_summary(
        [_budget(storage_budget_mb=1000)],
        storage_summaries=[storage],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["storage_summary"]["max_utilization_ratio"] == 0.9
    assert summary["storage_utilization_ratio"] == 0.9
    assert summary["optimization_state"] == "constrained"


def test_telemetry_bus_integration_sets_telemetry_ratio():
    bus = _bus(queue_depth=70, max_queue_depth=100)
    summary = build_resource_optimization_summary(
        [_budget(telemetry_budget_per_minute=200)],
        telemetry_bus_summaries=[bus],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["telemetry_bus_summary"]["queue_depth"] == 70
    assert summary["telemetry_utilization_ratio"] == 0.7
    assert summary["optimization_state"] == "growth_ready"


def test_state_transitions_and_empty_degraded_behavior():
    optimized = build_resource_optimization_summary([_budget()], generated_at=GENERATED_AT).to_dict()
    growth = build_resource_optimization_summary([_budget()], cpu_used_percent=42, generated_at=GENERATED_AT).to_dict()
    constrained = build_resource_optimization_summary([_budget()], cpu_used_percent=58, generated_at=GENERATED_AT).to_dict()
    degraded = build_resource_optimization_summary([object()], telemetry_bus_summaries=[object()], generated_at=GENERATED_AT).to_dict()
    empty = empty_resource_optimization_summary(generated_at=GENERATED_AT).to_dict()

    assert optimized["optimization_state"] == "optimized"
    assert growth["optimization_state"] == "growth_ready"
    assert constrained["optimization_state"] == "constrained"
    assert degraded["optimization_state"] == "degraded"
    assert empty["optimization_state"] == "unavailable"


def test_malformed_budget_handling_is_safe():
    budget = normalize_resource_budget(object()).to_dict()
    totals = resource_budget_totals([object()])

    assert budget["budget_type"] == "unknown"
    assert budget["preview_only"] is True
    assert totals["budget_count"] == 1
    assert totals["worker_budget_count"] == 0


def test_source_mode_preservation():
    summary = build_resource_optimization_summary(
        [
            _budget(source_modes=["fixture", "replay"]),
            _budget(budget_type="edge", source_modes=["live"], worker_budget_count=1),
        ],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["resource_budgets"][0]["source_modes"] == ["fixture", "replay"]
    assert summary["resource_budgets"][1]["source_modes"] == ["live"]


def test_preview_and_destructive_flags_are_fixed():
    summary = build_resource_optimization_summary([_budget()], generated_at=GENERATED_AT).to_dict()

    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert all(row["preview_only"] is True for row in summary["resource_budgets"])
    assert all(row["destructive_action"] is False for row in summary["resource_budgets"])
    assert summary["telemetry_throttled"] is False
    assert summary["sampling_changed"] is False
    assert summary["worker_count_modified"] is False
    assert summary["infrastructure_changed"] is False


def test_export_safe_serialization_is_json_safe():
    budget = _budget()
    summary = build_resource_optimization_summary([budget], generated_at=GENERATED_AT)

    json.loads(deterministic_resource_budget_json(budget))
    json.loads(deterministic_resource_optimization_json(summary))
    json.dumps(summary.to_dict(), sort_keys=True)


def test_no_runtime_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    summary = build_resource_optimization_summary([_budget()], generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["runtime_behavior_modified"] is False
    assert summary["collection_logic_changed"] is False
    assert summary["worker_count_modified"] is False
    assert summary["cloud_resource_created"] is False


def test_cross_platform_safe_record_shape():
    summary = build_resource_optimization_summary(
        [
            *default_resource_budgets(source_mode="fixture"),
            _budget(budget_name="Edge Linux ARM budget", budget_type="edge", worker_budget_count=1),
            _budget(budget_name="Windows workstation budget", budget_type="workstation"),
            _budget(budget_name="macOS workstation budget", budget_type="workstation"),
        ],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert len(summary["resource_budgets"]) == 4
    assert summary["optimization_state"] == "optimized"
    assert normalize_optimization_state("growth ready") == "growth_ready"
