from __future__ import annotations

import json

from core_engine.scaling import (
    build_bus_envelope,
    build_retention_tier,
    build_storage_engine_summary,
    build_telemetry_bus_summary,
    calculate_utilization,
    default_retention_tiers,
    deterministic_retention_json,
    deterministic_storage_json,
    empty_storage_engine_summary,
    normalize_compaction_policy,
    normalize_pressure_state,
    normalize_retention_tier,
    normalize_storage_state,
    normalize_tier_type,
    pressure_state_from_utilization,
    retention_tier_summary,
)


GENERATED_AT = "2026-06-10T12:00:00+00:00"


def _tier(**overrides):
    data = {
        "tier_name": "Hot fixture tier",
        "tier_type": "hot",
        "max_records": 100,
        "max_bytes": 100_000,
        "retention_window_seconds": 3600,
        "priority": 10,
        "compaction_policy": "none",
        "export_policy": "summary_only",
        "source_mode": "fixture",
    }
    data.update(overrides)
    return build_retention_tier(**data)


def _bus_summary(queue_depth=4, max_queue_depth=10, dropped_count=0):
    envelope_count = max_queue_depth + dropped_count if dropped_count else queue_depth
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
        for index in range(envelope_count)
    ]
    return build_telemetry_bus_summary(envelopes, max_queue_depth=max_queue_depth, generated_at=GENERATED_AT)


def test_retention_tier_generation_is_export_safe():
    tier = _tier().to_dict()

    assert tier["record_type"] == "retention_tier"
    assert tier["tier_type"] == "hot"
    assert tier["max_records"] == 100
    assert tier["max_bytes"] == 100_000
    assert tier["retention_window_seconds"] == 3600
    assert tier["priority"] == 10
    assert tier["compaction_policy"] == "none"
    assert tier["export_policy"] == "summary_only"
    assert tier["source_mode"] == "fixture"
    assert tier["preview_only"] is True
    assert tier["destructive_action"] is False
    assert tier["live_database_dependency"] is False
    assert tier["filesystem_written"] is False
    assert tier["data_deleted"] is False


def test_tier_validation_normalizes_types_policies_and_bounds():
    assert normalize_tier_type("warm") == "warm"
    assert normalize_tier_type("future") == "unknown"
    assert normalize_compaction_policy("rollup") == "rollup"
    assert normalize_compaction_policy("delete") == "unknown"

    tier = _tier(
        tier_type="invalid",
        max_records=-5,
        max_bytes="bad",
        retention_window_seconds=-10,
        priority=5000,
        compaction_policy="delete",
    ).to_dict()

    assert tier["tier_type"] == "unknown"
    assert tier["max_records"] == 0
    assert tier["max_bytes"] == 0
    assert tier["retention_window_seconds"] == 0
    assert tier["priority"] == 999
    assert tier["compaction_policy"] == "unknown"


def test_storage_readiness_generation_with_default_tiers():
    summary = build_storage_engine_summary(generated_at=GENERATED_AT, source_mode="fixture").to_dict()

    assert summary["record_type"] == "storage_engine_summary"
    assert summary["storage_state"] == "ready"
    assert summary["pressure_state"] == "normal"
    assert summary["total_record_capacity"] > 0
    assert summary["total_byte_capacity"] > 0
    assert summary["estimated_current_records"] == 0
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["runtime_data_written"] is False
    assert summary["live_database_dependency"] is False


def test_capacity_and_utilization_calculation():
    summary = build_storage_engine_summary(
        [_tier(max_records=100, max_bytes=10_000)],
        estimated_current_records=50,
        estimated_current_bytes=2_000,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert calculate_utilization(
        total_record_capacity=100,
        total_byte_capacity=10_000,
        estimated_current_records=50,
        estimated_current_bytes=2_000,
    ) == 0.5
    assert summary["utilization_ratio"] == 0.5
    assert summary["write_capacity_summary"]["estimated_remaining_records"] == 50


def test_pressure_state_transitions():
    assert pressure_state_from_utilization(0.1) == "normal"
    assert pressure_state_from_utilization(0.7) == "elevated"
    assert pressure_state_from_utilization(0.9) == "pressure"
    assert pressure_state_from_utilization(1.2) == "over_capacity"
    assert pressure_state_from_utilization(0.1, has_capacity=False) == "unavailable"

    elevated = build_storage_engine_summary([_tier(max_records=100)], estimated_current_records=70, generated_at=GENERATED_AT).to_dict()
    pressure = build_storage_engine_summary([_tier(max_records=100)], estimated_current_records=90, generated_at=GENERATED_AT).to_dict()
    over_capacity = build_storage_engine_summary([_tier(max_records=100)], estimated_current_records=120, generated_at=GENERATED_AT).to_dict()

    assert elevated["storage_state"] == "degraded"
    assert elevated["pressure_state"] == "elevated"
    assert pressure["storage_state"] == "pressure"
    assert over_capacity["storage_state"] == "over_capacity"


def test_compaction_preview_generation_is_non_destructive():
    summary = build_storage_engine_summary(
        [
            _tier(tier_type="warm", compaction_policy="summarize"),
            _tier(tier_type="cold", compaction_policy="sample"),
            _tier(tier_type="archive_preview", compaction_policy="rollup"),
            _tier(tier_type="hot", compaction_policy="drop_preview"),
        ],
        estimated_current_records=95,
        generated_at=GENERATED_AT,
    ).to_dict()

    preview = summary["compaction_preview"]
    assert preview["recommended"] is False
    assert preview["action_count"] == 4
    assert preview["compaction_executed"] is False
    assert preview["data_deleted"] is False
    assert all(action["destructive_action"] is False for action in preview["actions"])


def test_hot_warm_cold_archive_tier_summaries():
    tiers = default_retention_tiers(source_mode="fixture")
    summary = retention_tier_summary(tiers)

    assert summary["tier_count"] == 4
    assert summary["type_counts"] == {"archive_preview": 1, "cold": 1, "hot": 1, "warm": 1}
    assert summary["total_record_capacity"] > 0
    assert summary["total_byte_capacity"] > 0


def test_malformed_input_handling_degrades_safely():
    tier = normalize_retention_tier(object()).to_dict()
    summary = build_storage_engine_summary([object()], telemetry_bus_summaries=[object()], generated_at=GENERATED_AT).to_dict()

    assert tier["tier_type"] == "unknown"
    assert summary["storage_state"] == "degraded"
    assert summary["read_capacity_summary"]["readable_tier_count"] == 1
    assert summary["write_capacity_summary"]["queue_depth_input"] == 0


def test_empty_storage_behavior_is_unavailable_not_destructive():
    summary = empty_storage_engine_summary(generated_at=GENERATED_AT).to_dict()

    assert summary["storage_state"] == "unavailable"
    assert summary["pressure_state"] == "unavailable"
    assert summary["total_record_capacity"] == 0
    assert summary["total_byte_capacity"] == 0
    assert summary["retention_tiers"] == []
    assert summary["destructive_action"] is False


def test_telemetry_bus_summary_integration_estimates_current_load():
    bus = _bus_summary(queue_depth=3, max_queue_depth=5, dropped_count=2)
    summary = build_storage_engine_summary(
        [_tier(max_records=100, max_bytes=100_000)],
        telemetry_bus_summaries=[bus],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["estimated_current_records"] == 6
    assert summary["estimated_current_bytes"] == 6 * 1024
    assert summary["write_capacity_summary"]["queue_depth_input"] == 6
    assert summary["write_capacity_summary"]["dropped_by_bound_count"] == 2
    assert summary["read_capacity_summary"]["topic_counts"]["worker_telemetry"] == 5


def test_preview_and_destructive_flags_are_fixed():
    summary = build_storage_engine_summary([_tier()], generated_at=GENERATED_AT).to_dict()

    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert all(row["preview_only"] is True for row in summary["retention_tiers"])
    assert all(row["destructive_action"] is False for row in summary["retention_tiers"])


def test_no_filesystem_or_database_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    summary = build_storage_engine_summary([_tier()], generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["filesystem_written"] is False
    assert summary["runtime_data_written"] is False
    assert summary["live_database_dependency"] is False
    assert summary["data_deleted"] is False
    assert summary["compaction_executed"] is False


def test_export_safe_serialization_is_json_safe():
    tier = _tier()
    summary = build_storage_engine_summary([tier], generated_at=GENERATED_AT)

    json.loads(deterministic_retention_json(tier))
    json.loads(deterministic_storage_json(summary))
    json.dumps(summary.to_dict(), sort_keys=True)


def test_state_normalization_helpers():
    assert normalize_storage_state("over capacity") == "over_capacity"
    assert normalize_storage_state("bad") == "unknown"
    assert normalize_pressure_state("pressure") == "pressure"
    assert normalize_pressure_state("bad") == "unknown"


def test_cross_platform_safe_record_shape():
    summary = build_storage_engine_summary(
        [
            _tier(tier_name="Windows metadata tier", source_mode="fixture"),
            _tier(tier_name="macOS metadata tier", tier_type="warm", source_mode="fixture"),
            _tier(tier_name="Linux ARM metadata tier", tier_type="cold", source_mode="fixture"),
        ],
        generated_at=GENERATED_AT,
        source_mode="fixture",
    ).to_dict()

    assert summary["storage_state"] == "ready"
    assert summary["read_capacity_summary"]["readable_tier_count"] == 3
    assert {row["tier_type"] for row in summary["retention_tiers"]} == {"cold", "hot", "warm"}
