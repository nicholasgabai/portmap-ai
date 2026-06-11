from __future__ import annotations

import json

from core_engine.scaling import (
    build_bus_envelope,
    build_edge_profile,
    build_edge_worker_mode_summary,
    build_horizontal_scaling_summary,
    build_resource_optimization_summary,
    build_retention_tier,
    build_storage_engine_summary,
    build_telemetry_bus_summary,
    build_worker_group,
    default_edge_profiles,
    deterministic_edge_profile_json,
    deterministic_edge_worker_mode_json,
    edge_profile_summary,
    empty_edge_worker_mode_summary,
    normalize_device_class,
    normalize_edge_profile,
    normalize_edge_profile_type,
    normalize_edge_state,
)


GENERATED_AT = "2026-06-10T18:00:00+00:00"


def _profile(**overrides):
    data = {
        "profile_name": "Raspberry Pi fixture profile",
        "profile_type": "lightweight_collector",
        "device_class": "raspberry_pi",
        "cpu_budget_percent": 35.0,
        "memory_budget_mb": 512,
        "storage_budget_mb": 1024,
        "telemetry_budget_per_minute": 300,
        "source_modes": ["fixture"],
        "offline_supported": True,
        "degraded_supported": True,
    }
    data.update(overrides)
    return build_edge_profile(**data)


def _bus(queue_depth=3, max_queue_depth=10):
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
                tier_name="Hot edge tier",
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


def _scaling():
    return build_horizontal_scaling_summary(
        [
            build_worker_group(group_type="collector", worker_count=1, max_worker_count=3, source_modes=["fixture"], health_state="healthy"),
            build_worker_group(group_type="analysis", worker_count=1, max_worker_count=3, source_modes=["fixture"], health_state="healthy"),
        ],
        generated_at=GENERATED_AT,
        source_mode="fixture",
    )


def _optimization(state_pressure=False):
    return build_resource_optimization_summary(
        generated_at=GENERATED_AT,
        source_mode="fixture",
        cpu_used_percent=58 if state_pressure else 10,
    )


def test_edge_profile_creation_is_export_safe():
    profile = _profile().to_dict()

    assert profile["record_type"] == "edge_profile"
    assert profile["profile_type"] == "lightweight_collector"
    assert profile["device_class"] == "raspberry_pi"
    assert profile["cpu_budget_percent"] == 35.0
    assert profile["memory_budget_mb"] == 512
    assert profile["offline_supported"] is True
    assert profile["degraded_supported"] is True
    assert profile["preview_only"] is True
    assert profile["destructive_action"] is False
    assert profile["worker_deployed"] is False
    assert profile["telemetry_routing_modified"] is False


def test_profile_validation_normalizes_types_devices_and_bounds():
    assert normalize_edge_profile_type("gateway_collector") == "gateway_collector"
    assert normalize_edge_profile_type("bad") == "unknown"
    assert normalize_device_class("darwin") == "macos"
    assert normalize_device_class("rpi") == "raspberry_pi"
    assert normalize_device_class("bad") == "unknown"

    profile = _profile(
        profile_type="invalid",
        device_class="invalid",
        cpu_budget_percent=200,
        memory_budget_mb=-1,
        storage_budget_mb="bad",
        telemetry_budget_per_minute=-1,
    ).to_dict()

    assert profile["profile_type"] == "unknown"
    assert profile["device_class"] == "unknown"
    assert profile["cpu_budget_percent"] == 100.0
    assert profile["memory_budget_mb"] == 0
    assert profile["storage_budget_mb"] == 0
    assert profile["telemetry_budget_per_minute"] == 0


def test_raspberry_pi_profile_behavior():
    summary = build_edge_worker_mode_summary([_profile(device_class="raspberry_pi")], generated_at=GENERATED_AT).to_dict()

    assert summary["edge_profiles"][0]["device_class"] == "raspberry_pi"
    assert summary["offline_readiness"]["offline_ready"] is True
    assert summary["degraded_readiness"]["degraded_ready"] is True
    assert summary["edge_state"] == "offline_capable"


def test_linux_arm_profile_behavior():
    profile = _profile(profile_name="Linux ARM profile", device_class="linux_arm")
    summary = build_edge_worker_mode_summary([profile], generated_at=GENERATED_AT).to_dict()

    assert summary["edge_profiles"][0]["device_class"] == "linux_arm"
    assert summary["offline_readiness"]["offline_ready"] is True
    assert summary["edge_state"] == "offline_capable"


def test_gateway_profile_behavior():
    profile = _profile(profile_type="gateway_collector", device_class="linux")
    summary = build_edge_worker_mode_summary([profile], telemetry_bus_summaries=[_bus()], scaling_summaries=[_scaling()], generated_at=GENERATED_AT).to_dict()

    assert summary["gateway_readiness"]["gateway_ready"] is True
    assert summary["gateway_readiness"]["gateway_profile_count"] == 1
    assert summary["gateway_readiness"]["telemetry_routing_modified"] is False
    assert summary["edge_state"] == "edge_ready"


def test_branch_profile_behavior():
    profile = _profile(profile_type="branch_collector", device_class="linux")
    summary = build_edge_worker_mode_summary([profile], optimization_summaries=[_optimization()], scaling_summaries=[_scaling()], generated_at=GENERATED_AT).to_dict()

    assert summary["branch_readiness"]["branch_ready"] is True
    assert summary["branch_readiness"]["branch_profile_count"] == 1
    assert summary["branch_readiness"]["deployment_action_executed"] is False
    assert summary["edge_state"] == "edge_ready"


def test_offline_and_degraded_readiness():
    summary = build_edge_worker_mode_summary(
        [_profile(offline_supported=True, degraded_supported=True)],
        telemetry_bus_summaries=[_bus(queue_depth=5, max_queue_depth=10)],
        storage_summaries=[_storage(records=90, capacity=100)],
        optimization_summaries=[_optimization(state_pressure=True)],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["offline_readiness"]["offline_ready"] is True
    assert summary["offline_readiness"]["queue_depth"] == 5
    assert summary["degraded_readiness"]["degraded_ready"] is True
    assert summary["degraded_readiness"]["pressure_detected"] is True
    assert summary["degraded_readiness"]["collection_logic_changed"] is False


def test_upstream_summary_integration():
    summary = build_edge_worker_mode_summary(
        [_profile(profile_type="gateway_collector", device_class="linux")],
        telemetry_bus_summaries=[_bus(queue_depth=4, max_queue_depth=8)],
        storage_summaries=[_storage(records=30, capacity=100)],
        scaling_summaries=[_scaling()],
        optimization_summaries=[_optimization()],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["telemetry_bus_summary"]["queue_depth"] == 4
    assert summary["storage_summary"]["tier_count"] == 1
    assert summary["scaling_summary"]["cluster_size"] == 2
    assert summary["optimization_summary"]["summary_count"] == 1


def test_state_transitions_empty_degraded_and_ready():
    ready = build_edge_worker_mode_summary([_profile(profile_type="workstation_collector", device_class="macos", offline_supported=False)], generated_at=GENERATED_AT).to_dict()
    offline = build_edge_worker_mode_summary([_profile()], generated_at=GENERATED_AT).to_dict()
    degraded = build_edge_worker_mode_summary([object()], generated_at=GENERATED_AT).to_dict()
    empty = empty_edge_worker_mode_summary(generated_at=GENERATED_AT).to_dict()

    assert ready["edge_state"] == "ready"
    assert offline["edge_state"] == "offline_capable"
    assert degraded["edge_state"] == "degraded"
    assert empty["edge_state"] == "unavailable"


def test_malformed_input_handling_degrades_safely():
    profile = normalize_edge_profile(object()).to_dict()
    summary = build_edge_worker_mode_summary([object()], telemetry_bus_summaries=[object()], storage_summaries=[object()], generated_at=GENERATED_AT).to_dict()

    assert profile["profile_type"] == "unknown"
    assert profile["device_class"] == "unknown"
    assert summary["edge_state"] == "degraded"
    assert summary["edge_profiles"][0]["preview_only"] is True


def test_source_mode_preservation_and_profile_summary():
    profiles = [
        _profile(source_modes=["fixture", "replay"]),
        _profile(profile_type="branch_collector", device_class="linux", source_modes=["live"]),
    ]
    summary = edge_profile_summary(profiles)

    assert summary["source_modes"] == ["fixture", "live", "replay"]
    assert summary["type_counts"]["branch_collector"] == 1


def test_preview_and_destructive_flags_are_fixed():
    summary = build_edge_worker_mode_summary([_profile()], generated_at=GENERATED_AT).to_dict()

    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert all(row["preview_only"] is True for row in summary["edge_profiles"])
    assert all(row["destructive_action"] is False for row in summary["edge_profiles"])
    assert summary["worker_deployed"] is False
    assert summary["deployment_action_executed"] is False
    assert summary["runtime_behavior_modified"] is False


def test_export_safe_serialization_is_json_safe():
    profile = _profile()
    summary = build_edge_worker_mode_summary([profile], generated_at=GENERATED_AT)

    json.loads(deterministic_edge_profile_json(profile))
    json.loads(deterministic_edge_worker_mode_json(summary))
    json.dumps(summary.to_dict(), sort_keys=True)


def test_no_deployment_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    summary = build_edge_worker_mode_summary([_profile()], generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["worker_deployed"] is False
    assert summary["telemetry_collection_changed"] is False
    assert summary["telemetry_routing_modified"] is False
    assert summary["infrastructure_provisioned"] is False
    assert summary["relay_created"] is False


def test_cross_platform_compatibility():
    profiles = [
        *default_edge_profiles(source_mode="fixture"),
        _profile(profile_name="Windows profile", profile_type="workstation_collector", device_class="windows"),
        _profile(profile_name="macOS profile", profile_type="workstation_collector", device_class="macos"),
        _profile(profile_name="Linux profile", profile_type="enterprise_collector", device_class="linux"),
    ]
    summary = build_edge_worker_mode_summary(profiles, generated_at=GENERATED_AT).to_dict()

    devices = {row["device_class"] for row in summary["edge_profiles"]}
    assert {"raspberry_pi", "linux", "windows", "macos"}.issubset(devices)
    assert normalize_edge_state("edge ready") == "edge_ready"
