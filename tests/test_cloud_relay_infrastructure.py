from __future__ import annotations

import json

from core_engine.scaling import (
    build_bus_envelope,
    build_cloud_relay_readiness_summary,
    build_edge_profile,
    build_edge_worker_mode_summary,
    build_horizontal_scaling_summary,
    build_relay_session,
    build_resource_optimization_summary,
    build_retention_tier,
    build_storage_engine_summary,
    build_telemetry_bus_summary,
    build_worker_group,
    default_relay_sessions,
    deterministic_cloud_relay_json,
    deterministic_relay_session_json,
    empty_cloud_relay_readiness_summary,
    normalize_relay_readiness_state,
    normalize_relay_session,
    normalize_relay_session_state,
    normalize_relay_type,
    relay_session_summary,
)


GENERATED_AT = "2026-06-10T20:00:00+00:00"


def _session(**overrides):
    data = {
        "relay_name": "Local relay fixture",
        "relay_type": "local_preview",
        "tenant_scope": "single_tenant_preview",
        "routing_scope": "local_cluster_preview",
        "estimated_nodes": 4,
        "estimated_topics": 6,
        "source_modes": ["fixture"],
        "relay_state": "ready",
    }
    data.update(overrides)
    return build_relay_session(**data)


def _bus(queue_depth=5, max_queue_depth=20):
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
                tier_name="Relay storage tier",
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


def _optimization(pressure=False):
    return build_resource_optimization_summary(generated_at=GENERATED_AT, source_mode="fixture", cpu_used_percent=58 if pressure else 10)


def _edge():
    return build_edge_worker_mode_summary(
        [build_edge_profile(profile_type="gateway_collector", device_class="linux", offline_supported=True, degraded_supported=True, source_modes=["fixture"])],
        generated_at=GENERATED_AT,
        source_mode="fixture",
    )


def test_relay_session_creation_is_export_safe():
    session = _session().to_dict()

    assert session["record_type"] == "relay_session"
    assert session["relay_type"] == "local_preview"
    assert session["tenant_scope"] == "single_tenant_preview"
    assert session["routing_scope"] == "local_cluster_preview"
    assert session["estimated_nodes"] == 4
    assert session["estimated_topics"] == 6
    assert session["source_modes"] == ["fixture"]
    assert session["relay_state"] == "ready"
    assert session["preview_only"] is True
    assert session["destructive_action"] is False
    assert session["network_connection_opened"] is False
    assert session["telemetry_forwarded"] is False
    assert session["cloud_resource_created"] is False


def test_session_validation_normalizes_types_states_and_bounds():
    assert normalize_relay_type("regional_preview") == "regional_preview"
    assert normalize_relay_type("cloud") == "unknown"
    assert normalize_relay_session_state("degraded") == "degraded"
    assert normalize_relay_session_state("active") == "unknown"

    session = _session(relay_type="invalid", relay_state="bad", estimated_nodes=-5, estimated_topics=200_000).to_dict()

    assert session["relay_type"] == "unknown"
    assert session["relay_state"] == "unknown"
    assert session["estimated_nodes"] == 0
    assert session["estimated_topics"] == 100_000


def test_relay_readiness_generation_with_defaults():
    summary = build_cloud_relay_readiness_summary(generated_at=GENERATED_AT, source_mode="fixture").to_dict()

    assert summary["record_type"] == "cloud_relay_readiness_summary"
    assert summary["relay_readiness_state"] == "ready"
    assert summary["relay_sessions"][0]["relay_type"] == "local_preview"
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert summary["cloud_resource_created"] is False
    assert summary["network_connection_opened"] is False
    assert summary["saas_control_plane_enabled"] is False


def test_routing_preview_generation():
    summary = build_cloud_relay_readiness_summary(
        [_session(routing_scope="regional_preview"), _session(relay_name="Enterprise relay", relay_type="enterprise_preview", routing_scope="enterprise_preview")],
        telemetry_bus_summaries=[_bus(queue_depth=3)],
        edge_summaries=[_edge()],
        generated_at=GENERATED_AT,
    ).to_dict()

    routing = summary["routing_preview"]
    assert routing["routing_scope_count"] == 2
    assert routing["topic_count"] == 1
    assert routing["gateway_ready_count"] == 1
    assert routing["network_connection_opened"] is False
    assert routing["telemetry_forwarded"] is False


def test_tenant_isolation_preview_generation():
    summary = build_cloud_relay_readiness_summary(
        [_session(tenant_scope="tenant_a_preview"), _session(relay_type="hybrid_preview", tenant_scope="tenant_b_preview")],
        generated_at=GENERATED_AT,
    ).to_dict()

    tenant = summary["tenant_isolation_preview"]
    assert tenant["tenant_scope_count"] == 2
    assert tenant["enterprise_scope_preview"] is True
    assert tenant["tenant_isolation_ready"] is True
    assert tenant["saas_control_plane_enabled"] is False
    assert tenant["private_identifier_exported"] is False


def test_capacity_preview_generation():
    summary = build_cloud_relay_readiness_summary(
        [_session(estimated_nodes=2, estimated_topics=1)],
        telemetry_bus_summaries=[_bus(queue_depth=95, max_queue_depth=100)],
        storage_summaries=[_storage(records=90, capacity=100)],
        generated_at=GENERATED_AT,
    ).to_dict()

    capacity = summary["capacity_preview"]
    assert capacity["estimated_nodes"] == 2
    assert capacity["estimated_topics"] == 1
    assert capacity["capacity_constrained"] is True
    assert capacity["cloud_resource_created"] is False
    assert summary["relay_readiness_state"] == "capacity_constrained"


def test_upstream_summary_integration():
    summary = build_cloud_relay_readiness_summary(
        [_session(relay_type="regional_preview")],
        telemetry_bus_summaries=[_bus(queue_depth=4, max_queue_depth=10)],
        storage_summaries=[_storage(records=20, capacity=100)],
        scaling_summaries=[_scaling()],
        optimization_summaries=[_optimization()],
        edge_summaries=[_edge()],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["telemetry_bus_summary"]["queue_depth"] == 4
    assert summary["storage_summary"]["tier_count"] == 1
    assert summary["scaling_summary"]["cluster_size"] == 2
    assert summary["optimization_summary"]["summary_count"] == 1
    assert summary["edge_summary"]["gateway_ready_count"] == 1
    assert summary["relay_readiness_state"] == "relay_ready"


def test_state_transitions_and_empty_degraded_behavior():
    ready = build_cloud_relay_readiness_summary([_session()], generated_at=GENERATED_AT).to_dict()
    relay_ready = build_cloud_relay_readiness_summary([_session(relay_type="enterprise_preview")], generated_at=GENERATED_AT).to_dict()
    degraded = build_cloud_relay_readiness_summary([_session(relay_state="degraded")], generated_at=GENERATED_AT).to_dict()
    malformed = build_cloud_relay_readiness_summary([object()], telemetry_bus_summaries=[object()], generated_at=GENERATED_AT).to_dict()
    empty = empty_cloud_relay_readiness_summary(generated_at=GENERATED_AT).to_dict()

    assert ready["relay_readiness_state"] == "ready"
    assert relay_ready["relay_readiness_state"] == "relay_ready"
    assert degraded["relay_readiness_state"] == "degraded"
    assert malformed["relay_readiness_state"] == "degraded"
    assert empty["relay_readiness_state"] == "unavailable"


def test_malformed_input_handling_is_safe():
    session = normalize_relay_session(object()).to_dict()
    summary = relay_session_summary([object()])

    assert session["relay_type"] == "unknown"
    assert session["relay_state"] == "unknown"
    assert session["preview_only"] is True
    assert summary["session_count"] == 1
    assert summary["state_counts"]["unknown"] == 1


def test_source_mode_preservation():
    summary = build_cloud_relay_readiness_summary(
        [_session(source_modes=["fixture", "replay"]), _session(relay_type="regional_preview", source_modes=["live"])],
        generated_at=GENERATED_AT,
    ).to_dict()

    modes = {mode for row in summary["relay_sessions"] for mode in row["source_modes"]}
    assert modes == {"fixture", "live", "replay"}


def test_preview_and_destructive_flags_are_fixed():
    summary = build_cloud_relay_readiness_summary([_session()], generated_at=GENERATED_AT).to_dict()

    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert all(row["preview_only"] is True for row in summary["relay_sessions"])
    assert all(row["destructive_action"] is False for row in summary["relay_sessions"])
    assert summary["telemetry_forwarded"] is False
    assert summary["provisioning_executed"] is False
    assert summary["runtime_behavior_modified"] is False


def test_export_safe_serialization_is_json_safe():
    session = _session()
    summary = build_cloud_relay_readiness_summary([session], generated_at=GENERATED_AT)

    json.loads(deterministic_relay_session_json(session))
    json.loads(deterministic_cloud_relay_json(summary))
    json.dumps(summary.to_dict(), sort_keys=True)


def test_no_networking_or_cloud_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    summary = build_cloud_relay_readiness_summary([_session()], generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["network_connection_opened"] is False
    assert summary["telemetry_forwarded"] is False
    assert summary["cloud_resource_created"] is False
    assert summary["relay_infrastructure_created"] is False
    assert summary["saas_control_plane_enabled"] is False


def test_cross_platform_compatibility():
    summary = build_cloud_relay_readiness_summary(
        [
            *default_relay_sessions(source_mode="fixture"),
            _session(relay_name="Windows preview", relay_type="local_preview"),
            _session(relay_name="macOS preview", relay_type="regional_preview"),
            _session(relay_name="Linux ARM preview", relay_type="hybrid_preview"),
        ],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert len(summary["relay_sessions"]) == 4
    assert summary["tenant_isolation_preview"]["tenant_isolation_ready"] is True
    assert normalize_relay_readiness_state("relay ready") == "relay_ready"
