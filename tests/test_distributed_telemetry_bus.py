from __future__ import annotations

import json

from core_engine.scaling import (
    build_bus_envelope,
    build_telemetry_bus_summary,
    deterministic_bus_json,
    deterministic_envelope_json,
    empty_telemetry_bus_summary,
    envelope_from_summary,
    normalize_delivery_state,
    normalize_envelope,
    normalize_priority,
    normalize_topic,
    sanitize_payload_summary,
)


GENERATED_AT = "2026-06-09T12:00:00+00:00"


def _envelope(**overrides):
    data = {
        "topic": "worker_telemetry",
        "message_type": "runtime_summary",
        "source_node": "worker-alpha",
        "target_scope": "local-cluster",
        "source_mode": "fixture",
        "created_at": GENERATED_AT,
        "priority": "high",
        "retry_count": 1,
        "max_retries": 4,
        "backoff_seconds": 2.5,
        "payload": {"status": "ok", "count": 3},
        "payload_reference": "runtime-summary-001",
        "delivery_state": "retry_pending",
    }
    data.update(overrides)
    return build_bus_envelope(**data)


def test_envelope_generation_is_export_safe():
    envelope = _envelope()
    payload = envelope.to_dict()

    assert payload["record_type"] == "telemetry_bus_envelope"
    assert payload["topic"] == "worker_telemetry"
    assert payload["message_type"] == "runtime_summary"
    assert payload["source_mode"] == "fixture"
    assert payload["priority"] == "high"
    assert payload["retry_count"] == 1
    assert payload["max_retries"] == 4
    assert payload["backoff_seconds"] == 2.5
    assert payload["payload_reference"] == "runtime-summary-001"
    assert payload["delivery_state"] == "retry_pending"
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["raw_payload_stored"] is False
    assert payload["external_broker_required"] is False
    assert payload["network_forwarded"] is False


def test_topic_and_delivery_state_validation():
    assert normalize_topic("flow_summary") == "flow_summary"
    assert normalize_topic("not-a-topic") == "unknown"
    assert normalize_delivery_state("queued") == "queued"
    assert normalize_delivery_state("sent") == "unknown"
    assert normalize_priority("medium") == "normal"
    assert normalize_priority("urgent") == "unknown"


def test_payload_summary_sanitization_redacts_private_identifiers_and_raw_payloads():
    summary = sanitize_payload_summary(
        {
            "source": "operator@example.invalid",
            "raw_payload": "secret-body",
            "hostname": "internal-node",
            "fields": ["safe", "node@example.invalid"],
        }
    )

    assert summary["source"].startswith("redacted-")
    assert summary["raw_payload"].startswith("redacted-")
    assert summary["hostname"] == "internal-node"
    assert summary["fields"][1].startswith("redacted-")
    assert summary["raw_payload_stored"] is False


def test_retry_backoff_fields_are_bounded():
    payload = _envelope(retry_count=-1, max_retries=-2, backoff_seconds=-5).to_dict()

    assert payload["retry_count"] == 0
    assert payload["max_retries"] == 0
    assert payload["backoff_seconds"] == 0.0


def test_bounded_queue_behavior_adds_dropped_by_bound_record():
    envelopes = [
        _envelope(topic="worker_telemetry", payload_reference="env-1", priority="high"),
        _envelope(topic="flow_summary", payload_reference="env-2", priority="normal", delivery_state="queued"),
        _envelope(topic="runtime_health", payload_reference="env-3", priority="low", delivery_state="queued"),
    ]

    summary = build_telemetry_bus_summary(envelopes, max_queue_depth=2, generated_at=GENERATED_AT).to_dict()

    assert summary["bus_state"] == "bounded"
    assert summary["queue_depth"] == 3
    assert summary["max_queue_depth"] == 2
    assert summary["dropped_count"] == 1
    assert summary["delivery_state_counts"]["dropped_by_bound"] == 1
    assert any(row["delivery_state"] == "dropped_by_bound" for row in summary["envelopes"])


def test_topic_priority_and_state_counts():
    summary = build_telemetry_bus_summary(
        [
            _envelope(topic="worker_telemetry", priority="high", delivery_state="queued", retry_count=0),
            _envelope(topic="flow_summary", priority="normal", delivery_state="retry_pending"),
            _envelope(topic="flow_summary", priority="normal", delivery_state="delivered_preview"),
        ],
        max_queue_depth=10,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["topic_counts"] == {"flow_summary": 2, "worker_telemetry": 1}
    assert summary["priority_counts"] == {"high": 1, "normal": 2}
    assert summary["delivery_state_counts"] == {"delivered_preview": 1, "queued": 1, "retry_pending": 1}
    assert summary["retry_pending_count"] == 1
    assert summary["bus_state"] == "degraded"


def test_fanout_readiness_is_preview_only():
    ready = build_telemetry_bus_summary([_envelope(delivery_state="queued")], fanout_targets=["group-a"], generated_at=GENERATED_AT).to_dict()
    not_ready = build_telemetry_bus_summary([_envelope(delivery_state="invalid")], fanout_targets=["group-a"], generated_at=GENERATED_AT).to_dict()

    assert ready["fanout_ready"] is True
    assert ready["external_broker_required"] is False
    assert ready["live_forwarding_enabled"] is False
    assert not_ready["fanout_ready"] is False


def test_empty_and_unavailable_bus_states():
    empty = empty_telemetry_bus_summary(generated_at=GENERATED_AT).to_dict()
    unavailable = build_telemetry_bus_summary([], max_queue_depth=0, generated_at=GENERATED_AT).to_dict()

    assert empty["bus_state"] == "empty"
    assert empty["queue_depth"] == 0
    assert unavailable["bus_state"] == "unavailable"


def test_source_mode_preservation_and_summary_envelope_conversion():
    envelope = envelope_from_summary(
        {
            "record_type": "visualization_summary",
            "summary_id": "summary-001",
            "source_mode": "live",
            "generated_at": GENERATED_AT,
            "count": 2,
        },
        topic="visualization_summary",
    ).to_dict()

    assert envelope["topic"] == "visualization_summary"
    assert envelope["source_mode"] == "live"
    assert envelope["payload_reference"] == "summary-001"


def test_preview_and_destructive_flags_are_fixed():
    summary = build_telemetry_bus_summary([_envelope()], generated_at=GENERATED_AT).to_dict()

    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert all(row["preview_only"] is True for row in summary["envelopes"])
    assert all(row["destructive_action"] is False for row in summary["envelopes"])


def test_export_safe_serialization_is_json_safe():
    envelope = _envelope()
    summary = build_telemetry_bus_summary([envelope], generated_at=GENERATED_AT)

    json.loads(deterministic_envelope_json(envelope))
    json.loads(deterministic_bus_json(summary))
    json.dumps(summary.to_dict(), sort_keys=True)


def test_malformed_input_handling_creates_invalid_envelope():
    envelope = normalize_envelope(object(), generated_at=GENERATED_AT).to_dict()
    summary = build_telemetry_bus_summary([object()], generated_at=GENERATED_AT).to_dict()

    assert envelope["delivery_state"] == "invalid"
    assert summary["bus_state"] == "degraded"
    assert summary["delivery_state_counts"]["invalid"] == 1


def test_no_external_broker_or_network_behavior_fields():
    summary = build_telemetry_bus_summary([_envelope()], generated_at=GENERATED_AT).to_dict()

    assert summary["external_broker_required"] is False
    assert summary["network_forwarded"] is False
    assert summary["filesystem_written"] is False
    assert summary["live_forwarding_enabled"] is False


def test_cross_platform_safe_record_shape():
    summary = build_telemetry_bus_summary(
        [
            _envelope(source_node="windows-worker", source_mode="fixture"),
            _envelope(source_node="macos-worker", topic="runtime_health", source_mode="fixture"),
            _envelope(source_node="linux-arm-worker", topic="topology_update", source_mode="fixture"),
        ],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert summary["queue_depth"] == 3
    assert summary["topic_counts"]["runtime_health"] == 1
    assert summary["topic_counts"]["topology_update"] == 1
    assert summary["topic_counts"]["worker_telemetry"] == 1
