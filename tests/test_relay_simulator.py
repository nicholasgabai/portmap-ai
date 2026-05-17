import json
import re

from core_engine.diagnostics.relay_simulator import (
    build_relay_correlation_record,
    build_relay_dashboard_summary,
    build_relay_event,
    build_relay_finding,
    build_relay_storage_record,
    build_relay_timeline_entry,
    build_relay_topology_summary,
    run_relay_simulation_sync,
    summarize_relay_result,
)


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def test_relay_simulation_forwards_payloads_in_order():
    result = run_relay_simulation_sync([b"alpha", b"beta", "gamma"])

    assert result["ok"] is True
    assert result["classification"] == "completed"
    assert result["message_count"] == 3
    assert result["forwarded_bytes"] == len(b"alphabetagamma")
    assert [frame["frame_id"] for frame in result["frames"]] == [
        "relay-frame-0000",
        "relay-frame-0001",
        "relay-frame-0002",
    ]
    assert result["frames"][0]["hex_summary"] == b"alpha".hex()
    assert result["raw_payload_stored"] is False
    assert result["automatic_changes"] is False
    assert result["administrator_controlled"] is True


def test_relay_simulation_rejects_malformed_payload_iterable():
    result = run_relay_simulation_sync(123)

    assert result["ok"] is False
    assert result["classification"] == "unsupported"
    assert "iterable" in result["errors"][0]


def test_relay_simulation_rejects_unsupported_payload_type():
    result = run_relay_simulation_sync([b"valid", object()])

    assert result["ok"] is False
    assert result["classification"] == "unsupported"
    assert "bytes-like or string" in result["errors"][0]


def test_relay_simulation_enforces_message_limit():
    result = run_relay_simulation_sync([b"one", b"two", b"three"], max_messages=2)

    assert result["ok"] is False
    assert result["classification"] == "input_limited"
    assert result["message_count"] == 2
    assert result["summary"]["recommended_review"] is True
    assert "max_messages" in result["errors"][0]


def test_relay_simulation_enforces_payload_and_total_limits():
    payload_limited = run_relay_simulation_sync([b"abcdef"], max_payload_bytes=3)
    total_limited = run_relay_simulation_sync([b"abc", b"def"], max_total_bytes=4)

    assert payload_limited["classification"] == "input_limited"
    assert payload_limited["message_count"] == 0
    assert "max_payload_bytes" in payload_limited["errors"][0]
    assert total_limited["classification"] == "input_limited"
    assert total_limited["message_count"] == 1
    assert "max_total_bytes" in total_limited["errors"][0]


def test_relay_simulation_timeout_is_structured():
    result = run_relay_simulation_sync(
        [b"slow"],
        max_duration_seconds=0.001,
        per_message_delay_seconds=0.05,
    )

    assert result["ok"] is False
    assert result["classification"] == "timed_out"
    assert result["summary"]["severity"] == "high"
    assert result["integration_hooks"]["policy_review_ready"] is True


def test_relay_summary_and_operational_records():
    result = run_relay_simulation_sync([b"alpha"])

    summary = summarize_relay_result(result)
    event = build_relay_event(result)
    finding = build_relay_finding(result)
    storage = build_relay_storage_record(result)
    timeline = build_relay_timeline_entry(result)
    topology = build_relay_topology_summary(result)
    dashboard = build_relay_dashboard_summary(result)
    correlation = build_relay_correlation_record(result)

    assert summary["classification"] == "completed"
    assert event["event_type"] == "system_notice"
    assert event["metadata"]["diagnostic_type"] == "relay_orchestration"
    assert finding["category"] == "relay_orchestration"
    assert storage["payload"]["forwarded_message_count"] == 1
    assert timeline["category"] == "relay_orchestration"
    assert topology["node_count"] == 2
    assert topology["edges"][0]["relationship_type"] == "relay_forwarded"
    assert dashboard["panel"] == "relay_orchestration"
    assert correlation["score"] == 0.0
    assert all(row["raw_payload_stored"] is False for row in [event, finding, storage, timeline, dashboard, correlation])


def test_relay_error_record_becomes_policy_review_event():
    result = run_relay_simulation_sync([b"slow"], max_duration_seconds=0.001, per_message_delay_seconds=0.05)
    event = build_relay_event(result)
    finding = build_relay_finding(result)
    correlation = build_relay_correlation_record(result)

    assert event["event_type"] == "policy_review_required"
    assert finding["recommended_review"] is True
    assert correlation["score"] > 0


def test_relay_outputs_do_not_contain_private_identifiers():
    result = run_relay_simulation_sync([b"sample-frame"], session_label="sample-relay")
    records = [
        result,
        build_relay_event(result),
        build_relay_storage_record(result),
        build_relay_topology_summary(result),
        build_relay_dashboard_summary(result),
    ]
    payload = json.dumps(records, sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
