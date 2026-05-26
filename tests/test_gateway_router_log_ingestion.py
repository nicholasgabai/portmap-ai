import re

from core_engine.gateway import (
    deterministic_gateway_log_json,
    gateway_log_to_runtime_event,
    gateway_log_to_topology_edge,
    malformed_gateway_log_record,
    normalize_gateway_log_record,
    parse_gateway_log_line,
    parse_gateway_log_lines,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _lines():
    return [
        '2026-01-01T00:00:01+00:00 gateway-placeholder action=allow proto=tcp src=203.0.113.10 spt=53000 dst=198.51.100.20 dpt=443',
        '2026-01-01T00:00:02+00:00 gateway-placeholder action=deny proto=udp src=203.0.113.11 spt=53001 dst=198.51.100.53 dpt=53',
        '2026-01-01T00:00:03+00:00 gateway-placeholder action=allow proto=tcp src=203.0.113.12 spt=53002 dst=198.51.100.30 dpt=80 nat=true nat_src=198.51.100.200 nat_spt=40000',
        "not a parseable gateway log line",
    ]


def test_syslog_style_fixture_parsing_builds_gateway_records():
    report = parse_gateway_log_lines(_lines(), generated_at=GENERATED_AT)

    assert report["record_type"] == "gateway_log_ingestion_report"
    assert report["summary"]["record_count"] == 4
    assert report["summary"]["allow_count"] == 2
    assert report["summary"]["deny_count"] == 1
    assert report["summary"]["nat_event_count"] == 1
    assert report["summary"]["malformed_count"] == 1
    assert report["summary"]["by_action"] == {"allow": 2, "deny": 1, "unknown": 1}
    assert report["summary"]["by_category"]["nat"] == 1
    assert report["dashboard_status"]["status"] == "review_required"
    assert report["api_status"]["summary"]["topology_edge_count"] == 3
    assert report["export_summary"]["export_ready"] is True
    assert report["external_listener_started"] is False
    assert report["router_settings_modified"] is False
    assert report["raw_payload_stored"] is False


def test_normalized_gateway_log_has_runtime_event_and_topology_edge_hooks():
    record = normalize_gateway_log_record(
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "action": "drop",
            "event_type": "traffic",
            "protocol": "tcp",
            "source_ip": "203.0.113.10",
            "source_port": 53000,
            "destination_ip": "198.51.100.20",
            "destination_port": 443,
        },
        generated_at=GENERATED_AT,
    )

    assert record["action"] == "deny"
    assert record["severity"] == "medium"
    assert record["source"]["endpoint_ref"].startswith("endpoint-")
    assert record["destination"]["port"] == 443
    assert record["runtime_event"]["event_type"] == "system_notice"
    assert record["runtime_event"]["severity"] == "medium"
    assert record["topology_edge"]["relationship_type"] == "gateway_observed"
    assert record["topology_edge"]["source_asset"] == "203.0.113.10"
    assert record["automatic_blocking"] is False


def test_nat_event_summary_includes_translated_endpoint_metadata():
    record = parse_gateway_log_line(
        'Jan 01 00:00:03 gateway-placeholder action=allow proto=tcp src=203.0.113.12 spt=53002 dst=198.51.100.30 dpt=80 nat=true nat_src=198.51.100.200 nat_spt=40000',
        generated_at=GENERATED_AT,
    )

    assert record["event_category"] == "nat"
    assert record["nat_event"] is True
    assert record["translated_source"]["ip"] == "198.51.100.200"
    assert record["translated_source"]["port"] == 40000
    assert record["timestamp"].startswith("2026-01-01T00:00:03")


def test_malformed_log_handling_is_safe_and_exportable():
    record = malformed_gateway_log_record(line_ref="line:9", reason="missing fields", generated_at=GENERATED_AT)
    event = gateway_log_to_runtime_event(record)
    edge = gateway_log_to_topology_edge(record)

    assert record["malformed"] is True
    assert record["severity"] == "low"
    assert "missing fields" in record["parse_warnings"]
    assert event["event_type"] == "system_notice"
    assert edge is None
    assert record["raw_payload_stored"] is False


def test_router_log_parser_reports_missing_fields_as_warnings():
    record = parse_gateway_log_line(
        "2026-01-01T00:00:01+00:00 gateway-placeholder action=allow proto=tcp src=203.0.113.10",
        generated_at=GENERATED_AT,
    )

    assert "missing_destination_ip" in record["parse_warnings"]
    assert record["malformed"] is False
    assert record["topology_edge"] is None


def test_gateway_log_serialization_is_deterministic_and_private_safe():
    report = parse_gateway_log_lines(_lines(), generated_at=GENERATED_AT)
    report_json = deterministic_gateway_log_json(report)

    assert report_json == deterministic_gateway_log_json(report)
    assert '"payload_bytes_stored":0' in report_json
    assert "not a parseable gateway log line" not in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)
