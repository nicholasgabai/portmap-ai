import re

from core_engine.telemetry import (
    build_dns_query_record,
    build_dns_visibility_report,
    build_packet_ingestion_window,
    deterministic_dns_correlation_json,
    deterministic_dns_visibility_json,
    enrich_flow_records,
    reconstruct_flows_from_packet_window,
    sanitize_domain_name,
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


def _flows():
    packets = [
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "interface_name": "en0",
            "source_node_id": "node-alpha",
            "source_ip": "203.0.113.10",
            "destination_ip": "203.0.113.53",
            "source_port": 53000,
            "destination_port": 53,
            "transport": "udp",
            "size_bytes": 80,
            "packet_sequence": 1,
        },
        {
            "timestamp": "2026-01-01T00:00:02+00:00",
            "interface_name": "en0",
            "source_node_id": "node-alpha",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.20",
            "source_port": 53001,
            "destination_port": 443,
            "transport": "tcp",
            "size_bytes": 160,
            "packet_sequence": 2,
        },
        {
            "timestamp": "2026-01-01T00:00:03+00:00",
            "interface_name": "en0",
            "source_node_id": "node-alpha",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.53",
            "source_port": 53002,
            "destination_port": 853,
            "transport": "tcp",
            "size_bytes": 200,
            "packet_sequence": 3,
        },
    ]
    window = build_packet_ingestion_window(packets=packets, duration_seconds=3, generated_at=GENERATED_AT)
    flows = reconstruct_flows_from_packet_window(window, generated_at=GENERATED_AT)["flows"]
    return enrich_flow_records(flows, local_cidrs=["203.0.113.0/24"], generated_at=GENERATED_AT)["observations"]


def _queries():
    return [
        {
            "query_id": "q-1",
            "query_name": "service.example.test",
            "query_type": "A",
            "timestamp": "2026-01-01T00:00:01+00:00",
            "resolver_ip": "203.0.113.53",
            "transport_protocol": "udp",
            "source_refs": ["fixture:dns-query-1"],
        },
        {
            "query_id": "q-2",
            "query_name": "missing.example.test",
            "query_type": "AAAA",
            "timestamp": "2026-01-01T00:00:04+00:00",
            "resolver_ip": "203.0.113.53",
            "transport_protocol": "udp",
        },
    ]


def _responses():
    return [
        {
            "query_id": "q-1",
            "query_name": "service.example.test",
            "query_type": "A",
            "timestamp": "2026-01-01T00:00:01.120000+00:00",
            "resolver_ip": "203.0.113.53",
            "response_code": "NOERROR",
            "answers": [{"answer_type": "A", "value": "198.51.100.20", "ttl": 120}],
        },
        {
            "query_id": "q-2",
            "query_name": "missing.example.test",
            "query_type": "AAAA",
            "timestamp": "2026-01-01T00:00:04.040000+00:00",
            "resolver_ip": "203.0.113.53",
            "response_code": "NXDOMAIN",
            "answers": [],
        },
    ]


def test_dns_visibility_builds_query_response_records_and_summaries():
    report = build_dns_visibility_report(
        queries=_queries(),
        responses=_responses(),
        enriched_flows=_flows(),
        generated_at=GENERATED_AT,
    )

    assert report["record_type"] == "dns_visibility_report"
    assert report["summary"]["query_count"] == 2
    assert report["summary"]["response_count"] == 2
    assert report["summary"]["correlated_flow_count"] == 1
    assert report["summary"]["nxdomain_count"] == 1
    assert report["summary"]["error_response_count"] == 1
    assert report["summary"]["by_query_type"] == {"A": 1, "AAAA": 1}
    matched = next(row for row in report["domain_flow_correlations"] if row["status"] == "matched")
    assert matched["query_name"] == "service.example.test"
    assert matched["matched_flow_refs"]
    assert report["timing_summaries"][0]["response_time_ms"] == 120
    assert report["resolver_summaries"][0]["resolver_type"] == "local"
    assert any(hint["hint_type"] == "dns_response_error" for hint in report["anomaly_hints"])
    assert report["dashboard_status"]["status"] == "review_required"
    assert report["api_status"]["summary"]["nxdomain_count"] == 1
    assert report["raw_payload_stored"] is False
    assert report["credentials_retained"] is False


def test_dns_domain_sanitization_truncates_and_redacts_safely():
    name, governance = sanitize_domain_name("very_long_label_with_symbols_!@#.example.test", max_length=24)

    assert name.endswith("...")
    assert "!" not in name
    assert governance["truncated"] is True
    assert governance["redacted"] is True
    assert governance["raw_domain_stored"] is False


def test_dns_query_record_uses_safe_domain_output():
    query = build_dns_query_record(
        {"query_name": "Service.Example.Test.", "query_type": "A", "timestamp": "2026-01-01T00:00:01+00:00"},
        generated_at=GENERATED_AT,
    )

    assert query["query_name"] == "service.example.test"
    assert query["query_type"] == "A"
    assert query["domain_governance"]["safe_domain_output"] is True
    assert query["traffic_interception"] is False
    assert query["dns_settings_modified"] is False


def test_encrypted_dns_limitations_are_visible():
    report = build_dns_visibility_report(
        queries=[],
        responses=[],
        enriched_flows=_flows(),
        generated_at=GENERATED_AT,
    )

    assert report["encrypted_dns_limitations"]["visibility_limited"] is True
    assert report["encrypted_dns_limitations"]["decryption_performed"] is False
    assert report["summary"]["encrypted_dns_visibility_limited"] is True


def test_unpaired_dns_query_generates_missing_response_hint():
    report = build_dns_visibility_report(
        queries=[_queries()[0]],
        responses=[],
        enriched_flows=[],
        generated_at=GENERATED_AT,
    )

    assert report["pairings"][0]["status"] == "query_only"
    assert report["timing_summaries"][0]["response_observed"] is False
    assert any(hint["hint_type"] == "dns_response_missing" for hint in report["anomaly_hints"])


def test_dns_visibility_serialization_is_deterministic_and_private_safe():
    report = build_dns_visibility_report(
        queries=_queries(),
        responses=_responses(),
        enriched_flows=_flows(),
        generated_at=GENERATED_AT,
    )
    visibility_json = deterministic_dns_visibility_json(report)
    correlation_json = deterministic_dns_correlation_json(report["domain_flow_correlations"][0])

    assert visibility_json == deterministic_dns_visibility_json(report)
    assert correlation_json == deterministic_dns_correlation_json(report["domain_flow_correlations"][0])
    assert "payload_bytes_stored\":0" in visibility_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(visibility_json)
        assert not pattern.search(correlation_json)
