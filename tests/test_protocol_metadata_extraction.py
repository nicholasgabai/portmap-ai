import re

from core_engine.telemetry import (
    build_packet_ingestion_window,
    deterministic_protocol_fingerprint_json,
    deterministic_protocol_metadata_json,
    extract_protocol_metadata,
    extract_protocol_metadata_report,
    reconstruct_flows_from_packet_window,
    safe_truncate_metadata_value,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


GENERATED_AT = "2026-01-01T00:00:00+00:00"


def _flows():
    packets = [
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "interface_name": "en0",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.20",
            "source_port": 53000,
            "destination_port": 80,
            "transport": "tcp",
            "size_bytes": 120,
            "packet_sequence": 1,
        },
        {
            "timestamp": "2026-01-01T00:00:02+00:00",
            "interface_name": "en0",
            "source_ip": "198.51.100.20",
            "destination_ip": "203.0.113.10",
            "source_port": 80,
            "destination_port": 53000,
            "transport": "tcp",
            "size_bytes": 160,
            "packet_sequence": 2,
        },
        {
            "timestamp": "2026-01-01T00:00:03+00:00",
            "interface_name": "en0",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.30",
            "source_port": 53001,
            "destination_port": 443,
            "transport": "tcp",
            "size_bytes": 200,
            "packet_sequence": 3,
        },
        {
            "timestamp": "2026-01-01T00:00:04+00:00",
            "interface_name": "en0",
            "source_ip": "198.51.100.30",
            "destination_ip": "203.0.113.10",
            "source_port": 443,
            "destination_port": 53001,
            "transport": "tcp",
            "size_bytes": 220,
            "packet_sequence": 4,
        },
        {
            "timestamp": "2026-01-01T00:00:05+00:00",
            "interface_name": "en0",
            "source_ip": "203.0.113.10",
            "destination_ip": "203.0.113.53",
            "source_port": 53002,
            "destination_port": 53,
            "transport": "udp",
            "size_bytes": 80,
            "packet_sequence": 5,
        },
    ]
    window = build_packet_ingestion_window(packets=packets, duration_seconds=5, generated_at=GENERATED_AT)
    return reconstruct_flows_from_packet_window(window, generated_at=GENERATED_AT)["flows"]


def _flow_by_service(service_name):
    return next(flow for flow in _flows() if flow["service_association"]["service_name"] == service_name)


def test_http_metadata_summary_removes_sensitive_fields_and_strips_query():
    flow = _flow_by_service("http")
    record = extract_protocol_metadata(
        flow=flow,
        metadata={
            "http": {
                "method": "GET",
                "host": "example.test",
                "path": "/login?session=sample",
                "header_names": ["Host", "Authorization"],
                "authorization": "Bearer sample-value",
                "content": "sample body text",
            }
        },
        generated_at=GENERATED_AT,
    )

    http = record["http_metadata"]
    assert record["protocol"] == "http"
    assert http["status"] == "ok"
    assert http["fields"]["method"] == "GET"
    assert http["fields"]["path"] == "/login"
    assert http["fields"]["header_names"] == ["authorization", "host"]
    assert "authorization" not in http["fields"]
    assert "content" not in http["fields"]
    assert http["governance"]["removed_sensitive_field_count"] == 2
    assert record["protocol_fingerprint"]["confidence"] >= 0.9
    assert record["credentials_retained"] is False
    assert record["payload_contents_retained"] is False
    assert record["automatic_blocking"] is False


def test_tls_metadata_summary_keeps_encrypted_session_metadata_without_decryption():
    flow = _flow_by_service("https")
    record = extract_protocol_metadata(
        flow=flow,
        metadata={
            "tls": {
                "tls_version": "TLS 1.3",
                "sni": "sample-service-with-a-long-name.example.test",
                "alpn": "h2",
                "cipher_family": "aes-gcm",
                "certificate_issuer": "Example Issuer",
            }
        },
        generated_at=GENERATED_AT,
        max_field_length=16,
    )
    tls = record["tls_metadata"]

    assert record["protocol"] == "tls"
    assert tls["fields"]["encrypted_session"] is True
    assert tls["fields"]["decryption_performed"] is False
    assert tls["fields"]["sni"].endswith("...")
    assert tls["governance"]["truncated_field_count"] == 1
    assert record["protocol_anomalies"][0]["anomaly_type"] == "metadata_truncated"
    assert record["decryption_performed"] is False


def test_dns_metadata_and_report_summaries_are_dashboard_api_ready():
    flows = _flows()
    dns_flow = next(flow for flow in flows if flow["service_association"]["service_name"] == "dns")
    metadata_by_flow_id = {
        dns_flow["flow_id"]: {
            "dns": {
                "query_name": "example.test",
                "query_type": "A",
                "response_code": "NOERROR",
                "answer_count": 1,
            }
        }
    }

    report = extract_protocol_metadata_report(flows=flows, metadata_by_flow_id=metadata_by_flow_id, generated_at=GENERATED_AT)

    assert report["record_type"] == "protocol_metadata_report"
    assert report["summary"]["record_count"] == 3
    assert report["summary"]["by_protocol"] == {"dns": 1, "http": 1, "tls": 1}
    assert report["service_fingerprint_summary"]["fingerprint_count"] == 3
    assert report["dashboard_status"]["metrics"]["record_count"] == 3
    assert report["api_status"]["count"] == 3
    assert report["raw_payload_stored"] is False


def test_protocol_mismatch_generates_anomaly_without_action():
    flow = _flow_by_service("https")
    record = extract_protocol_metadata(
        flow=flow,
        metadata={"protocol": "http", "method": "GET", "host": "example.test", "path": "/"},
        generated_at=GENERATED_AT,
    )

    assert record["protocol"] == "http"
    assert any(item["anomaly_type"] == "protocol_service_mismatch" for item in record["protocol_anomalies"])
    assert all(item["automatic_blocking"] is False for item in record["protocol_anomalies"])
    assert all(item["traffic_injected"] is False for item in record["protocol_anomalies"])


def test_protocol_serialization_is_deterministic_and_private_safe():
    flow = _flow_by_service("http")
    record = extract_protocol_metadata(
        flow=flow,
        metadata={"http": {"method": "GET", "host": "example.test", "path": "/safe?sample=value"}},
        generated_at=GENERATED_AT,
    )
    metadata_json = deterministic_protocol_metadata_json(record)
    fingerprint_json = deterministic_protocol_fingerprint_json(record["protocol_fingerprint"])

    assert safe_truncate_metadata_value("abcdef", max_length=3) == ("abc...", True)
    assert metadata_json == deterministic_protocol_metadata_json(record)
    assert fingerprint_json == deterministic_protocol_fingerprint_json(record["protocol_fingerprint"])
    assert "sample=value" not in metadata_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(metadata_json)
        assert not pattern.search(fingerprint_json)
