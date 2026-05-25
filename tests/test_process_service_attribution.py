import re

from core_engine.telemetry import (
    build_packet_ingestion_window,
    build_process_service_attribution_report,
    build_process_socket_inventory,
    deterministic_process_attribution_json,
    deterministic_service_attribution_json,
    enrich_flow_records,
    minimize_process_metadata,
    reconstruct_flows_from_packet_window,
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


def _packets():
    return [
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "interface_name": "en0",
            "source_node_id": "node-alpha",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.20",
            "source_port": 53000,
            "destination_port": 443,
            "transport": "tcp",
            "size_bytes": 120,
            "packet_sequence": 1,
        },
        {
            "timestamp": "2026-01-01T00:00:02+00:00",
            "interface_name": "en0",
            "source_node_id": "node-alpha",
            "source_ip": "198.51.100.20",
            "destination_ip": "203.0.113.10",
            "source_port": 443,
            "destination_port": 53000,
            "transport": "tcp",
            "size_bytes": 200,
            "packet_sequence": 2,
        },
        {
            "timestamp": "2026-01-01T00:00:03+00:00",
            "interface_name": "en0",
            "source_node_id": "node-alpha",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.20",
            "source_port": 53000,
            "destination_port": 443,
            "transport": "tcp",
            "size_bytes": 220,
            "packet_sequence": 3,
        },
    ]


def _enriched_flows():
    window = build_packet_ingestion_window(packets=_packets(), duration_seconds=4, generated_at=GENERATED_AT)
    flows = reconstruct_flows_from_packet_window(window, generated_at=GENERATED_AT)["flows"]
    return enrich_flow_records(flows, local_cidrs=["203.0.113.0/24"], generated_at=GENERATED_AT)["observations"]


def _socket_records():
    return [
        {
            "transport_protocol": "tcp",
            "local_ip": "198.51.100.20",
            "local_port": 443,
            "status": "LISTEN",
            "pid": 4242,
            "process_name": "sample-server",
        }
    ]


def _process_records():
    return [
        {
            "pid": 4242,
            "name": "sample-server",
            "cmdline": ["sample-server", "--config", "<redacted-config>"],
            "username": "<redacted-user>",
        }
    ]


def test_process_inventory_minimizes_process_and_socket_metadata():
    inventory = build_process_socket_inventory(
        socket_records=_socket_records(),
        process_records=_process_records(),
        generated_at=GENERATED_AT,
    )

    assert inventory["record_type"] == "process_socket_inventory"
    assert inventory["status"] == "ok"
    assert inventory["summary"]["listening_socket_count"] == 1
    assert inventory["summary"]["owned_socket_count"] == 1
    assert inventory["process_records"][0]["process_name"] == "sample-server"
    assert inventory["process_records"][0]["command_line_stored"] is False
    assert inventory["process_records"][0]["username_stored"] is False
    assert "cmdline" in inventory["process_records"][0]["sensitive_fields_removed"]
    assert inventory["socket_records"][0]["owner_known"] is True
    assert inventory["dashboard_status"]["rows"][0]["process_display"]["display_name"] == "sample-server"


def test_service_report_matches_flow_to_process_and_service():
    report = build_process_service_attribution_report(
        enriched_flows=_enriched_flows(),
        socket_records=_socket_records(),
        process_records=_process_records(),
        protocol_records=[
            {
                "flow_ref": _enriched_flows()[0]["flow_ref"],
                "protocol_metadata_id": "protocol-metadata-sample",
                "protocol": "tls",
                "confidence": 0.9,
            }
        ],
        generated_at=GENERATED_AT,
    )
    attribution = report["attributions"][0]

    assert report["record_type"] == "process_service_attribution_report"
    assert report["summary"]["attribution_count"] == 1
    assert report["summary"]["matched_process_count"] == 1
    assert report["summary"]["by_service"] == {"https": 1}
    assert attribution["service_name"] == "https"
    assert attribution["process_attribution"]["status"] == "matched"
    assert attribution["process_attribution"]["confidence_level"] == "high"
    assert attribution["confidence_level"] == "high"
    assert "process_port_match" in attribution["match_reasons"]
    assert attribution["operator_display"]["process_display_name"] == "sample-server"
    assert attribution["operator_display"]["command_line_stored"] is False
    assert report["dashboard_status"]["status"] == "ok"
    assert report["api_status"]["summary"]["matched_process_count"] == 1
    assert report["raw_payload_stored"] is False
    assert report["payload_bytes_stored"] == 0


def test_permission_denied_degrades_safely():
    report = build_process_service_attribution_report(
        enriched_flows=_enriched_flows(),
        socket_records=[],
        process_records=[],
        platform_status={"permission_denied": True, "reason": "operator permission required"},
        generated_at=GENERATED_AT,
    )
    attribution = report["attributions"][0]

    assert report["inventory"]["status"] == "degraded"
    assert report["summary"]["permission_denied_count"] == 1
    assert attribution["process_attribution"]["status"] == "permission_denied"
    assert attribution["process_attribution"]["permission_denied"] is True
    assert attribution["process_attribution"]["privilege_escalation_attempted"] is False
    assert report["dashboard_status"]["status"] == "degraded"


def test_unsupported_platform_fallback_is_reported():
    report = build_process_service_attribution_report(
        enriched_flows=_enriched_flows(),
        platform_status={"unsupported_platform": True, "reason": "socket inventory unavailable"},
        generated_at=GENERATED_AT,
    )

    assert report["inventory"]["platform_status"]["unsupported_platform"] is True
    assert report["summary"]["unsupported_platform_count"] == 1
    assert report["attributions"][0]["process_attribution"]["status"] == "unsupported"


def test_sensitive_process_name_is_redacted():
    record = minimize_process_metadata({"pid": 7, "name": "sample-key-helper"})

    assert record["process_name"] == "redacted-process"
    assert record["command_line_stored"] is False
    assert record["username_stored"] is False


def test_attribution_serialization_is_deterministic_and_private_safe():
    report = build_process_service_attribution_report(
        enriched_flows=_enriched_flows(),
        socket_records=_socket_records(),
        process_records=_process_records(),
        generated_at=GENERATED_AT,
    )
    report_json = deterministic_service_attribution_json(report)
    inventory_json = deterministic_process_attribution_json(report["inventory"])

    assert report_json == deterministic_service_attribution_json(report)
    assert inventory_json == deterministic_process_attribution_json(report["inventory"])
    assert "--config" not in report_json
    assert "<redacted-config>" not in report_json
    assert "<redacted-user>" not in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)
        assert not pattern.search(inventory_json)
