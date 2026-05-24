import re

import pytest

from core_engine.telemetry import (
    FlowSessionTrackerError,
    build_packet_ingestion_window,
    deterministic_flow_json,
    deterministic_session_tracker_json,
    normalize_flow_key,
    reconstruct_flows_from_packet_window,
    track_flow_sessions,
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


def _packets():
    return [
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "interface_name": "en0",
            "source_node_id": "node-local",
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
            "source_node_id": "node-local",
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
            "source_node_id": "node-local",
            "source_ip": "203.0.113.10",
            "destination_ip": "198.51.100.20",
            "source_port": 53000,
            "destination_port": 443,
            "transport": "tcp",
            "size_bytes": 220,
            "packet_sequence": 3,
        },
        {
            "timestamp": "2026-01-01T00:00:04+00:00",
            "interface_name": "en0",
            "source_node_id": "node-local",
            "source_ip": "2001:db8::10",
            "destination_ip": "2001:db8::20",
            "source_port": 53001,
            "destination_port": 53,
            "transport": "udp",
            "size_bytes": 80,
            "packet_sequence": 4,
        },
    ]


def _packet_window(packets=None):
    return build_packet_ingestion_window(
        packets=packets or _packets(),
        duration_seconds=4,
        generated_at=GENERATED_AT,
    )


def test_flow_key_normalization_is_bidirectional():
    window = _packet_window()
    first, second = window["packet_records"][0], window["packet_records"][1]

    first_key = normalize_flow_key(first)
    second_key = normalize_flow_key(second)

    assert first_key["flow_key"] == second_key["flow_key"]
    assert first_key["transport_protocol"] == "tcp"
    assert first_key["endpoint_a"]["ip"] in {"198.51.100.20", "203.0.113.10"}
    assert first_key["raw_payload_stored"] is False


def test_reconstructs_bidirectional_flows_and_topology_edges():
    report = reconstruct_flows_from_packet_window(_packet_window(), timeout_seconds=300, generated_at=GENERATED_AT)
    flows = report["flows"]
    tcp_flow = next(flow for flow in flows if flow["transport_protocol"] == "tcp")
    udp_flow = next(flow for flow in flows if flow["transport_protocol"] == "udp")

    assert report["record_type"] == "flow_session_tracking_report"
    assert report["summary"]["flow_count"] == 2
    assert report["flow_summary"]["complete_flow_count"] == 1
    assert report["flow_summary"]["partial_flow_count"] == 1
    assert tcp_flow["classification"] == "complete"
    assert tcp_flow["ephemeral_or_persistent"] == "persistent"
    assert tcp_flow["forward_packet_count"] == 2
    assert tcp_flow["reverse_packet_count"] == 1
    assert tcp_flow["service_association"]["service_name"] == "https"
    assert tcp_flow["topology_edge"]["relationship_type"] == "observed_flow"
    assert tcp_flow["topology_edge"]["protocol"] == "tcp/https"
    assert udp_flow["classification"] == "partial"
    assert "single_direction_observed" in udp_flow["partial_reasons"]
    assert report["dashboard_status"]["metrics"]["topology_edge_count"] == 2
    assert report["api_status"]["count"] == 2
    assert report["payload_bytes_stored"] == 0
    assert report["raw_payload_stored"] is False


def test_flow_timeout_splits_sessions():
    packets = [
        _packets()[0],
        {
            **_packets()[1],
            "timestamp": "2026-01-01T00:10:00+00:00",
            "packet_sequence": 20,
        },
    ]
    report = reconstruct_flows_from_packet_window(_packet_window(packets), timeout_seconds=60, generated_at=GENERATED_AT)

    assert report["summary"]["session_count"] == 2
    assert report["summary"]["timed_out_session_count"] == 1
    assert all(flow["classification"] == "partial" for flow in report["flows"])


def test_malformed_and_partial_flow_handling_is_reported():
    window = _packet_window(
        [
            {
                "timestamp": "2026-01-01T00:00:01+00:00",
                "interface_name": "en0",
                "source_ip": "not-an-ip",
                "destination_ip": "203.0.113.10",
                "source_port": 12345,
                "destination_port": 443,
                "transport": "tcp",
                "size_bytes": 64,
            }
        ]
    )
    report = reconstruct_flows_from_packet_window(window, generated_at=GENERATED_AT)

    assert report["flow_summary"]["malformed_flow_count"] == 1
    assert report["flows"][0]["classification"] == "malformed"
    assert report["dashboard_status"]["status"] == "review_required"


def test_flow_tracker_rejects_invalid_timeout():
    with pytest.raises(FlowSessionTrackerError):
        track_flow_sessions(packets=[], timeout_seconds=-1, generated_at=GENERATED_AT)


def test_flow_serialization_is_deterministic_and_private_safe():
    report = reconstruct_flows_from_packet_window(_packet_window(), timeout_seconds=300, generated_at=GENERATED_AT)
    flow_json = deterministic_flow_json(report["flows"][0])
    report_json = deterministic_session_tracker_json(report)

    assert flow_json == deterministic_flow_json(report["flows"][0])
    assert report_json == deterministic_session_tracker_json(report)
    assert '"payload_bytes_stored":0' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(flow_json)
        assert not pattern.search(report_json)
