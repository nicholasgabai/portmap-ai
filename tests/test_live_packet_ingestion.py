import re
import socket

import pytest

from core_engine.telemetry import (
    PacketWindowError,
    build_packet_ingestion_window,
    build_passive_capture_session_plan,
    deterministic_packet_metadata_json,
    deterministic_packet_window_json,
    normalize_packet_metadata,
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


def _fixture_interfaces():
    return {
        "en0": [
            {
                "family": socket.AF_INET,
                "address": "203.0.113.10",
                "netmask": "255.255.255.0",
                "broadcast": "203.0.113.255",
            }
        ]
    }


def _capture_plan():
    return build_passive_capture_session_plan(
        interfaces=_fixture_interfaces(),
        selected_interfaces=["en0"],
        generated_at=GENERATED_AT,
    )


def _fixture_packets():
    return [
        {
            "timestamp": "2026-01-01T00:00:01+00:00",
            "interface_name": "en0",
            "source_node_id": "node-local",
            "source_ip": "203.0.113.10",
            "destination_ip": "203.0.113.20",
            "source_port": 44321,
            "destination_port": 443,
            "transport": "tcp",
            "size_bytes": 128,
            "payload": "redacted test payload",
            "packet_sequence": 1,
        },
        {
            "timestamp": "2026-01-01T00:00:02+00:00",
            "interface_name": "en0",
            "source_node_id": "node-local",
            "source_ip": "2001:db8::10",
            "destination_ip": "2001:db8::20",
            "source_port": 53000,
            "destination_port": 53,
            "transport": "udp",
            "size_bytes": 96,
            "packet_sequence": 2,
        },
        {
            "timestamp": "2026-01-01T00:00:03+00:00",
            "interface_name": "en0",
            "source_node_id": "node-local",
            "source_ip": "203.0.113.20",
            "destination_ip": "203.0.113.10",
            "transport": "icmp",
            "size_bytes": 84,
            "packet_sequence": 3,
        },
    ]


def test_packet_metadata_normalizes_without_payload_storage():
    metadata = normalize_packet_metadata(_fixture_packets()[0], generated_at=GENERATED_AT)

    assert metadata["record_type"] == "packet_metadata"
    assert metadata["interface_name"] == "en0"
    assert metadata["source_node_id"] == "node-local"
    assert metadata["address_family"] == "ipv4"
    assert metadata["transport_protocol"] == "tcp"
    assert metadata["classification"] == "accepted"
    assert metadata["payload_present"] is True
    assert metadata["payload_discarded"] is True
    assert metadata["payload_bytes_stored"] == 0
    assert metadata["raw_payload_stored"] is False
    assert "payload" not in metadata
    assert metadata["packet_digest"].startswith("sha256:")


def test_packet_ingestion_window_summarizes_transport_address_size_and_rate():
    window = build_packet_ingestion_window(
        packets=_fixture_packets(),
        capture_plan=_capture_plan(),
        duration_seconds=2,
        generated_at=GENERATED_AT,
    )
    summary = window["summary"]

    assert window["record_type"] == "packet_ingestion_window"
    assert window["dry_run"] is True
    assert window["metadata_only"] is True
    assert summary["metadata_record_count"] == 3
    assert summary["accepted_count"] == 3
    assert summary["transport_summary"] == {"icmp": 1, "tcp": 1, "udp": 1}
    assert summary["address_family_summary"] == {"ipv4": 2, "ipv6": 1}
    assert summary["packet_size_summary"]["total_bytes"] == 308
    assert summary["packet_size_summary"]["max_size_bytes"] == 128
    assert summary["packet_rate_summary"]["packets_per_second"] == 1.5
    assert summary["replay_safe_counters"]["accepted_count"] == 3
    assert window["dashboard_status"]["metrics"]["accepted_count"] == 3
    assert window["api_status"]["count"] == 3
    assert window["raw_payload_stored"] is False


def test_packet_ingestion_classifies_malformed_unsupported_duplicate_and_stale_records():
    accepted = normalize_packet_metadata(_fixture_packets()[0], generated_at=GENERATED_AT)
    packets = [
        _fixture_packets()[0],
        {
            "timestamp": "2026-01-01T00:00:04+00:00",
            "interface_name": "en0",
            "source_ip": "not-an-ip",
            "destination_ip": "203.0.113.30",
            "transport": "tcp",
            "size_bytes": 40,
        },
        {
            "timestamp": "2026-01-01T00:00:05+00:00",
            "interface_name": "en0",
            "source_ip": "203.0.113.30",
            "destination_ip": "203.0.113.40",
            "transport": "gre",
            "size_bytes": 60,
        },
        {
            "timestamp": "2025-12-31T23:59:59+00:00",
            "interface_name": "en0",
            "source_ip": "203.0.113.50",
            "destination_ip": "203.0.113.60",
            "transport": "udp",
            "size_bytes": 70,
        },
    ]

    window = build_packet_ingestion_window(
        packets=packets,
        previous_packet_digests=[accepted["packet_digest"]],
        replay_window_started_at="2026-01-01T00:00:00+00:00",
        generated_at=GENERATED_AT,
    )
    summary = window["summary"]

    assert summary["duplicate_count"] == 1
    assert summary["malformed_count"] == 1
    assert summary["unsupported_count"] == 1
    assert summary["stale_count"] == 1
    assert summary["accepted_count"] == 0
    assert summary["replay_safe_counters"]["rejected_count"] == 2
    assert window["dashboard_status"]["status"] == "review_required"


def test_packet_ingestion_window_enforces_packet_and_byte_bounds():
    packets = _fixture_packets()
    limited_by_count = build_packet_ingestion_window(packets=packets, max_packets=2, generated_at=GENERATED_AT)
    limited_by_bytes = build_packet_ingestion_window(packets=packets, max_window_bytes=130, generated_at=GENERATED_AT)

    assert limited_by_count["summary"]["metadata_record_count"] == 2
    assert limited_by_count["summary"]["truncated_count"] == 1
    assert limited_by_bytes["summary"]["metadata_record_count"] == 1
    assert limited_by_bytes["summary"]["truncated_count"] == 2

    with pytest.raises(PacketWindowError):
        build_packet_ingestion_window(packets=packets, max_packets=-1, generated_at=GENERATED_AT)


def test_packet_ingestion_serialization_is_deterministic_and_private_safe():
    metadata = normalize_packet_metadata(_fixture_packets()[0], generated_at=GENERATED_AT)
    window = build_packet_ingestion_window(
        packets=_fixture_packets(),
        capture_plan=_capture_plan(),
        duration_seconds=2,
        generated_at=GENERATED_AT,
    )
    metadata_json = deterministic_packet_metadata_json(metadata)
    window_json = deterministic_packet_window_json(window)

    assert metadata_json == deterministic_packet_metadata_json(metadata)
    assert window_json == deterministic_packet_window_json(window)
    assert "redacted test payload" not in metadata_json
    assert "redacted test payload" not in window_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(metadata_json)
        assert not pattern.search(window_json)
