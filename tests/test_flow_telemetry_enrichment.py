import re

import pytest

from core_engine.telemetry import (
    FlowEnrichmentError,
    build_enriched_flow_observation,
    build_packet_ingestion_window,
    deterministic_flow_enrichment_json,
    deterministic_flow_observation_json,
    enrich_flow_records,
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
        {
            "timestamp": "2026-01-01T00:00:04+00:00",
            "interface_name": "en1",
            "source_node_id": "node-alpha",
            "source_ip": "2001:db8:100::10",
            "destination_ip": "2001:db8:200::20",
            "source_port": 53001,
            "destination_port": 53,
            "transport": "udp",
            "size_bytes": 80,
            "packet_sequence": 4,
        },
    ]


def _flows(packets=None):
    window = build_packet_ingestion_window(
        packets=packets or _packets(),
        duration_seconds=4,
        generated_at=GENERATED_AT,
    )
    return reconstruct_flows_from_packet_window(window, timeout_seconds=300, generated_at=GENERATED_AT)["flows"]


def test_enriches_flow_observations_with_direction_service_and_counters():
    report = enrich_flow_records(
        _flows(),
        local_cidrs=["203.0.113.0/24", "2001:db8:100::/48"],
        generated_at=GENERATED_AT,
    )
    tcp = next(row for row in report["observations"] if row["transport_protocol"] == "tcp")
    udp = next(row for row in report["observations"] if row["transport_protocol"] == "udp")

    assert report["record_type"] == "flow_enrichment_report"
    assert report["summary"]["observation_count"] == 2
    assert report["summary"]["packet_count"] == 4
    assert report["summary"]["byte_count"] == 620
    assert report["summary"]["by_direction"] == {"outbound": 2}
    assert report["summary"]["by_service"] == {"dns": 1, "https": 1}
    assert tcp["direction"]["direction"] == "outbound"
    assert tcp["endpoint_classification"]["initiator"]["endpoint_scope"] == "local"
    assert tcp["endpoint_classification"]["responder"]["endpoint_scope"] == "remote"
    assert tcp["service_port_hint"]["service_name"] == "https"
    assert tcp["counters"]["packet_count"] == 3
    assert tcp["counters"]["byte_count"] == 540
    assert tcp["state_transition"]["state"] == "new"
    assert tcp["confidence"] >= 0.9
    assert tcp["telemetry_quality_flags"]["quality_level"] == "high"
    assert udp["classification"] == "partial"
    assert udp["telemetry_quality_flags"]["quality_level"] == "medium"
    assert report["dashboard_status"]["status"] == "ok"
    assert report["api_status"]["count"] == 2
    assert report["raw_payload_stored"] is False
    assert report["payload_bytes_stored"] == 0


def test_state_transition_detects_counter_growth_from_previous_observation():
    first_flow = next(row for row in _flows() if row["transport_protocol"] == "tcp")
    previous = build_enriched_flow_observation(
        {
            **first_flow,
            "packet_count": 2,
            "byte_count": 320,
            "last_seen": "2026-01-01T00:00:02+00:00",
        },
        local_cidrs=["203.0.113.0/24"],
        generated_at=GENERATED_AT,
    )
    current = build_enriched_flow_observation(
        first_flow,
        previous_observation=previous,
        local_cidrs=["203.0.113.0/24"],
        generated_at=GENERATED_AT,
    )

    assert current["state_transition"]["state"] == "changed"
    assert "packet_count_increased" in current["state_transition"]["reasons"]
    assert "byte_count_increased" in current["state_transition"]["reasons"]


def test_enrichment_bounds_observation_count():
    report = enrich_flow_records(_flows(), max_observations=1, generated_at=GENERATED_AT)

    assert report["input_flow_count"] == 2
    assert report["summary"]["observation_count"] == 1
    assert report["summary"]["dropped_observation_count"] == 1
    assert report["dashboard_status"]["metrics"]["dropped_observation_count"] == 1


def test_malformed_flow_enrichment_is_review_required():
    malformed = _flows(
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
    report = enrich_flow_records(malformed, local_cidrs=["203.0.113.0/24"], generated_at=GENERATED_AT)

    assert report["summary"]["malformed_flow_count"] == 1
    assert report["summary"]["poor_quality_count"] == 1
    assert report["dashboard_status"]["status"] == "review_required"
    assert report["observations"][0]["telemetry_quality_flags"]["malformed_flow"] is True
    assert report["observations"][0]["confidence"] < 0.5


def test_rejects_invalid_observation_bound():
    with pytest.raises(FlowEnrichmentError):
        enrich_flow_records(_flows(), max_observations=0, generated_at=GENERATED_AT)


def test_enrichment_serialization_is_deterministic_and_private_safe():
    report = enrich_flow_records(_flows(), generated_at=GENERATED_AT)
    report_json = deterministic_flow_enrichment_json(report)
    observation_json = deterministic_flow_observation_json(report["observations"][0])

    assert report_json == deterministic_flow_enrichment_json(report)
    assert observation_json == deterministic_flow_observation_json(report["observations"][0])
    assert '"payload_bytes_stored":0' in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)
        assert not pattern.search(observation_json)
