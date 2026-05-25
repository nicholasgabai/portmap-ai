import re

from core_engine.telemetry import (
    build_live_topology,
    build_packet_ingestion_window,
    deterministic_live_topology_json,
    deterministic_live_topology_record_json,
    extract_protocol_metadata_report,
    reconstruct_flows_from_packet_window,
)
from core_engine.topology.graph import build_topology_graph


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


def _protocol_records(flows):
    dns_flow = next(flow for flow in flows if flow["service_association"]["service_name"] == "dns")
    report = extract_protocol_metadata_report(
        flows=flows,
        metadata_by_flow_id={
            dns_flow["flow_id"]: {
                "dns": {
                    "query_name": "example.test",
                    "query_type": "A",
                    "response_code": "NOERROR",
                    "answer_count": 1,
                }
            }
        },
        generated_at=GENERATED_AT,
    )
    return report["records"]


def test_live_topology_correlates_flows_protocols_and_edges():
    flows = _flows()
    record = build_live_topology(flows=flows, protocol_records=_protocol_records(flows), generated_at=GENERATED_AT)

    assert record["record_type"] == "live_topology"
    assert record["graph"]["node_count"] == 4
    assert record["graph"]["edge_count"] == 3
    assert record["protocol_summary"]["by_protocol"] == {"dns": 1, "http": 1, "tls": 1}
    assert record["dashboard_status"]["metrics"]["node_count"] == 4
    assert record["api_status"]["status"] == record["health_summary"]["status"]
    assert record["raw_payload_stored"] is False
    assert record["payload_bytes_stored"] == 0
    assert record["traffic_injected"] is False
    assert record["automatic_blocking"] is False
    assert record["parallel_topology_schema_created"] is False


def test_node_role_inference_is_protocol_and_service_aware():
    flows = _flows()
    record = build_live_topology(flows=flows, protocol_records=_protocol_records(flows), generated_at=GENERATED_AT)
    nodes = {node["asset_id"]: node for node in record["nodes"]}

    assert nodes["203.0.113.10"]["role"] == "client"
    assert nodes["198.51.100.20"]["role"] == "web_service"
    assert nodes["198.51.100.30"]["role"] == "web_service"
    assert nodes["203.0.113.53"]["role"] == "name_service"


def test_bounded_growth_reports_truncated_live_topology():
    flows = _flows()
    record = build_live_topology(flows=flows, protocol_records=_protocol_records(flows), max_nodes=2, max_edges=1, generated_at=GENERATED_AT)

    inference = record["relationship_inference"]
    assert inference["node_count"] == 2
    assert inference["edge_count"] == 1
    assert inference["truncated_node_count"] == 2
    assert inference["truncated_edge_count"] == 2
    assert "node_limit_reached" in record["health_summary"]["warnings"]
    assert "edge_limit_reached" in record["health_summary"]["warnings"]
    assert record["health_summary"]["status"] == "review_required"


def test_replay_safe_topology_update_marks_duplicate_digest():
    flows = _flows()
    first = build_live_topology(flows=flows, protocol_records=_protocol_records(flows), generated_at=GENERATED_AT)
    second = build_live_topology(
        flows=flows,
        protocol_records=_protocol_records(flows),
        previous_update_digests=[first["topology_update"]["update_digest"]],
        generated_at=GENERATED_AT,
    )

    assert first["topology_update"]["classification"] == "accepted"
    assert second["topology_update"]["classification"] == "duplicate"
    assert second["topology_update"]["duplicate_count"] == 1
    assert second["topology_update"]["replay_checked"] is True


def test_topology_drift_correlation_reports_added_live_edges():
    flows = _flows()
    first_flow = flows[:1]
    baseline = build_topology_graph(assets=[], topology_edges=[first_flow[0]["topology_edge"]], generated_at=GENERATED_AT)
    record = build_live_topology(flows=flows, protocol_records=_protocol_records(flows), baseline_graph=baseline, generated_at=GENERATED_AT)

    drift = record["drift_correlation"]
    assert drift["status"] == "review_required"
    assert drift["added_edge_count"] >= 2
    assert drift["removed_edge_count"] == 0
    assert record["health_summary"]["status"] == "review_required"


def test_live_topology_serialization_is_deterministic_and_private_safe():
    flows = _flows()
    record = build_live_topology(flows=flows, protocol_records=_protocol_records(flows), generated_at=GENERATED_AT)
    as_json = deterministic_live_topology_json(record)
    record_json = deterministic_live_topology_record_json(record)

    assert as_json == deterministic_live_topology_json(record)
    assert record_json == as_json
    assert "payload" in as_json
    assert "payload_bytes_stored\":0" in as_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(as_json)
