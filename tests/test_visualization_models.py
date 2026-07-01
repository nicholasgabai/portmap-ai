import json

from core_engine.protocols import classify_packets, summarize_conversations
from core_engine.timeline import build_packet_timeline
from core_engine.visualization import (
    build_activity_heatmap,
    build_bandwidth_model,
    build_communication_matrix,
    build_conversation_graph,
    build_conversation_visualizations,
    build_flow_graph,
    build_host_graph,
    build_network_snapshot,
    build_port_distribution,
    build_protocol_distribution,
    build_session_visualizations,
    build_timeline_lanes,
    build_timeline_model,
    build_top_talkers,
    visualization_statistics,
)


def _packet(**overrides):
    data = {
        "packet_id": "packet-a",
        "session_id": "session-a",
        "observed_at": "2026-06-14T12:00:00+00:00",
        "interface": "mock0",
        "direction": "outbound",
        "length": 64,
        "captured_length": 64,
        "link_type": "ethernet",
        "eth_src": "aa:bb:cc:dd:ee:ff",
        "eth_dst": "11:22:33:44:55:66",
        "ether_type": "0x0800",
        "ip_version": 4,
        "src_ip": "192.168.1.10",
        "dst_ip": "203.0.113.10",
        "ttl": 64,
        "protocol": "TCP",
        "src_port": 51515,
        "dst_port": 443,
        "tcp_flags": ["SYN"],
        "payload_length": 0,
        "tags": ["fixture"],
        "metadata": {"safe": "yes"},
    }
    data.update(overrides)
    return data


def _packets():
    return [
        _packet(packet_id="packet-b", observed_at="2026-06-14T12:00:03+00:00", dst_port=443, length=70),
        _packet(packet_id="packet-a", observed_at="2026-06-14T12:00:00+00:00", dst_port=443, length=60),
        _packet(
            packet_id="packet-c",
            session_id="session-b",
            observed_at="2026-06-14T12:00:01+00:00",
            protocol="UDP",
            dst_ip="198.51.100.53",
            src_port=53000,
            dst_port=53,
            length=80,
        ),
    ]


def _derived():
    packets = _packets()
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    timeline = build_packet_timeline(packets, protocol_records=records, conversations=conversations)
    return packets, records, conversations, timeline


def test_timeline_generation_and_lanes_are_stable():
    _, _, _, timeline = _derived()

    model = build_timeline_model(timeline, group_by="protocol")
    lanes = build_timeline_lanes(timeline, group_by="session")

    assert model["timeline_id"].startswith("timeline-model-")
    assert model["event_count"] == len(timeline)
    assert model["lane_count"] >= 2
    assert model["events"] == sorted(model["events"], key=lambda row: (row["timestamp"], row["event_type"], row["event_id"], row["packet_id"]))
    assert {lane["label"] for lane in lanes} >= {"session-a", "session-b"}
    assert all(lane["event_count"] == len(lane["events"]) for lane in lanes)


def test_host_graph_and_flow_graph_models():
    _, _, conversations, timeline = _derived()

    host_graph = build_host_graph(timeline)
    flow_graph = build_flow_graph(conversations)

    assert host_graph["host_count"] == 3
    assert host_graph["edge_count"] >= 2
    assert any(node["ip"] == "192.168.1.10" and "client" in node["roles"] for node in host_graph["nodes"])
    assert flow_graph["flow_count"] == len(conversations)
    assert all(edge["flow_key"] != "-" for edge in flow_graph["edges"])
    assert all(0 <= edge["confidence"] <= 1 for edge in flow_graph["edges"])


def test_conversation_graph_and_visualizations():
    _, _, conversations, timeline = _derived()

    graph = build_conversation_graph(conversations)
    conversation_views = build_conversation_visualizations(conversations)
    session_views = build_session_visualizations(timeline)

    assert graph["conversation_count"] == 2
    assert len(graph["nodes"]) == 2
    assert len(conversation_views) == 2
    assert {view["protocol"] for view in conversation_views} == {"dns", "https"}
    assert {view["session_id"] for view in session_views} == {"session-a", "session-b"}
    assert next(view for view in session_views if view["session_id"] == "session-a")["byte_count"] == 130


def test_protocol_and_port_distribution_models():
    _, records, conversations, _ = _derived()

    protocol_distribution = build_protocol_distribution(records, conversations=conversations)
    port_distribution = build_port_distribution(records, conversations=conversations)

    assert protocol_distribution["total_count"] == 3
    assert [row["protocol"] for row in protocol_distribution["protocols"]] == ["https", "dns"]
    https = next(row for row in protocol_distribution["protocols"] if row["protocol"] == "https")
    assert https["percentage"] == 66.667
    assert any(row["port"] == 443 and row["protocol"] == "https" for row in port_distribution["ports"])
    assert any(row["port"] == 53 and row["protocol"] == "dns" for row in port_distribution["ports"])


def test_communication_matrix_heatmap_top_talkers_and_bandwidth():
    _, _, conversations, timeline = _derived()

    matrix = build_communication_matrix(conversations)
    heatmap = build_activity_heatmap(timeline, granularity="minute")
    top_talkers = build_top_talkers(conversations)
    bandwidth = build_bandwidth_model(conversations)

    assert matrix["host_count"] == 3
    assert any(row["bytes"] == 130 and row["protocols"] == ["https"] for row in matrix["rows"])
    assert heatmap["granularity"] == "minute"
    assert heatmap["bucket_count"] == 1
    assert heatmap["buckets"][0]["event_count"] == len(timeline)
    assert top_talkers["talkers"][0]["rank"] == 1
    assert bandwidth["total_bytes"] == 210
    assert bandwidth["by_protocol"][0]["protocol"] == "https"


def test_network_snapshot_and_statistics():
    _, records, conversations, timeline = _derived()

    snapshot = build_network_snapshot(
        timestamp="2026-06-14T12:00:05+00:00",
        events=timeline,
        protocol_records=records,
        conversations=conversations,
    )
    stats = visualization_statistics(events=timeline, protocol_records=records, conversations=conversations)

    assert snapshot["host_count"] == 3
    assert snapshot["conversation_count"] == 2
    assert snapshot["flow_count"] == 2
    assert snapshot["session_count"] == 2
    assert snapshot["protocol_distribution"]["protocols"]
    assert stats["largest_conversation"] != "-"
    assert stats["largest_flow"] != "-"
    assert stats["most_active_protocol"] == "https"


def test_json_serialization_and_no_payload_fields():
    packets = [_packet(packet_id="payload-safe", metadata={"payload_body": "secret", "safe": "yes"}, payload="hidden")]
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    timeline = build_packet_timeline(packets, protocol_records=records, conversations=conversations)

    models = {
        "timeline": build_timeline_model(timeline),
        "host_graph": build_host_graph(timeline),
        "flow_graph": build_flow_graph(conversations),
        "protocol_distribution": build_protocol_distribution(records, conversations=conversations),
        "snapshot": build_network_snapshot(events=timeline, protocol_records=records, conversations=conversations),
    }
    rendered = json.dumps(models, sort_keys=True)

    assert "secret" not in rendered
    assert "hidden" not in rendered
    assert "payload_body" not in rendered


def test_stable_ordering_and_deterministic_output():
    packets = _packets()
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    timeline = build_packet_timeline(packets, protocol_records=records, conversations=conversations)

    first = {
        "timeline": build_timeline_model(timeline),
        "host": build_host_graph(timeline),
        "flow": build_flow_graph(conversations),
        "protocol": build_protocol_distribution(records, conversations=conversations),
        "ports": build_port_distribution(records, conversations=conversations),
        "matrix": build_communication_matrix(conversations),
        "heatmap": build_activity_heatmap(timeline),
        "talkers": build_top_talkers(conversations),
        "snapshot": build_network_snapshot(events=timeline, protocol_records=records, conversations=conversations),
    }
    second = {
        "timeline": build_timeline_model(list(reversed(timeline))),
        "host": build_host_graph(list(reversed(timeline))),
        "flow": build_flow_graph(list(reversed(conversations))),
        "protocol": build_protocol_distribution(list(reversed(records)), conversations=list(reversed(conversations))),
        "ports": build_port_distribution(list(reversed(records)), conversations=list(reversed(conversations))),
        "matrix": build_communication_matrix(list(reversed(conversations))),
        "heatmap": build_activity_heatmap(list(reversed(timeline))),
        "talkers": build_top_talkers(list(reversed(conversations))),
        "snapshot": build_network_snapshot(
            events=list(reversed(timeline)),
            protocol_records=list(reversed(records)),
            conversations=list(reversed(conversations)),
        ),
    }

    assert first == second
    json.dumps(first, sort_keys=True)


def test_empty_input_returns_safe_models():
    assert build_timeline_model([])["event_count"] == 0
    assert build_timeline_lanes([]) == []
    assert build_host_graph([])["nodes"] == []
    assert build_flow_graph([])["edges"] == []
    assert build_conversation_graph([])["nodes"] == []
    assert build_protocol_distribution([])["protocols"] == []
    assert build_port_distribution([])["ports"] == []
    assert build_communication_matrix([])["rows"] == []
    assert build_activity_heatmap([])["buckets"] == []
    assert build_top_talkers([])["talkers"] == []
    assert build_network_snapshot(events=[], protocol_records=[], conversations=[])["host_count"] == 0


def test_callers_are_not_mutated():
    packets = _packets()
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    timeline = build_packet_timeline(packets, protocol_records=records, conversations=conversations)
    original_records = json.loads(json.dumps(records))
    original_conversations = json.loads(json.dumps(conversations))
    original_timeline = json.loads(json.dumps(timeline))

    build_protocol_distribution(records, conversations=conversations)
    build_flow_graph(conversations)
    build_timeline_model(timeline)

    assert records == original_records
    assert conversations == original_conversations
    assert timeline == original_timeline
