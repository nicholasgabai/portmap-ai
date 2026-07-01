import json
import socket

from core_engine.hunting import (
    HuntQuery,
    PacketHuntEngine,
    contains_search,
    deduplicate,
    difference,
    exact_search,
    find_conversations_during_time_window,
    find_conversations_for_interface,
    find_conversations_for_protocol,
    find_flows_between_hosts,
    find_highest_confidence_conversations,
    find_inactive_conversations,
    find_largest_conversations,
    find_newest_observations,
    find_oldest_observations,
    find_protocol_transitions,
    find_traffic_for_host,
    find_traffic_for_ip,
    find_unknown_protocols,
    intersection,
    prefix_search,
    save_query,
    search_packets,
    stable_sort,
    suffix_search,
    union,
)
from core_engine.protocols import classify_packets, summarize_conversations
from core_engine.timeline import build_packet_timeline
from core_engine.visualization import build_network_snapshot, build_protocol_distribution, build_timeline_model


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
        _packet(
            packet_id="packet-d",
            session_id="session-c",
            observed_at="2026-06-14T12:00:04+00:00",
            protocol="-",
            link_type="-",
            ether_type="-",
            ip_version=0,
            eth_src="-",
            eth_dst="-",
            src_ip="10.0.0.5",
            dst_ip="-",
            src_port=0,
            dst_port=0,
            length=40,
            tags=["unknown"],
        ),
    ]


def _derived():
    packets = _packets()
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    timeline = build_packet_timeline(packets, protocol_records=records, conversations=conversations)
    visualizations = [
        build_timeline_model(timeline),
        build_protocol_distribution(records, conversations=conversations),
        build_network_snapshot(events=timeline, protocol_records=records, conversations=conversations),
    ]
    return packets, records, conversations, timeline, visualizations


def _search(query):
    packets, records, conversations, timeline, visualizations = _derived()
    return PacketHuntEngine().search(
        query,
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualizations=visualizations,
    )


def test_query_creation_equality_stable_ids_and_json():
    first = HuntQuery(protocol="HTTPS", tags=["Fixture"], limit=2)
    second = HuntQuery(tags=("fixture",), protocol="https", limit=2)

    assert first == second
    assert first.query_id == second.query_id
    assert first.to_dict()["tags"] == ["fixture"]
    json.dumps(first.to_dict(), sort_keys=True)


def test_packet_protocol_timeline_conversation_session_and_flow_searching():
    result = _search(HuntQuery(host="192.168.1.10", sort_by="time"))

    assert result["matched_packets"]
    assert result["matched_protocols"]
    assert result["matched_conversations"]
    assert result["matched_timeline_events"]
    assert result["matched_sessions"]
    assert result["statistics"]["flow_matches"] >= 2
    assert "192.168.1.10" in result["metadata"]["related_hosts"]


def test_protocol_search_and_unknown_protocol_search():
    https = _search(HuntQuery(protocol="https"))
    unknown = _search(find_unknown_protocols())

    assert {record["protocol"] for record in https["matched_protocols"]} == {"https"}
    assert all(event["protocol"] == "https" for event in https["matched_timeline_events"])
    assert unknown["matched_protocols"][0]["protocol"] == "unknown"


def test_visualization_searching_matches_nested_models():
    result = _search(HuntQuery(protocol="dns"))

    assert result["matched_visualizations"]
    rendered = json.dumps(result["matched_visualizations"], sort_keys=True)
    assert "dns" in rendered


def test_filter_combinations_and_sorting():
    result = _search(
        HuntQuery(
            host="192.168.1.10",
            port=443,
            interface="mock0",
            confidence=0.5,
            sort_by="time",
            sort_direction="desc",
            limit=1,
        )
    )

    assert len(result["matched_protocols"]) == 1
    assert result["matched_protocols"][0]["protocol"] == "https"
    assert result["matched_timeline_events"][0]["dst_port"] == 443


def test_exact_contains_prefix_suffix_helpers():
    rows = [{"packet_id": "alpha", "protocol": "https"}, {"packet_id": "beta", "protocol": "dns"}]

    assert exact_search(rows, "protocol", "https")[0]["packet_id"] == "alpha"
    assert contains_search(rows, "packet_id", "et")[0]["packet_id"] == "beta"
    assert prefix_search(rows, "packet_id", "al")[0]["packet_id"] == "alpha"
    assert suffix_search(rows, "packet_id", "ta")[0]["packet_id"] == "beta"


def test_deduplication_intersection_union_difference_and_sorting():
    left = [{"packet_id": "b", "observed_at": "2026-06-14T12:00:02+00:00"}, {"packet_id": "a", "observed_at": "2026-06-14T12:00:01+00:00"}]
    right = [{"packet_id": "a", "observed_at": "2026-06-14T12:00:01+00:00"}]

    assert [row["packet_id"] for row in stable_sort(left)] == ["a", "b"]
    assert len(deduplicate(left + right)) == 2
    assert [row["packet_id"] for row in intersection(left, right)] == ["a"]
    assert [row["packet_id"] for row in union(left, right)] == ["a", "b"]
    assert [row["packet_id"] for row in difference(left, right)] == ["b"]


def test_saved_query_model():
    query = find_traffic_for_ip("192.168.1.10")
    saved = save_query(name="Host hunt", description="Find host traffic", query=query, tags=["host"], version="2")

    rendered = saved.to_dict()
    assert rendered["saved_query_id"].startswith("saved-hunt-query-")
    assert rendered["query"]["host"] == "192.168.1.10"
    assert rendered["tags"] == ["host"]


def test_common_hunt_helpers():
    assert find_traffic_for_host("host-a").host == "host-a"
    assert find_conversations_for_protocol("dns").protocol == "dns"
    assert find_conversations_for_interface("mock0").interface == "mock0"
    assert find_flows_between_hosts("a", "b").src_ip == "a"
    assert find_conversations_during_time_window("a", "b").time_end == "b"
    assert find_newest_observations(3).sort_direction == "desc"
    assert find_oldest_observations(3).sort_direction == "asc"
    assert find_largest_conversations(2).sort_by == "bytes"
    assert find_highest_confidence_conversations(2).sort_by == "confidence"
    assert find_protocol_transitions().metadata == {"event_type": "protocol_changed"}
    assert find_inactive_conversations().metadata == {"state": "inactive"}


def test_json_serialization_deterministic_ordering_and_no_payload_fields():
    result = _search(HuntQuery(host="192.168.1.10"))
    repeated = _search(HuntQuery(host="192.168.1.10"))
    rendered = json.dumps(result, sort_keys=True)

    assert result == repeated
    assert "payload_body" not in rendered
    assert "raw_bytes" not in rendered
    assert result["matched_packets"] == sorted(result["matched_packets"], key=lambda row: (row["observed_at"], f"packet_id:{row['packet_id']}", str(row)))


def test_empty_input_returns_safe_result():
    result = search_packets(HuntQuery(protocol="https"), packets=[], protocol_records=[], conversations=[], timeline_events=[], visualizations=[])

    assert result["matched_packets"] == []
    assert result["statistics"]["packet_matches"] == 0
    assert result["summary"]["top_protocol"] == "-"
    assert result["confidence"] == 0.0


def test_large_input_is_deterministic():
    packets = [
        _packet(
            packet_id=f"packet-{index:03d}",
            observed_at=f"2026-06-14T12:{index % 60:02d}:00+00:00",
            src_port=50000 + index,
            length=50 + index,
        )
        for index in range(75)
    ]
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    timeline = build_packet_timeline(packets, protocol_records=records, conversations=conversations)
    query = HuntQuery(protocol="https", limit=5, sort_by="time")

    first = PacketHuntEngine().search(query, packets=packets, protocol_records=records, conversations=conversations, timeline_events=timeline)
    second = PacketHuntEngine().search(query, packets=list(reversed(packets)), protocol_records=list(reversed(records)), conversations=list(reversed(conversations)), timeline_events=list(reversed(timeline)))

    assert first == second
    assert len(first["matched_protocols"]) == 5


def test_inputs_are_not_mutated_and_payload_is_removed():
    packet = _packet(packet_id="payload-safe", payload="hidden", raw_bytes=b"hidden", metadata={"payload_body": "secret", "safe": "yes"})
    packets = [packet]
    original = json.loads(json.dumps(packet, default=str))

    result = search_packets(HuntQuery(host="192.168.1.10"), packets=packets)
    rendered = json.dumps(result, sort_keys=True)

    assert json.loads(json.dumps(packet, default=str)) == original
    assert "secret" not in rendered
    assert "hidden" not in rendered
    assert "payload_body" not in rendered


def test_no_network_calls(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("network access is not allowed")

    monkeypatch.setattr(socket, "socket", fail)

    result = _search(HuntQuery(protocol="https"))

    assert result["matched_protocols"]
