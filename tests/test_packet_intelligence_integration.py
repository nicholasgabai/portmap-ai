import json
import socket

from core_engine.hunting import HuntQuery, PacketHuntEngine
from core_engine.packet_intelligence import (
    PacketIntelligenceEngine,
    build_packet_intelligence_summary,
    derive_attribution_hints,
    derive_behavior_graph_hints,
    derive_risk_relevant_signals,
    derive_service_candidates,
    historical_flow_aggregation,
)
from core_engine.protocols import classify_packets, summarize_conversations
from core_engine.timeline import build_packet_timeline
from core_engine.timeline.models import TimelineEvent
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
    transition = TimelineEvent.from_dict(
        {
            "timestamp": "2026-06-14T12:00:05+00:00",
            "event_type": "protocol_changed",
            "protocol": "https",
            "src_ip": "192.168.1.10",
            "dst_ip": "203.0.113.10",
            "src_port": 51515,
            "dst_port": 443,
            "confidence": 0.7,
        }
    ).to_dict()
    timeline = [*timeline, transition]
    visualizations = [
        build_timeline_model(timeline),
        build_protocol_distribution(records, conversations=conversations),
        build_network_snapshot(events=timeline, protocol_records=records, conversations=conversations),
    ]
    hunt = PacketHuntEngine().search(
        HuntQuery(host="192.168.1.10"),
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualizations=visualizations,
    )
    return packets, records, conversations, timeline, visualizations, [hunt]


def test_empty_input_behavior():
    summary = build_packet_intelligence_summary()

    assert summary["packet_count"] == 0
    assert summary["protocol_count"] == 0
    assert summary["conversation_count"] == 0
    assert summary["confidence"] == 0.0
    assert "no_packet_metadata_available" in summary["limitations"]
    assert summary["operator_summary"] == "No packet metadata was available for integration."


def test_summary_generation_from_packet_metadata_only():
    summary = build_packet_intelligence_summary(packets=_packets(), generated_at="2026-06-14T12:00:10+00:00")

    assert summary["packet_count"] == 4
    assert summary["protocol_count"] == 4
    assert summary["conversation_count"] == 3
    assert summary["flow_count"] == 3
    assert summary["top_protocol"] == "https"
    assert summary["top_talker"] == "192.168.1.10"
    assert summary["packet_activity_summary"]["total_packet_bytes"] == 250


def test_protocol_timeline_visualization_and_hunting_integration():
    packets, records, conversations, timeline, visualizations, hunts = _derived()
    summary = PacketIntelligenceEngine().summarize(
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualization_models=visualizations,
        hunt_results=hunts,
    )

    assert summary["protocol_count"] == len(records)
    assert summary["timeline_event_count"] == len(timeline)
    assert summary["visualization_summary"]["visualization_model_count"] == 3
    assert summary["hunting_summary"]["hunt_result_count"] == 1
    assert summary["metadata"]["hunt_correlation"]["related_hosts"]
    assert summary["metadata"]["visualization_correlation"]["visualization_model_count"] == 3


def test_attribution_hints():
    _, records, conversations, _, _, _ = _derived()

    hints = derive_attribution_hints(records, conversations)

    assert "likely_dns" in hints
    assert "likely_https" in hints
    assert "unknown_application_protocol" in hints
    assert "protocol_by_port" in hints
    assert "repeated_flow_observation" in hints


def test_risk_relevant_signals():
    _, records, conversations, timeline, _, hunts = _derived()

    signals = derive_risk_relevant_signals(records, timeline, hunts, conversations)

    assert "unknown_protocol_observed" in signals
    assert "repeated_sensitive_port" in signals
    assert "one_way_conversation" in signals
    assert "protocol_transition" in signals


def test_behavior_graph_hints():
    _, records, conversations, timeline, _, _ = _derived()

    hints = derive_behavior_graph_hints(records, timeline, conversations)

    assert hints == [
        "conversation_relationship_observed",
        "flow_relationship_observed",
        "host_pair_observed",
        "protocol_relationship_observed",
        "timeline_relationship_observed",
    ]


def test_confidence_bounds_and_evidence_limitations():
    packets, records, conversations, timeline, visualizations, hunts = _derived()
    summary = build_packet_intelligence_summary(
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualization_models=visualizations,
        hunt_results=hunts,
    )

    assert 0.0 <= summary["confidence"] <= 1.0
    assert summary["confidence"] == 1.0
    assert "packet_metadata:4" in summary["evidence"]
    assert "metadata_only_no_payload_inspection" in summary["limitations"]


def test_deterministic_summary_ids_and_output_ordering():
    packets, records, conversations, timeline, visualizations, hunts = _derived()
    first = build_packet_intelligence_summary(
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualization_models=visualizations,
        hunt_results=hunts,
    )
    second = build_packet_intelligence_summary(
        packets=list(reversed(packets)),
        protocol_records=list(reversed(records)),
        conversations=list(reversed(conversations)),
        timeline_events=list(reversed(timeline)),
        visualization_models=list(reversed(visualizations)),
        hunt_results=list(reversed(hunts)),
    )

    assert first == second
    assert first["summary_id"].startswith("packet-intelligence-")
    assert first["risk_relevant_signals"] == sorted(first["risk_relevant_signals"])
    assert first["attribution_hints"] == sorted(first["attribution_hints"])
    assert first["behavior_graph_hints"] == sorted(first["behavior_graph_hints"])


def test_json_safe_output_and_no_payload_fields():
    packets = [_packet(packet_id="payload-safe", payload="hidden", raw_bytes=b"hidden", metadata={"payload_body": "secret", "safe": "yes"})]

    summary = build_packet_intelligence_summary(packets=packets)
    rendered = json.dumps(summary, sort_keys=True)

    assert "secret" not in rendered
    assert "hidden" not in rendered
    assert "payload_body" not in rendered


def test_no_mutation_of_caller_inputs():
    packets, records, conversations, timeline, visualizations, hunts = _derived()
    originals = json.loads(json.dumps([packets, records, conversations, timeline, visualizations, hunts], default=str))

    build_packet_intelligence_summary(
        packets=packets,
        protocol_records=records,
        conversations=conversations,
        timeline_events=timeline,
        visualization_models=visualizations,
        hunt_results=hunts,
    )

    assert json.loads(json.dumps([packets, records, conversations, timeline, visualizations, hunts], default=str)) == originals


def test_one_way_sensitive_and_unknown_protocol_detection():
    summary = build_packet_intelligence_summary(packets=_packets())

    assert "one_way_conversation" in summary["risk_relevant_signals"]
    assert "repeated_sensitive_port" in summary["risk_relevant_signals"]
    assert "unknown_protocol_observed" in summary["risk_relevant_signals"]


def test_operator_summary_and_next_steps():
    summary = build_packet_intelligence_summary(packets=_packets())

    assert "Integrated 4 packet metadata records" in summary["operator_summary"]
    assert any("unknown protocol" in step.lower() for step in summary["operator_next_steps"])
    assert any("sensitive-port" in step.lower() for step in summary["operator_next_steps"])


def test_no_network_calls(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("network access is not allowed")

    monkeypatch.setattr(socket, "socket", fail)

    summary = build_packet_intelligence_summary(packets=_packets())

    assert summary["packet_count"] == 4


def test_validated_tcp_flow_direction_is_preserved_for_outbound_https():
    packet = _packet(
        packet_id="validated-tcp-direction",
        session_id="curl-session",
        src_ip="10.10.10.20",
        src_port=53984,
        dst_ip="198.51.100.44",
        dst_port=443,
        protocol="TCP",
        direction="outbound",
    )
    conversation = summarize_conversations([packet])[0]

    assert conversation["src_ip"] == "10.10.10.20"
    assert conversation["src_port"] == 53984
    assert conversation["dst_ip"] == "198.51.100.44"
    assert conversation["dst_port"] == 443
    assert conversation["direction"] == "outbound"
    assert conversation["flow_key"] == "tcp|10.10.10.20|53984|198.51.100.44|443"


def test_dns_service_candidates_cover_udp_tcp_local_resolver_and_repetition():
    packets = []
    for index in range(6):
        protocol = "UDP" if index < 5 else "TCP"
        packets.append(
            _packet(
                packet_id=f"dns-{index}",
                session_id=f"dns-session-{index}",
                observed_at=f"2026-06-14T12:00:{index:02d}+00:00",
                protocol=protocol,
                src_ip="10.0.0.15",
                dst_ip="10.0.0.1",
                src_port=53000 + index,
                dst_port=53,
                length=72,
            )
        )
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    candidates = derive_service_candidates(records, conversations)
    summary = build_packet_intelligence_summary(packets=packets)

    dns = next(row for row in candidates if row["service_candidate"] == "dns")
    assert "dns" in {row["protocol"] for row in records}
    assert dns["ports"] == [53]
    assert dns["flow_count"] == 6
    assert {"protocol:dns", "port:53"}.issubset(set(dns["evidence"]))
    assert any(row["service_candidate"] == "dns" for row in summary["metadata"]["service_candidates"])


def test_short_lived_https_burst_is_preserved_as_historical_aggregate():
    packets = [
        _packet(
            packet_id=f"https-burst-{index:02d}",
            session_id=f"https-session-{index:02d}",
            observed_at=f"2026-06-14T12:00:{index % 50:02d}+00:00",
            protocol="TCP",
            src_ip="10.0.0.15",
            src_port=54000 + index,
            dst_ip="198.51.100.44",
            dst_port=443,
            length=60 + index,
        )
        for index in range(50)
    ]
    records = classify_packets(packets)
    conversations = summarize_conversations(packets)
    aggregate = historical_flow_aggregation(conversations, protocol_records=records)
    summary = build_packet_intelligence_summary(packets=packets)

    assert aggregate["connection_count"] == 50
    assert aggregate["unique_flow_count"] == 50
    assert aggregate["active_vs_historical"] == "historical_summary_preserved"
    assert "short_lived_flow_burst" in aggregate["trend_indicators"]
    assert "https_service" in aggregate["service_candidates"]
    assert summary["metadata"]["historical_flow_aggregation"] == aggregate
