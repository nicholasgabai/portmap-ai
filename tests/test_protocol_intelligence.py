import json
import socket

import pytest

from core_engine.capture import PacketMetadata
from core_engine.protocols import (
    classify_packet_metadata_protocol,
    classify_packets,
    protocol_intelligence_summary,
    summarize_conversations,
)


def _packet(**overrides):
    data = {
        "packet_id": "packet-test",
        "session_id": "session-test",
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


def _record(**overrides):
    return classify_packet_metadata_protocol(_packet(**overrides)).to_dict()


def test_tcp_detection_from_metadata():
    record = _record(packet_id="tcp", dst_port=9443)

    assert record["protocol"] == "tcp"
    assert record["protocol_family"] == "tcp"
    assert record["transport_protocol"] == "tcp"
    assert record["application_protocol"] == "-"
    assert record["detection_method"] == "protocol_field"
    assert "protocol:tcp" in record["evidence"]


def test_udp_detection_from_metadata():
    record = _record(packet_id="udp", protocol="UDP", src_port=53000, dst_port=53001)

    assert record["protocol"] == "udp"
    assert record["protocol_family"] == "udp"
    assert record["transport_protocol"] == "udp"


@pytest.mark.parametrize(
    ("port", "expected"),
    [
        (53, "dns"),
        (80, "http"),
        (443, "https"),
        (22, "ssh"),
        (445, "smb"),
    ],
)
def test_application_protocol_detection_by_port(port, expected):
    record = _record(packet_id=f"port-{port}", dst_port=port)

    assert record["protocol"] == expected
    assert record["protocol_family"] == expected
    assert record["application_protocol"] == expected
    assert record["transport_protocol"] == "tcp"
    assert f"port:{port}" in record["evidence"]
    assert 0 <= record["confidence"] <= 1


def test_tls_detection_by_metadata_tag():
    record = _record(packet_id="tls", dst_port=4443, tags=["fixture", "tls"])

    assert record["protocol"] == "tls"
    assert record["protocol_family"] == "tls"
    assert record["application_protocol"] == "tls"
    assert "tag:tls" in record["evidence"]


def test_icmp_detection_from_protocol_field():
    record = _record(packet_id="icmp", protocol="ICMP", src_port=0, dst_port=0)

    assert record["protocol"] == "icmp"
    assert record["protocol_family"] == "icmp"
    assert record["transport_protocol"] == "icmp"


def test_arp_detection_from_ether_type():
    record = _record(
        packet_id="arp",
        protocol="-",
        ether_type="0x0806",
        ip_version=0,
        src_ip="-",
        dst_ip="-",
        src_port=0,
        dst_port=0,
    )

    assert record["protocol"] == "arp"
    assert record["protocol_family"] == "arp"
    assert record["detection_method"] == "ether_type"


def test_ipv4_ipv6_and_ethernet_fallbacks():
    ipv4 = _record(packet_id="ipv4", protocol="-", ip_version=4, src_port=0, dst_port=0)
    ipv6 = _record(packet_id="ipv6", protocol="-", ip_version=6, ether_type="0x86DD", src_port=0, dst_port=0)
    ethernet = _record(
        packet_id="ethernet",
        protocol="-",
        ip_version=0,
        ether_type="-",
        src_ip="-",
        dst_ip="-",
        src_port=0,
        dst_port=0,
    )

    assert ipv4["protocol"] == "ipv4"
    assert ipv6["protocol"] == "ipv6"
    assert ethernet["protocol"] == "ethernet"


def test_unknown_protocol_fallback():
    record = classify_packet_metadata_protocol({}).to_dict()

    assert record["protocol"] == "unknown"
    assert record["protocol_family"] == "unknown"
    assert record["confidence"] == 0.2
    assert record["evidence"] == ["insufficient_metadata"]


def test_protocol_ids_are_deterministic_and_json_safe():
    first = classify_packet_metadata_protocol(_packet(packet_id="", dst_port=53)).to_dict()
    second = classify_packet_metadata_protocol(dict(reversed(list(_packet(packet_id="", dst_port=53).items())))).to_dict()

    assert first["protocol_id"] == second["protocol_id"]
    json.dumps(first, sort_keys=True)
    rendered = json.dumps(first, sort_keys=True)
    assert "payload_body" not in rendered
    assert "raw_bytes" not in rendered


def test_protocol_output_order_is_deterministic():
    packets = [
        _packet(packet_id="b", observed_at="2026-06-14T12:00:02+00:00", dst_port=80),
        _packet(packet_id="a", observed_at="2026-06-14T12:00:01+00:00", dst_port=53, protocol="UDP"),
    ]

    first = classify_packets(packets)
    second = classify_packets(list(reversed(packets)))

    assert first == second
    assert [record["protocol"] for record in first] == ["dns", "http"]


def test_conversation_grouping_and_summary_fields():
    packets = [
        _packet(packet_id="a", observed_at="2026-06-14T12:00:00+00:00", dst_port=443, length=60),
        _packet(packet_id="b", observed_at="2026-06-14T12:00:03+00:00", dst_port=443, length=70),
        _packet(packet_id="c", observed_at="2026-06-14T12:00:01+00:00", dst_port=53, protocol="UDP", length=80),
    ]

    conversations = summarize_conversations(packets)

    assert len(conversations) == 2
    https = next(row for row in conversations if row["protocol"] == "https")
    assert https["packet_count"] == 2
    assert https["byte_count"] == 130
    assert https["src_ip"] == "192.168.1.10"
    assert https["dst_port"] == 443
    assert https["direction"] == "outbound"
    assert "port:443" in https["evidence_summary"]
    assert https["conversation_id"].startswith("conversation-")


def test_empty_input_returns_safe_empty_summaries():
    assert classify_packets([]) == []
    assert summarize_conversations([]) == []
    assert protocol_intelligence_summary([]) == {
        "protocol_record_count": 0,
        "conversation_count": 0,
        "protocols": [],
        "records": [],
        "conversations": [],
    }


def test_protocol_summary_is_json_safe_and_contains_records():
    summary = protocol_intelligence_summary([_packet(packet_id="dns", protocol="UDP", dst_port=53)])

    assert summary["protocol_record_count"] == 1
    assert summary["conversation_count"] == 1
    assert summary["protocols"] == ["dns"]
    assert summary["records"][0]["protocol"] == "dns"
    json.dumps(summary, sort_keys=True)


def test_no_payload_fields_are_exposed_from_metadata():
    packet = _packet(
        packet_id="payload-safety",
        metadata={"payload": "secret", "payload_body": "hidden", "safe": "yes"},
        payload="do-not-copy",
        raw_bytes=b"abc",
    )

    record = classify_packet_metadata_protocol(packet).to_dict()

    assert record["metadata"] == {"ip_version": 4, "ether_type": "0x0800", "tcp_flags": "SYN", "safe": "yes"}
    rendered = json.dumps(record, sort_keys=True)
    assert "secret" not in rendered
    assert "hidden" not in rendered
    assert "do-not-copy" not in rendered


def test_no_network_calls(monkeypatch):
    def fail(*args, **kwargs):
        raise AssertionError("network access is not allowed")

    monkeypatch.setattr(socket, "socket", fail)

    record = classify_packet_metadata_protocol(_packet(packet_id="network-safe")).to_dict()

    assert record["protocol"] == "https"


def test_caller_packet_dictionary_is_not_mutated():
    source = _packet(packet_id="immutability", tags=["tls"], metadata={"safe": "yes"})
    original = json.loads(json.dumps(source))

    classify_packet_metadata_protocol(source)

    assert source == original


def test_packet_metadata_instances_are_supported():
    packet = PacketMetadata.from_dict(_packet(packet_id="instance", dst_port=22))

    record = classify_packet_metadata_protocol(packet).to_dict()

    assert record["packet_id"] == packet.packet_id
    assert record["protocol"] == "ssh"
