import struct

from core_engine.modules import packet_capture
from core_engine.modules.packet_capture import CapturePacket, capture_live, extract_packet_metadata, packet_matches_filter
from core_engine.modules.pcap_writer import write_pcap

MAC_A_PARTS = ["aa", "bb", "cc", "dd", "ee", "ff"]
MAC_B_PARTS = ["11", "22", "33", "44", "55", "66"]
MAC_A = ":".join(MAC_A_PARTS)
MAC_B = ":".join(MAC_B_PARTS)


def _mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def _ipv4_tcp_frame(src="203.0.113.10", dst="203.0.113.20", src_port=51515, dst_port=443):
    ethernet = _mac(MAC_A) + _mac(MAC_B) + b"\x08\x00"
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        40,
        1,
        0,
        64,
        6,
        0,
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, 0x12, 29200, 0, 0)
    return ethernet + ipv4 + tcp


def _ipv4_udp_frame(src="203.0.113.10", dst="203.0.113.30", src_port=5353, dst_port=53):
    ethernet = _mac(MAC_A) + _mac(MAC_B) + b"\x08\x00"
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        28,
        1,
        0,
        64,
        17,
        0,
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    udp = struct.pack("!HHHH", src_port, dst_port, 8, 0)
    return ethernet + ipv4 + udp


def test_extract_packet_metadata_for_ipv4_tcp():
    metadata = extract_packet_metadata(CapturePacket(_ipv4_tcp_frame(), timestamp=1000.5, interface="en0"))

    assert metadata["interface"] == "en0"
    assert metadata["timestamp"] == 1000.5
    assert metadata["src_mac"] == MAC_B
    assert metadata["dst_mac"] == MAC_A
    assert metadata["ip_version"] == 4
    assert metadata["ttl"] == 64
    assert metadata["protocol"] == "TCP"
    assert metadata["src_ip"] == "203.0.113.10"
    assert metadata["dst_ip"] == "203.0.113.20"
    assert metadata["src_port"] == 51515
    assert metadata["dst_port"] == 443
    assert metadata["tcp_flags"] == ["SYN", "ACK"]
    assert metadata["tcp_window"] == 29200


def test_extract_packet_metadata_for_ipv4_udp():
    metadata = extract_packet_metadata(_ipv4_udp_frame())

    assert metadata["protocol"] == "UDP"
    assert metadata["src_port"] == 5353
    assert metadata["dst_port"] == 53
    assert metadata["udp_length"] == 8


def test_capture_filters_match_protocol_ports_and_hosts():
    tcp = extract_packet_metadata(_ipv4_tcp_frame())
    udp = extract_packet_metadata(_ipv4_udp_frame())

    assert packet_matches_filter(tcp, "tcp")
    assert packet_matches_filter(tcp, "port 443")
    assert packet_matches_filter(tcp, "dst port 443")
    assert packet_matches_filter(tcp, "host 203.0.113.20")
    assert packet_matches_filter(tcp, "src host 203.0.113.10")
    assert not packet_matches_filter(tcp, "udp")
    assert packet_matches_filter(udp, "udp")


def test_list_and_select_capture_interfaces(monkeypatch):
    monkeypatch.setattr(
        packet_capture.platform_utils,
        "network_interfaces",
        lambda: {
            "lo0": [{"address": "127.0.0.1"}],
            "en0": [{"address": "203.0.113.10"}],
        },
    )

    interfaces = packet_capture.list_capture_interfaces()

    assert [item["name"] for item in interfaces] == ["en0", "lo0"]
    assert packet_capture.select_capture_interface() == "en0"
    assert packet_capture.select_capture_interface("utun1") == "utun1"


def test_write_pcap_creates_classic_pcap_file(tmp_path):
    output = tmp_path / "capture.pcap"

    summary = write_pcap(output, [_ipv4_tcp_frame()])

    assert summary["packets_written"] == 1
    assert summary["payload_bytes"] == len(_ipv4_tcp_frame())
    assert output.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"


def test_capture_live_with_injected_source_and_pcap(tmp_path):
    output = tmp_path / "filtered.pcap"

    def source(interface, duration, max_packets):
        assert interface == "en0"
        assert duration == 0.5
        assert max_packets == 5
        return [
            CapturePacket(_ipv4_udp_frame(), timestamp=1.0, interface=interface),
            CapturePacket(_ipv4_tcp_frame(), timestamp=2.0, interface=interface),
        ]

    result = capture_live(
        interface="en0",
        duration=0.5,
        max_packets=5,
        capture_filter="tcp",
        pcap_path=output,
        packet_source=source,
    )

    assert result["ok"] is True
    assert result["backend"] == "injected"
    assert result["packet_count"] == 1
    assert result["packets"][0]["protocol"] == "TCP"
    assert result["pcap"]["packets_written"] == 1
    assert output.exists()


def test_capture_live_can_attach_protocol_dissection():
    def source(interface, duration, max_packets):
        return [CapturePacket(_ipv4_tcp_frame(dst_port=80) + b"GET /index.html?token=abc HTTP/1.1\r\nHost: local\r\n\r\n")]

    result = capture_live(interface="en0", duration=0.1, max_packets=1, packet_source=source, dissect=True)

    dissection = result["packets"][0]["dissection"]
    assert dissection["protocol"] == "HTTP"
    assert dissection["fields"]["path"] == "/index.html"


def test_capture_live_can_attach_dpi_analysis():
    def source(interface, duration, max_packets):
        return [CapturePacket(_ipv4_tcp_frame(dst_port=80) + b"POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret")]

    result = capture_live(interface="en0", duration=0.1, max_packets=1, packet_source=source, dpi=True)

    dpi = result["packets"][0]["dpi"]
    assert dpi["protocol"] == "HTTP"
    assert any(finding["type"] == "credential_material" for finding in dpi["findings"])
    assert "secret" not in str(dpi)


def test_capture_live_allows_zero_packet_pcap(tmp_path):
    output = tmp_path / "empty.pcap"

    def source(interface, duration, max_packets):
        raise AssertionError("packet source should not be opened for zero-packet captures")

    result = capture_live(duration=0.1, max_packets=0, pcap_path=output, packet_source=source)

    assert result["ok"] is True
    assert result["packet_count"] == 0
    assert result["pcap"]["packets_written"] == 0
    assert output.read_bytes()[:4] == b"\xd4\xc3\xb2\xa1"


def test_capture_live_handles_missing_permissions():
    def source(interface, duration, max_packets):
        raise PermissionError("root required")

    result = capture_live(interface="en0", duration=0.1, max_packets=1, packet_source=source)

    assert result["ok"] is False
    assert result["error"] == "permission_denied"
    assert result["packets"] == []
