import struct

from core_engine.protocols import classify_protocol, dissect_packet, dissect_payload, extract_transport_payload


def _mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def _ipv4_frame(protocol, transport, payload, src="192.168.1.10", dst="192.168.1.20"):
    ethernet = _mac("aa:bb:cc:dd:ee:ff") + _mac("11:22:33:44:55:66") + b"\x08\x00"
    total_length = 20 + len(transport) + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        protocol,
        0,
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    return ethernet + ipv4 + transport + payload


def _tcp_frame(src_port, dst_port, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, 0x18, 29200, 0, 0)
    return _ipv4_frame(6, tcp, payload)


def _udp_frame(src_port, dst_port, payload=b""):
    udp = struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0)
    return _ipv4_frame(17, udp, payload)


def test_http_dissector_redacts_query_from_path():
    payload = b"GET /login?token=secret HTTP/1.1\r\nHost: example.local\r\nUser-Agent: test\r\n\r\n"

    result = dissect_payload("HTTP", payload)

    assert result["status"] == "ok"
    assert result["protocol"] == "HTTP"
    assert result["fields"]["method"] == "GET"
    assert result["fields"]["path"] == "/login"
    assert result["fields"]["host"] == "example.local"


def test_dns_dissector_extracts_question():
    query = (
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x07example\x05local\x00\x00\x01\x00\x01"
    )

    result = dissect_payload("DNS", query)

    assert result["status"] == "ok"
    assert result["fields"]["transaction_id"] == 0x1234
    assert result["fields"]["query_name"] == "example.local"
    assert result["fields"]["query_type"] == "A"


def test_tls_dissector_extracts_record_header():
    payload = b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"

    result = dissect_payload("TLS", payload)

    assert result["status"] == "ok"
    assert result["fields"]["content_type"] == "handshake"
    assert result["fields"]["record_version"] == "TLS 1.2"
    assert result["fields"]["handshake_type"] == "client_hello"


def test_ssh_smb_and_icmp_dissectors():
    ssh = dissect_payload("SSH", b"SSH-2.0-OpenSSH_9.0\r\n")
    smb = dissect_payload("SMB", b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 8 + b"\x00\x00" + b"\x00\x00")
    icmp = dissect_payload("ICMP", b"\x08\x00\x00\x00", {"protocol": "ICMP"})

    assert ssh["fields"]["software"] == "OpenSSH_9.0"
    assert smb["fields"]["version"] == "SMB2/3"
    assert icmp["fields"]["type_name"] == "echo_request"


def test_dhcp_dissector_extracts_message_type_and_hostname():
    payload = bytearray(240)
    payload[0] = 1
    payload[4:8] = b"\x00\x00\x00\x2a"
    payload[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
    payload[236:240] = b"\x63\x82\x53\x63"
    payload.extend(b"\x35\x01\x01\x0c\x04test\xff")

    result = dissect_payload("DHCP", bytes(payload))

    assert result["status"] == "ok"
    assert result["fields"]["message_type"] == "discover"
    assert result["fields"]["hostname"] == "test"


def test_ftp_and_smtp_redact_sensitive_arguments():
    ftp = dissect_payload("FTP", b"PASS super-secret\r\n")
    smtp = dissect_payload("SMTP", b"AUTH PLAIN abc123\r\n")

    assert ftp["fields"]["argument"] == "<redacted>"
    assert smtp["fields"]["argument"] == "<redacted>"


def test_packet_dispatcher_extracts_payload_and_classifies_http():
    frame = _tcp_frame(51515, 80, b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")

    payload = extract_transport_payload(frame)
    result = dissect_packet(frame)

    assert payload.startswith(b"GET /")
    assert classify_protocol(result["packet"], payload) == "HTTP"
    assert result["protocol"] == "HTTP"
    assert result["fields"]["method"] == "GET"


def test_packet_dispatcher_classifies_dns_from_udp_port():
    frame = _udp_frame(
        5353,
        53,
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03lan\x00\x00\x01\x00\x01",
    )

    result = dissect_packet(frame)

    assert result["protocol"] == "DNS"
    assert result["packet"]["dst_port"] == 53


def test_unknown_protocol_is_labeled_safely():
    result = dissect_payload("madeup", b"secret bytes")

    assert result["status"] == "unknown"
    assert result["protocol"] == "MADEUP"
    assert "secret bytes" not in str(result)
