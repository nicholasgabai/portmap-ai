import base64
import struct

from core_engine.modules.dpi import (
    analyze_observation,
    analyze_packet,
    detect_malformed_protocol,
    group_sessions,
    payload_metadata,
    redact_text,
    session_key,
    shannon_entropy,
)

MAC_A = ":".join(["aa", "bb", "cc", "dd", "ee", "ff"])
MAC_B = ":".join(["11", "22", "33", "44", "55", "66"])


def _mac(text):
    return bytes(int(part, 16) for part in text.split(":"))


def _ipv4_tcp_frame(src="203.0.113.5", dst="203.0.113.10", src_port=51515, dst_port=80, payload=b""):
    ethernet = _mac(MAC_A) + _mac(MAC_B) + b"\x08\x00"
    total_length = 20 + 20 + len(payload)
    ipv4 = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        1,
        0,
        64,
        6,
        0,
        bytes(int(part) for part in src.split(".")),
        bytes(int(part) for part in dst.split(".")),
    )
    tcp = struct.pack("!HHIIBBHHH", src_port, dst_port, 0, 0, 0x50, 0x18, 29200, 0, 0)
    return ethernet + ipv4 + tcp + payload


def test_payload_metadata_defaults_to_no_payload_preview():
    metadata = payload_metadata(b"password=secret-token")

    assert metadata["length"] == 21
    assert metadata["preview_included"] is False
    assert "preview" not in metadata
    assert metadata["sha256"]


def test_redacted_preview_removes_sensitive_values():
    metadata = payload_metadata(
        b"Authorization: Bearer abc123\r\nemail=alice@example.local&token=secret",
        include_preview=True,
    )

    preview = metadata["preview"]
    assert "abc123" not in preview
    assert "secret" not in preview
    assert "alice@example.local" not in preview
    assert "<redacted>" in preview


def test_analyze_packet_detects_http_sensitive_markers_without_raw_payload():
    frame = _ipv4_tcp_frame(payload=b"POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret")

    result = analyze_packet(frame)

    finding_types = {finding["type"] for finding in result["findings"]}
    assert result["protocol"] == "HTTP"
    assert result["payload"]["preview_included"] is False
    assert "preview" not in result["payload"]
    assert "credential_material" in finding_types
    assert "cleartext_login_flow" in finding_types
    assert "secret" not in str(result)


def test_analyze_observation_accepts_base64_payload_and_redacts_preview():
    payload = b"GET /?token=secret HTTP/1.1\r\nHost: local\r\n\r\n"
    result = analyze_observation(
        {
            "protocol": "HTTP",
            "metadata": {"protocol": "TCP", "src_ip": "203.0.113.5", "dst_ip": "203.0.113.10", "src_port": 51515, "dst_port": 80},
            "payload_b64": base64.b64encode(payload).decode("ascii"),
        },
        include_payload_preview=True,
    )

    assert result["protocol"] == "HTTP"
    assert result["headers"]["application"]["path"] == "/"
    assert "secret" not in str(result)
    assert "<redacted>" in result["payload"]["preview"]


def test_detect_malformed_tls_record_length():
    malformed = {
        "protocol": "TLS",
        "status": "ok",
        "fields": {"record_length": 100},
    }

    findings = detect_malformed_protocol(b"\x16\x03\x03\x00\x64\x01", malformed)

    assert findings[0]["type"] == "truncated_tls_record"
    assert findings[0]["severity"] == "medium"


def test_entropy_marks_high_entropy_payload():
    payload = bytes(range(256)) * 2

    metadata = payload_metadata(payload)
    result = analyze_observation({"protocol": "unknown", "payload_b64": base64.b64encode(payload).decode("ascii")})

    assert shannon_entropy(payload) > 7.5
    assert metadata["category"] == "high_entropy"
    assert any(finding["type"] == "high_entropy_payload" for finding in result["findings"])


def test_session_key_is_bidirectional_and_group_sessions_summarizes():
    left = {"timestamp": 1, "protocol": "TCP", "src_ip": "203.0.113.5", "src_port": 1111, "dst_ip": "203.0.113.10", "dst_port": 80, "payload_bytes": 10}
    right = {"timestamp": 3, "protocol": "TCP", "src_ip": "203.0.113.10", "src_port": 80, "dst_ip": "203.0.113.5", "dst_port": 1111, "payload_bytes": 20}

    assert session_key(left) == session_key(right)
    sessions = group_sessions([left, right])

    assert len(sessions) == 1
    assert sessions[0]["packet_count"] == 2
    assert sessions[0]["total_payload_bytes"] == 30
    assert sessions[0]["duration_seconds"] == 2
