from __future__ import annotations

from typing import Any

from core_engine.modules.packet_capture import extract_packet_metadata
from core_engine.protocols import dhcp, dns, ftp, http, icmp, smb, smtp, ssh, tls
from core_engine.protocols.common import failed, unknown


PORT_PROTOCOLS = {
    20: "FTP",
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    139: "SMB",
    143: "IMAP",
    443: "TLS",
    445: "SMB",
    465: "TLS",
    587: "SMTP",
    993: "TLS",
    995: "TLS",
    8443: "TLS",
}

DISSECTORS = {
    "DHCP": dhcp.dissect,
    "DNS": dns.dissect,
    "FTP": ftp.dissect,
    "HTTP": http.dissect,
    "ICMP": icmp.dissect,
    "ICMPv6": icmp.dissect,
    "SMB": smb.dissect,
    "SMTP": smtp.dissect,
    "SSH": ssh.dissect,
    "TLS": tls.dissect,
}


def classify_protocol(metadata: dict[str, Any], payload: bytes = b"") -> str:
    protocol = str(metadata.get("protocol") or "")
    src_port = metadata.get("src_port")
    dst_port = metadata.get("dst_port")
    if protocol in {"ICMP", "ICMPv6", "ARP"}:
        return protocol
    for port in (dst_port, src_port):
        try:
            port_number = int(port)
        except (TypeError, ValueError):
            continue
        if port_number in PORT_PROTOCOLS:
            return PORT_PROTOCOLS[port_number]
    if payload.startswith(b"SSH-"):
        return "SSH"
    if payload.startswith((b"GET ", b"POST ", b"HEAD ", b"HTTP/")):
        return "HTTP"
    if len(payload) >= 5 and payload[0] in {20, 21, 22, 23} and payload[1] == 3:
        return "TLS"
    if payload.startswith((b"\xffSMB", b"\xfeSMB")) or (len(payload) >= 8 and payload[4:8] in {b"\xffSMB", b"\xfeSMB"}):
        return "SMB"
    return "unknown"


def dissect_payload(protocol: str, payload: bytes | bytearray | memoryview, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    selected = protocol.upper() if protocol.lower() != "icmpv6" else "ICMPv6"
    dissector = DISSECTORS.get(selected)
    if not dissector:
        return unknown(selected, reason="unsupported_protocol", payload=bytes(payload))
    try:
        return dissector(bytes(payload), metadata or {})
    except Exception as exc:
        return failed(selected, error=str(exc), payload=bytes(payload))


def dissect_packet(packet: bytes | bytearray | memoryview, *, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    raw = bytes(packet)
    packet_metadata = dict(metadata or extract_packet_metadata(raw))
    payload = extract_transport_payload(raw, packet_metadata)
    protocol = classify_protocol(packet_metadata, payload)
    result = dissect_payload(protocol, payload, packet_metadata) if protocol != "ARP" else unknown("ARP", reason="arp_has_no_transport_payload", payload=b"")
    result["packet"] = {
        "protocol": packet_metadata.get("protocol"),
        "src_ip": packet_metadata.get("src_ip"),
        "dst_ip": packet_metadata.get("dst_ip"),
        "src_port": packet_metadata.get("src_port"),
        "dst_port": packet_metadata.get("dst_port"),
        "payload_bytes": len(payload),
    }
    return result


def extract_transport_payload(packet: bytes | bytearray | memoryview, metadata: dict[str, Any] | None = None) -> bytes:
    raw = bytes(packet)
    if len(raw) < 14:
        return b""
    ethertype = int.from_bytes(raw[12:14], "big")
    offset = 14
    if ethertype == 0x8100 and len(raw) >= 18:
        ethertype = int.from_bytes(raw[16:18], "big")
        offset = 18
    if ethertype == 0x0800:
        return _ipv4_payload(raw, offset)
    if ethertype == 0x86DD:
        return _ipv6_payload(raw, offset)
    return b""


def _ipv4_payload(raw: bytes, offset: int) -> bytes:
    if len(raw) < offset + 20:
        return b""
    ihl = (raw[offset] & 0x0F) * 4
    protocol = raw[offset + 9]
    transport_offset = offset + ihl
    if protocol == 6:
        if len(raw) < transport_offset + 20:
            return b""
        data_offset = (raw[transport_offset + 12] >> 4) * 4
        return raw[transport_offset + data_offset :]
    if protocol == 17:
        if len(raw) < transport_offset + 8:
            return b""
        return raw[transport_offset + 8 :]
    if protocol == 1:
        return raw[transport_offset:]
    return b""


def _ipv6_payload(raw: bytes, offset: int) -> bytes:
    if len(raw) < offset + 40:
        return b""
    next_header = raw[offset + 6]
    transport_offset = offset + 40
    if next_header == 6:
        if len(raw) < transport_offset + 20:
            return b""
        data_offset = (raw[transport_offset + 12] >> 4) * 4
        return raw[transport_offset + data_offset :]
    if next_header == 17:
        if len(raw) < transport_offset + 8:
            return b""
        return raw[transport_offset + 8 :]
    if next_header == 58:
        return raw[transport_offset:]
    return b""


__all__ = [
    "classify_protocol",
    "dissect_packet",
    "dissect_payload",
    "extract_transport_payload",
]
