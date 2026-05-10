from __future__ import annotations

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

from core_engine import platform_utils
from core_engine.modules.pcap_writer import LINKTYPE_ETHERNET, PcapPacket, write_pcap


DEFAULT_CAPTURE_DURATION = 5.0
DEFAULT_MAX_PACKETS = 100
DEFAULT_BUFFER_SIZE = 65535
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD
IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


class CaptureUnavailable(RuntimeError):
    """Raised when this platform cannot perform stdlib live packet capture."""


@dataclass(frozen=True)
class CapturePacket:
    data: bytes
    timestamp: float = field(default_factory=time.time)
    interface: str | None = None
    linktype: int = LINKTYPE_ETHERNET
    original_length: int | None = None


PacketSource = Callable[[str | None, float, int], Iterable[bytes | bytearray | memoryview | CapturePacket]]


def _format_mac(data: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in data)


def _u16(data: bytes, offset: int) -> int:
    return int.from_bytes(data[offset : offset + 2], "big")


def _tcp_flags(value: int) -> list[str]:
    flags = [
        ("FIN", 0x01),
        ("SYN", 0x02),
        ("RST", 0x04),
        ("PSH", 0x08),
        ("ACK", 0x10),
        ("URG", 0x20),
        ("ECE", 0x40),
        ("CWR", 0x80),
    ]
    return [name for name, bit in flags if value & bit]


def _base_metadata(packet: bytes, *, interface: str | None = None, timestamp: float | None = None) -> dict[str, Any]:
    return {
        "timestamp": timestamp if timestamp is not None else time.time(),
        "interface": interface,
        "captured_len": len(packet),
        "original_len": len(packet),
        "linktype": LINKTYPE_ETHERNET,
        "protocol": "unknown",
        "protocol_number": None,
        "src_mac": "",
        "dst_mac": "",
        "src_ip": "",
        "dst_ip": "",
        "src_port": None,
        "dst_port": None,
        "payload_bytes": 0,
        "reason": "parsed",
    }


def extract_packet_metadata(
    packet: bytes | bytearray | memoryview | CapturePacket,
    *,
    interface: str | None = None,
    timestamp: float | None = None,
) -> dict[str, Any]:
    """Extract safe packet metadata without retaining payload contents."""
    if isinstance(packet, CapturePacket):
        raw = bytes(packet.data)
        interface = interface or packet.interface
        timestamp = packet.timestamp
    else:
        raw = bytes(packet)
    metadata = _base_metadata(raw, interface=interface, timestamp=timestamp)
    if len(raw) < 14:
        metadata["reason"] = "frame_too_short"
        return metadata

    metadata["dst_mac"] = _format_mac(raw[0:6])
    metadata["src_mac"] = _format_mac(raw[6:12])
    ethertype = _u16(raw, 12)
    offset = 14
    if ethertype == 0x8100 and len(raw) >= 18:
        metadata["vlan_id"] = _u16(raw, 14) & 0x0FFF
        ethertype = _u16(raw, 16)
        offset = 18
    metadata["ethertype"] = f"0x{ethertype:04x}"

    if ethertype == ETHERTYPE_ARP:
        metadata["protocol"] = "ARP"
        return metadata
    if ethertype == ETHERTYPE_IPV4:
        return _extract_ipv4_metadata(raw, offset, metadata)
    if ethertype == ETHERTYPE_IPV6:
        return _extract_ipv6_metadata(raw, offset, metadata)

    metadata["reason"] = "unsupported_ethertype"
    return metadata


def _extract_ipv4_metadata(raw: bytes, offset: int, metadata: dict[str, Any]) -> dict[str, Any]:
    if len(raw) < offset + 20:
        metadata["reason"] = "ipv4_header_too_short"
        return metadata
    version = raw[offset] >> 4
    ihl = (raw[offset] & 0x0F) * 4
    if version != 4 or ihl < 20 or len(raw) < offset + ihl:
        metadata["reason"] = "invalid_ipv4_header"
        return metadata
    total_length = _u16(raw, offset + 2) or max(len(raw) - offset, 0)
    protocol_number = raw[offset + 9]
    protocol = IP_PROTOCOLS.get(protocol_number, str(protocol_number))
    metadata.update(
        {
            "ip_version": 4,
            "ttl": raw[offset + 8],
            "protocol": protocol,
            "protocol_number": protocol_number,
            "src_ip": str(ipaddress.IPv4Address(raw[offset + 12 : offset + 16])),
            "dst_ip": str(ipaddress.IPv4Address(raw[offset + 16 : offset + 20])),
        }
    )
    transport_offset = offset + ihl
    transport_length = max(total_length - ihl, 0)
    return _extract_transport_metadata(raw, transport_offset, transport_length, metadata)


def _extract_ipv6_metadata(raw: bytes, offset: int, metadata: dict[str, Any]) -> dict[str, Any]:
    if len(raw) < offset + 40:
        metadata["reason"] = "ipv6_header_too_short"
        return metadata
    version = raw[offset] >> 4
    if version != 6:
        metadata["reason"] = "invalid_ipv6_header"
        return metadata
    payload_length = _u16(raw, offset + 4)
    protocol_number = raw[offset + 6]
    protocol = IP_PROTOCOLS.get(protocol_number, str(protocol_number))
    metadata.update(
        {
            "ip_version": 6,
            "hop_limit": raw[offset + 7],
            "protocol": protocol,
            "protocol_number": protocol_number,
            "src_ip": str(ipaddress.IPv6Address(raw[offset + 8 : offset + 24])),
            "dst_ip": str(ipaddress.IPv6Address(raw[offset + 24 : offset + 40])),
        }
    )
    return _extract_transport_metadata(raw, offset + 40, payload_length, metadata)


def _extract_transport_metadata(
    raw: bytes,
    offset: int,
    transport_length: int,
    metadata: dict[str, Any],
) -> dict[str, Any]:
    protocol = metadata.get("protocol")
    if protocol == "TCP":
        if len(raw) < offset + 20:
            metadata["reason"] = "tcp_header_too_short"
            return metadata
        data_offset = (raw[offset + 12] >> 4) * 4
        metadata.update(
            {
                "src_port": _u16(raw, offset),
                "dst_port": _u16(raw, offset + 2),
                "tcp_flags": _tcp_flags(raw[offset + 13]),
                "tcp_window": _u16(raw, offset + 14),
                "payload_bytes": max(int(transport_length) - data_offset, 0),
            }
        )
    elif protocol == "UDP":
        if len(raw) < offset + 8:
            metadata["reason"] = "udp_header_too_short"
            return metadata
        udp_length = _u16(raw, offset + 4)
        metadata.update(
            {
                "src_port": _u16(raw, offset),
                "dst_port": _u16(raw, offset + 2),
                "udp_length": udp_length,
                "payload_bytes": max(udp_length - 8, 0),
            }
        )
    elif protocol in {"ICMP", "ICMPv6"}:
        if len(raw) >= offset + 2:
            metadata.update({"icmp_type": raw[offset], "icmp_code": raw[offset + 1]})
    return metadata


def list_capture_interfaces() -> list[dict[str, Any]]:
    interfaces: list[dict[str, Any]] = []
    for name, addrs in platform_utils.network_interfaces().items():
        addresses = [str(item.get("address")) for item in addrs if item.get("address")]
        interfaces.append(
            {
                "name": name,
                "addresses": addresses,
                "loopback": any(address.startswith(("127.", "::1")) for address in addresses),
            }
        )
    return sorted(interfaces, key=lambda item: (bool(item["loopback"]), str(item["name"])))


def select_capture_interface(name: str | None = None) -> str | None:
    if name:
        return name
    interfaces = list_capture_interfaces()
    if not interfaces:
        return None
    return str(interfaces[0]["name"])


def packet_matches_filter(metadata: dict[str, Any], capture_filter: str | None = None) -> bool:
    if not capture_filter or not capture_filter.strip():
        return True
    parts = capture_filter.strip().lower().split()
    protocol = str(metadata.get("protocol") or "").lower()
    ip_version = metadata.get("ip_version")
    src_ip = str(metadata.get("src_ip") or "").lower()
    dst_ip = str(metadata.get("dst_ip") or "").lower()
    src_port = metadata.get("src_port")
    dst_port = metadata.get("dst_port")

    if len(parts) == 1:
        token = parts[0]
        if token in {"tcp", "udp", "icmp", "arp"}:
            return protocol == token
        if token == "ip":
            return ip_version == 4
        if token in {"ip6", "ipv6"}:
            return ip_version == 6
    if len(parts) == 2 and parts[0] == "port":
        port = int(parts[1])
        return src_port == port or dst_port == port
    if len(parts) == 2 and parts[0] == "host":
        host = parts[1]
        return src_ip == host or dst_ip == host
    if len(parts) == 3 and parts[0] in {"src", "dst"} and parts[1] == "port":
        port = int(parts[2])
        return (src_port if parts[0] == "src" else dst_port) == port
    if len(parts) == 3 and parts[0] in {"src", "dst"} and parts[1] == "host":
        host = parts[2]
        return (src_ip if parts[0] == "src" else dst_ip) == host
    raise ValueError("unsupported capture filter; use tcp, udp, icmp, arp, ip, ipv6, host IP, port N, src/dst host IP, or src/dst port N")


def _linux_packet_source(interface: str | None, duration: float, max_packets: int) -> Iterator[bytes]:
    platform = platform_utils.get_platform_info()
    if not platform.is_linux or not hasattr(socket, "AF_PACKET"):
        raise CaptureUnavailable("stdlib live packet capture is currently available only through Linux AF_PACKET")
    proto_all = 0x0003
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(proto_all))
    try:
        if interface:
            sock.bind((interface, 0))
        sock.settimeout(min(max(duration, 0.01), 0.25))
        deadline = time.monotonic() + duration
        captured = 0
        while captured < max_packets and time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(DEFAULT_BUFFER_SIZE)
            except socket.timeout:
                continue
            captured += 1
            yield data
    finally:
        sock.close()


def _coerce_capture_packet(raw: bytes | bytearray | memoryview | CapturePacket, interface: str | None) -> CapturePacket:
    if isinstance(raw, CapturePacket):
        return raw
    return CapturePacket(data=bytes(raw), interface=interface)


def capture_live(
    *,
    interface: str | None = None,
    duration: float = DEFAULT_CAPTURE_DURATION,
    max_packets: int = DEFAULT_MAX_PACKETS,
    capture_filter: str | None = None,
    pcap_path: str | Path | None = None,
    packet_source: PacketSource | None = None,
    dissect: bool = False,
    dpi: bool = False,
    flows: bool = False,
) -> dict[str, Any]:
    """Capture packet metadata and optionally write filtered packets to PCAP."""
    if duration <= 0:
        raise ValueError("capture duration must be greater than 0")
    if max_packets < 0:
        raise ValueError("max_packets must be 0 or greater")
    selected_interface = select_capture_interface(interface)
    source = packet_source or _linux_packet_source
    backend = "injected" if packet_source else "linux_af_packet"
    rows: list[dict[str, Any]] = []
    pcap_packets: list[PcapPacket] = []
    started = time.time()

    if max_packets == 0:
        pcap_summary = write_pcap(pcap_path, []) if pcap_path else None
        result = {
            "ok": True,
            "interface": selected_interface,
            "backend": backend,
            "duration": float(duration),
            "elapsed_seconds": round(time.time() - started, 3),
            "packet_count": 0,
            "packets": [],
            "pcap": pcap_summary,
            "warnings": [],
        }
        if flows:
            from core_engine.modules.flow_tracker import build_flow_report

            result["flows"] = build_flow_report([])
        return result

    try:
        for raw_packet in source(selected_interface, float(duration), int(max_packets)):
            packet = _coerce_capture_packet(raw_packet, selected_interface)
            metadata = extract_packet_metadata(packet, interface=packet.interface)
            if not packet_matches_filter(metadata, capture_filter):
                continue
            if dissect:
                from core_engine.protocols import dissect_packet

                metadata["dissection"] = dissect_packet(packet.data, metadata=metadata)
            if dpi:
                from core_engine.modules.dpi import analyze_packet

                metadata["dpi"] = analyze_packet(
                    packet.data,
                    metadata=metadata,
                    dissection=metadata.get("dissection"),
                )
            metadata["packet_number"] = len(rows) + 1
            rows.append(metadata)
            pcap_packets.append(
                PcapPacket(
                    data=packet.data,
                    timestamp=packet.timestamp,
                    original_length=packet.original_length or len(packet.data),
                )
            )
            if len(rows) >= max_packets:
                break
    except PermissionError as exc:
        return _capture_error("permission_denied", str(exc), selected_interface, backend, started)
    except CaptureUnavailable as exc:
        return _capture_error("unsupported_capture_backend", str(exc), selected_interface, backend, started)
    except OSError as exc:
        if exc.errno in {1, 13}:
            return _capture_error("permission_denied", str(exc), selected_interface, backend, started)
        return _capture_error("capture_failed", str(exc), selected_interface, backend, started)

    pcap_summary = write_pcap(pcap_path, pcap_packets) if pcap_path else None
    result = {
        "ok": True,
        "interface": selected_interface,
        "backend": backend,
        "duration": float(duration),
        "elapsed_seconds": round(time.time() - started, 3),
        "packet_count": len(rows),
        "packets": rows,
        "pcap": pcap_summary,
        "warnings": [],
    }
    if flows:
        from core_engine.modules.flow_tracker import build_flow_report

        result["flows"] = build_flow_report(rows)
    return result


def _capture_error(error: str, reason: str, interface: str | None, backend: str, started: float) -> dict[str, Any]:
    return {
        "ok": False,
        "error": error,
        "reason": reason,
        "interface": interface,
        "backend": backend,
        "elapsed_seconds": round(time.time() - started, 3),
        "packet_count": 0,
        "packets": [],
        "pcap": None,
    }


__all__ = [
    "CapturePacket",
    "CaptureUnavailable",
    "PacketSource",
    "capture_live",
    "extract_packet_metadata",
    "list_capture_interfaces",
    "packet_matches_filter",
    "select_capture_interface",
]
