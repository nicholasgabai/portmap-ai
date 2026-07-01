"""Deterministic packet metadata statistics."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List

from .models import CaptureSession, PacketMetadata


def _parse_time(value: str) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _counter_dict(counter: Counter) -> Dict[str, int]:
    return {
        key: counter[key]
        for key in sorted(counter, key=lambda item: (-counter[item], str(item)))
        if str(key) not in {"", "-"}
    }


def summarize_packets(packets: Iterable[PacketMetadata | Dict[str, Any]]) -> Dict[str, Any]:
    normalized = [PacketMetadata.from_dict(packet) for packet in packets]
    packet_count = len(normalized)
    byte_count = sum(packet.length for packet in normalized)
    captured_byte_count = sum(packet.captured_length for packet in normalized)
    protocol_counts = Counter(packet.protocol for packet in normalized)
    interface_counts = Counter(packet.interface for packet in normalized)
    talker_counts = Counter(
        endpoint
        for packet in normalized
        for endpoint in (packet.src_ip, packet.dst_ip)
        if endpoint not in {"", "-"}
    )
    port_counts = Counter(
        str(port)
        for packet in normalized
        for port in (packet.src_port, packet.dst_port)
        if port
    )
    observed = [_parse_time(packet.observed_at) for packet in normalized]
    observed = [value for value in observed if value is not None]
    first = min(observed).isoformat() if observed else "-"
    last = max(observed).isoformat() if observed else "-"
    duration = int((max(observed) - min(observed)).total_seconds()) if len(observed) >= 2 else 0
    return {
        "packet_count": packet_count,
        "byte_count": byte_count,
        "captured_byte_count": captured_byte_count,
        "dropped_count": 0,
        "packets_per_protocol": _counter_dict(protocol_counts),
        "packets_per_interface": _counter_dict(interface_counts),
        "top_talkers": _counter_dict(talker_counts),
        "top_ports": _counter_dict(port_counts),
        "first_observed": first,
        "last_observed": last,
        "duration_seconds": duration,
        "average_packet_size": round(byte_count / packet_count, 2) if packet_count else 0,
        "flow_count": len({packet.flow_key for packet in normalized if packet.flow_key not in {"", "-"}}),
    }


def summarize_session(
    session: CaptureSession,
    packets: Iterable[PacketMetadata | Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    packet_summary = summarize_packets(packets or [])
    return {
        **session.to_dict(),
        "packet_count": packet_summary["packet_count"],
        "byte_count": packet_summary["byte_count"],
        "captured_byte_count": packet_summary["captured_byte_count"],
        "dropped_count": session.packets_dropped,
        "flow_count": packet_summary["flow_count"],
        "statistics": packet_summary,
    }
