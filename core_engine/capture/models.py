"""Metadata-only packet capture data models.

This module intentionally models packet metadata only. It must not carry raw
packet bytes or payload body fields.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from typing import Any, Dict, Iterable, List

from core_engine.time_utils import normalize_timestamp as normalize_utc_timestamp


FORBIDDEN_PACKET_FIELDS = {
    "payload",
    "payload_body",
    "payload_bytes",
    "raw_packet",
    "raw_bytes",
    "packet_bytes",
    "body",
    "content",
}

SESSION_STATUSES = {"initialized", "running", "paused", "stopped", "error", "imported"}


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _stable_id(prefix: str, value: Any, *, length: int = 16) -> str:
    digest = hashlib.sha256(_stable_json(value).encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}"


def _safe_text(value: Any, default: str = "-") -> str:
    text = " ".join(str(value or "").replace("\n", " ").replace("\r", " ").split())
    return text or default


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(parsed, 0)


def _safe_metadata(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: Dict[str, Any] = {}
    for key in sorted(value):
        normalized_key = _safe_text(key).lower()
        if normalized_key in FORBIDDEN_PACKET_FIELDS:
            continue
        item = value[key]
        if isinstance(item, (str, int, float, bool)) or item is None:
            result[str(key)] = item
        elif isinstance(item, (list, tuple)):
            result[str(key)] = [
                entry for entry in item if isinstance(entry, (str, int, float, bool)) or entry is None
            ]
        elif isinstance(item, dict):
            result[str(key)] = _safe_metadata(item)
        else:
            result[str(key)] = str(item)
    return result


def normalize_timestamp(value: Any) -> str:
    return normalize_utc_timestamp(value, preserve_ambiguous=True) or "-"


def build_flow_key(
    *,
    protocol: Any = "-",
    src_ip: Any = "-",
    dst_ip: Any = "-",
    src_port: Any = None,
    dst_port: Any = None,
) -> str:
    protocol_text = _safe_text(protocol).lower()
    src = _safe_text(src_ip)
    dst = _safe_text(dst_ip)
    sport = str(_safe_int(src_port, 0)) if src_port not in {"", "-", None} else "-"
    dport = str(_safe_int(dst_port, 0)) if dst_port not in {"", "-", None} else "-"
    return "|".join([protocol_text, src, sport, dst, dport])


@dataclass(frozen=True)
class PacketMetadata:
    packet_id: str = ""
    session_id: str = "-"
    observed_at: str = "-"
    interface: str = "-"
    direction: str = "unknown"
    length: int = 0
    captured_length: int = 0
    link_type: str = "ethernet"
    eth_src: str = "-"
    eth_dst: str = "-"
    ether_type: str = "-"
    ip_version: int = 0
    src_ip: str = "-"
    dst_ip: str = "-"
    ttl: int = 0
    protocol: str = "-"
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: List[str] = field(default_factory=list)
    payload_length: int = 0
    flow_key: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | "PacketMetadata") -> "PacketMetadata":
        if isinstance(data, PacketMetadata):
            return data
        source = dict(data or {})
        for key in list(source):
            if key.lower() in FORBIDDEN_PACKET_FIELDS:
                source.pop(key, None)
        protocol = _safe_text(source.get("protocol")).upper()
        raw_src_port = source.get("src_port")
        raw_dst_port = source.get("dst_port")
        src_port = _safe_int(source.get("src_port"))
        dst_port = _safe_int(source.get("dst_port"))
        flow_key = _safe_text(
            source.get("flow_key"),
            build_flow_key(
                protocol=protocol,
                src_ip=source.get("src_ip"),
                dst_ip=source.get("dst_ip"),
                src_port=raw_src_port,
                dst_port=raw_dst_port,
            ),
        )
        tags = sorted({_safe_text(tag) for tag in source.get("tags") or [] if _safe_text(tag) != "-"})
        tcp_flags = sorted(
            {_safe_text(flag).upper() for flag in source.get("tcp_flags") or [] if _safe_text(flag) != "-"}
        )
        normalized = {
            "session_id": _safe_text(source.get("session_id")),
            "observed_at": normalize_timestamp(source.get("observed_at") or source.get("timestamp")),
            "interface": _safe_text(source.get("interface")),
            "direction": _safe_text(source.get("direction"), "unknown"),
            "length": _safe_int(source.get("length")),
            "captured_length": _safe_int(source.get("captured_length"), _safe_int(source.get("length"))),
            "link_type": _safe_text(source.get("link_type"), "ethernet"),
            "eth_src": _safe_text(source.get("eth_src") or source.get("src_mac")),
            "eth_dst": _safe_text(source.get("eth_dst") or source.get("dst_mac")),
            "ether_type": _safe_text(source.get("ether_type")),
            "ip_version": _safe_int(source.get("ip_version")),
            "src_ip": _safe_text(source.get("src_ip")),
            "dst_ip": _safe_text(source.get("dst_ip")),
            "ttl": _safe_int(source.get("ttl")),
            "protocol": protocol,
            "src_port": src_port,
            "dst_port": dst_port,
            "tcp_flags": tcp_flags,
            "payload_length": _safe_int(source.get("payload_length")),
            "flow_key": flow_key,
            "tags": tags,
            "metadata": _safe_metadata(source.get("metadata")),
        }
        packet_id = _safe_text(source.get("packet_id"), "")
        if not packet_id:
            packet_id = _stable_id("packet", normalized)
        return cls(packet_id=packet_id, **normalized)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "packet_id": self.packet_id,
            "session_id": self.session_id,
            "observed_at": self.observed_at,
            "interface": self.interface,
            "direction": self.direction,
            "length": self.length,
            "captured_length": self.captured_length,
            "link_type": self.link_type,
            "eth_src": self.eth_src,
            "eth_dst": self.eth_dst,
            "ether_type": self.ether_type,
            "ip_version": self.ip_version,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ttl": self.ttl,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": list(self.tcp_flags),
            "payload_length": self.payload_length,
            "flow_key": self.flow_key,
            "tags": list(self.tags),
            "metadata": _safe_metadata(self.metadata),
        }


@dataclass(frozen=True)
class CaptureSession:
    session_id: str = ""
    interface: str = "-"
    adapter: str = "mock"
    status: str = "initialized"
    started_at: str = "-"
    ended_at: str = "-"
    filter_expression: str = "all"
    filter_mode: str = "preset"
    packets_seen: int = 0
    bytes_seen: int = 0
    packets_dropped: int = 0
    capture_path: str = "-"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        interface: str = "-",
        adapter: str = "mock",
        filter_expression: str = "all",
        filter_mode: str = "preset",
        started_at: Any = "-",
        capture_path: Any = "-",
        metadata: Dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> "CaptureSession":
        normalized = {
            "interface": _safe_text(interface),
            "adapter": _safe_text(adapter, "mock"),
            "started_at": normalize_timestamp(started_at),
            "filter_expression": _safe_text(filter_expression, "all"),
            "filter_mode": _safe_text(filter_mode, "preset"),
            "capture_path": _safe_text(capture_path),
            "metadata": _safe_metadata(metadata or {}),
        }
        return cls(session_id=session_id or _stable_id("capture-session", normalized), **normalized)

    def transition(self, status: str, *, at: Any = None, reason: str | None = None) -> "CaptureSession":
        status = _safe_text(status)
        if status not in SESSION_STATUSES:
            return replace(self, status="error", metadata={**self.metadata, "error": "invalid_status"})
        allowed = {
            "initialized": {"running", "stopped", "imported", "error"},
            "running": {"paused", "stopped", "error"},
            "paused": {"running", "stopped", "error"},
            "stopped": set(),
            "error": set(),
            "imported": {"stopped"},
        }
        if status != self.status and status not in allowed.get(self.status, set()):
            return replace(
                self,
                metadata={
                    **self.metadata,
                    "last_transition_rejected": f"{self.status}->{status}",
                    "transition_reason": reason or "invalid_transition",
                },
            )
        timestamp = normalize_timestamp(at) if at is not None else "-"
        updates: Dict[str, Any] = {"status": status}
        if status == "running" and self.started_at == "-":
            updates["started_at"] = timestamp
        if status in {"stopped", "error", "imported"}:
            updates["ended_at"] = timestamp
        if reason:
            updates["metadata"] = {**self.metadata, "transition_reason": reason}
        return replace(self, **updates)

    def add_packets(self, packets: Iterable[PacketMetadata | Dict[str, Any]], *, dropped: int = 0) -> "CaptureSession":
        normalized = [PacketMetadata.from_dict(packet) for packet in packets]
        return replace(
            self,
            packets_seen=self.packets_seen + len(normalized),
            bytes_seen=self.bytes_seen + sum(packet.length for packet in normalized),
            packets_dropped=self.packets_dropped + _safe_int(dropped),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "interface": self.interface,
            "adapter": self.adapter,
            "status": self.status,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "filter_expression": self.filter_expression,
            "filter_mode": self.filter_mode,
            "packets_seen": self.packets_seen,
            "bytes_seen": self.bytes_seen,
            "packets_dropped": self.packets_dropped,
            "capture_path": self.capture_path,
            "metadata": _safe_metadata(self.metadata),
        }


def packet_from_dict(data: Dict[str, Any]) -> PacketMetadata:
    return PacketMetadata.from_dict(data)


def session_from_dict(data: Dict[str, Any]) -> CaptureSession:
    return CaptureSession(
        session_id=_safe_text(data.get("session_id"), ""),
        interface=_safe_text(data.get("interface")),
        adapter=_safe_text(data.get("adapter"), "mock"),
        status=_safe_text(data.get("status"), "initialized"),
        started_at=normalize_timestamp(data.get("started_at")),
        ended_at=normalize_timestamp(data.get("ended_at")),
        filter_expression=_safe_text(data.get("filter_expression"), "all"),
        filter_mode=_safe_text(data.get("filter_mode"), "preset"),
        packets_seen=_safe_int(data.get("packets_seen")),
        bytes_seen=_safe_int(data.get("bytes_seen")),
        packets_dropped=_safe_int(data.get("packets_dropped")),
        capture_path=_safe_text(data.get("capture_path")),
        metadata=_safe_metadata(data.get("metadata")),
    )
