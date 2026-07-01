"""Metadata-only packet timeline models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List


EVENT_TYPES = {
    "packet_observed",
    "conversation_started",
    "conversation_updated",
    "conversation_completed",
    "protocol_detected",
    "protocol_changed",
    "session_started",
    "session_updated",
    "session_completed",
    "flow_created",
    "flow_updated",
    "flow_completed",
    "timeline_gap",
    "timeline_merge",
    "unknown",
}

FORBIDDEN_FIELDS = {
    "payload",
    "payload_body",
    "payload_bytes",
    "raw_packet",
    "raw_bytes",
    "packet_bytes",
    "body",
    "content",
}


def stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def stable_id(prefix: str, value: Any, *, length: int = 16) -> str:
    return f"{prefix}-{hashlib.sha256(stable_json(value).encode('utf-8')).hexdigest()[:length]}"


def safe_text(value: Any, default: str = "-") -> str:
    text = " ".join(str(value or "").replace("\n", " ").replace("\r", " ").split())
    return text or default


def safe_int(value: Any, default: int = 0) -> int:
    try:
        parsed = int(value)
    except Exception:
        return default
    return max(parsed, 0)


def safe_float(value: Any, default: float = 0.0) -> float:
    try:
        parsed = float(value)
    except Exception:
        return default
    return max(0.0, min(1.0, parsed))


def safe_metadata(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    result: Dict[str, Any] = {}
    for key in sorted(value):
        if str(key).lower() in FORBIDDEN_FIELDS:
            continue
        item = value[key]
        if isinstance(item, (str, int, float, bool)) or item is None:
            result[str(key)] = item
        elif isinstance(item, (list, tuple)):
            result[str(key)] = [
                entry for entry in item if isinstance(entry, (str, int, float, bool)) or entry is None
            ]
        elif isinstance(item, dict):
            result[str(key)] = safe_metadata(item)
        else:
            result[str(key)] = str(item)
    return result


@dataclass(frozen=True)
class TimelineEvent:
    event_id: str = ""
    timestamp: str = "-"
    event_type: str = "unknown"
    packet_id: str = "-"
    protocol_id: str = "-"
    session_id: str = "-"
    conversation_id: str = "-"
    flow_key: str = "-"
    interface: str = "-"
    protocol: str = "unknown"
    application_protocol: str = "-"
    transport_protocol: str = "-"
    src_ip: str = "-"
    dst_ip: str = "-"
    src_port: int = 0
    dst_port: int = 0
    direction: str = "unknown"
    importance: str = "normal"
    confidence: float = 0.0
    summary: str = "-"
    evidence: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | "TimelineEvent") -> "TimelineEvent":
        if isinstance(data, TimelineEvent):
            return data
        source = {key: value for key, value in dict(data or {}).items() if str(key).lower() not in FORBIDDEN_FIELDS}
        event_type = safe_text(source.get("event_type"), "unknown")
        if event_type not in EVENT_TYPES:
            event_type = "unknown"
        normalized = {
            "timestamp": safe_text(source.get("timestamp")),
            "event_type": event_type,
            "packet_id": safe_text(source.get("packet_id")),
            "protocol_id": safe_text(source.get("protocol_id")),
            "session_id": safe_text(source.get("session_id")),
            "conversation_id": safe_text(source.get("conversation_id")),
            "flow_key": safe_text(source.get("flow_key")),
            "interface": safe_text(source.get("interface")),
            "protocol": safe_text(source.get("protocol"), "unknown"),
            "application_protocol": safe_text(source.get("application_protocol")),
            "transport_protocol": safe_text(source.get("transport_protocol")),
            "src_ip": safe_text(source.get("src_ip")),
            "dst_ip": safe_text(source.get("dst_ip")),
            "src_port": safe_int(source.get("src_port")),
            "dst_port": safe_int(source.get("dst_port")),
            "direction": safe_text(source.get("direction"), "unknown"),
            "importance": safe_text(source.get("importance"), "normal"),
            "confidence": safe_float(source.get("confidence")),
            "summary": safe_text(source.get("summary")),
            "evidence": sorted({safe_text(item) for item in source.get("evidence") or [] if safe_text(item) != "-"}),
            "tags": sorted({safe_text(item) for item in source.get("tags") or [] if safe_text(item) != "-"}),
            "metadata": safe_metadata(source.get("metadata")),
        }
        event_id = safe_text(source.get("event_id"), "")
        if not event_id:
            event_id = stable_id("timeline-event", normalized)
        return cls(event_id=event_id, **normalized)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "packet_id": self.packet_id,
            "protocol_id": self.protocol_id,
            "session_id": self.session_id,
            "conversation_id": self.conversation_id,
            "flow_key": self.flow_key,
            "interface": self.interface,
            "protocol": self.protocol,
            "application_protocol": self.application_protocol,
            "transport_protocol": self.transport_protocol,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "direction": self.direction,
            "importance": self.importance,
            "confidence": round(float(self.confidence), 3),
            "summary": self.summary,
            "evidence": list(self.evidence),
            "tags": list(self.tags),
            "metadata": safe_metadata(self.metadata),
        }


def event_sort_key(event: TimelineEvent | Dict[str, Any]) -> tuple[str, str, str, str]:
    item = TimelineEvent.from_dict(event)
    return (item.timestamp, item.event_type, item.event_id, item.packet_id)
