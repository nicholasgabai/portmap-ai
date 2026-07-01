"""Reusable packet visualization data models.

These models describe what packet metadata visualizations should contain. They
do not render charts, graphics, widgets, HTML, SVG, or GUI components.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List


FORBIDDEN_VISUALIZATION_FIELDS = {
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
        normalized_key = safe_text(key).lower()
        if normalized_key in FORBIDDEN_VISUALIZATION_FIELDS:
            continue
        item = value[key]
        if isinstance(item, (str, int, float, bool)) or item is None:
            result[str(key)] = item
        elif isinstance(item, (list, tuple)):
            safe_items = []
            for entry in item:
                if isinstance(entry, (str, int, float, bool)) or entry is None:
                    safe_items.append(entry)
                elif isinstance(entry, dict):
                    safe_items.append(safe_metadata(entry))
                else:
                    safe_items.append(str(entry))
            result[str(key)] = safe_items
        elif isinstance(item, dict):
            result[str(key)] = safe_metadata(item)
        else:
            result[str(key)] = str(item)
    return result


@dataclass(frozen=True)
class TimelineLane:
    lane_id: str
    label: str
    events: List[Dict[str, Any]] = field(default_factory=list)
    first_seen: str = "-"
    last_seen: str = "-"
    event_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "lane_id": self.lane_id,
            "label": self.label,
            "events": [safe_metadata(event) for event in self.events],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "event_count": self.event_count,
        }


@dataclass(frozen=True)
class TimelineModel:
    timeline_id: str
    start_time: str = "-"
    end_time: str = "-"
    duration: int = 0
    event_count: int = 0
    lane_count: int = 0
    events: List[Dict[str, Any]] = field(default_factory=list)
    summaries: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)
    lanes: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeline_id": self.timeline_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "duration": self.duration,
            "event_count": self.event_count,
            "lane_count": self.lane_count,
            "events": [safe_metadata(event) for event in self.events],
            "summaries": safe_metadata(self.summaries),
            "statistics": safe_metadata(self.statistics),
            "lanes": [safe_metadata(lane) for lane in self.lanes],
        }


@dataclass(frozen=True)
class HostGraph:
    graph_id: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    host_count: int = 0
    edge_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "nodes": [safe_metadata(node) for node in self.nodes],
            "edges": [safe_metadata(edge) for edge in self.edges],
            "host_count": self.host_count,
            "edge_count": self.edge_count,
        }


@dataclass(frozen=True)
class FlowGraph:
    graph_id: str
    edges: List[Dict[str, Any]] = field(default_factory=list)
    flow_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "edges": [safe_metadata(edge) for edge in self.edges],
            "flow_count": self.flow_count,
        }


@dataclass(frozen=True)
class ConversationGraph:
    graph_id: str
    nodes: List[Dict[str, Any]] = field(default_factory=list)
    edges: List[Dict[str, Any]] = field(default_factory=list)
    conversation_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "nodes": [safe_metadata(node) for node in self.nodes],
            "edges": [safe_metadata(edge) for edge in self.edges],
            "conversation_count": self.conversation_count,
        }


@dataclass(frozen=True)
class ProtocolDistribution:
    distribution_id: str
    protocols: List[Dict[str, Any]] = field(default_factory=list)
    total_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "distribution_id": self.distribution_id,
            "protocols": [safe_metadata(row) for row in self.protocols],
            "total_count": self.total_count,
        }


@dataclass(frozen=True)
class PortDistribution:
    distribution_id: str
    ports: List[Dict[str, Any]] = field(default_factory=list)
    total_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "distribution_id": self.distribution_id,
            "ports": [safe_metadata(row) for row in self.ports],
            "total_count": self.total_count,
        }


@dataclass(frozen=True)
class BandwidthModel:
    bandwidth_id: str
    total_bytes: int = 0
    by_host: List[Dict[str, Any]] = field(default_factory=list)
    by_protocol: List[Dict[str, Any]] = field(default_factory=list)
    by_flow: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bandwidth_id": self.bandwidth_id,
            "total_bytes": self.total_bytes,
            "by_host": [safe_metadata(row) for row in self.by_host],
            "by_protocol": [safe_metadata(row) for row in self.by_protocol],
            "by_flow": [safe_metadata(row) for row in self.by_flow],
        }


@dataclass(frozen=True)
class ActivityHeatmap:
    heatmap_id: str
    granularity: str
    buckets: List[Dict[str, Any]] = field(default_factory=list)
    bucket_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "heatmap_id": self.heatmap_id,
            "granularity": self.granularity,
            "buckets": [safe_metadata(row) for row in self.buckets],
            "bucket_count": self.bucket_count,
        }


@dataclass(frozen=True)
class CommunicationMatrix:
    matrix_id: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    host_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "matrix_id": self.matrix_id,
            "rows": [safe_metadata(row) for row in self.rows],
            "host_count": self.host_count,
        }


@dataclass(frozen=True)
class TopTalkerModel:
    model_id: str
    talkers: List[Dict[str, Any]] = field(default_factory=list)
    host_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "talkers": [safe_metadata(row) for row in self.talkers],
            "host_count": self.host_count,
        }


@dataclass(frozen=True)
class SessionVisualization:
    session_id: str
    packet_count: int = 0
    byte_count: int = 0
    first_seen: str = "-"
    last_seen: str = "-"
    protocols: List[str] = field(default_factory=list)
    conversations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "protocols": list(self.protocols),
            "conversations": list(self.conversations),
        }


@dataclass(frozen=True)
class ConversationVisualization:
    conversation_id: str
    protocol: str = "unknown"
    participants: List[str] = field(default_factory=list)
    start: str = "-"
    end: str = "-"
    summary: str = "-"
    packet_count: int = 0
    byte_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "conversation_id": self.conversation_id,
            "protocol": self.protocol,
            "participants": list(self.participants),
            "start": self.start,
            "end": self.end,
            "summary": self.summary,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
        }


@dataclass(frozen=True)
class NetworkSnapshot:
    snapshot_id: str
    timestamp: str = "-"
    host_count: int = 0
    conversation_count: int = 0
    flow_count: int = 0
    session_count: int = 0
    protocol_distribution: Dict[str, Any] = field(default_factory=dict)
    top_talkers: Dict[str, Any] = field(default_factory=dict)
    timeline_summary: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "timestamp": self.timestamp,
            "host_count": self.host_count,
            "conversation_count": self.conversation_count,
            "flow_count": self.flow_count,
            "session_count": self.session_count,
            "protocol_distribution": safe_metadata(self.protocol_distribution),
            "top_talkers": safe_metadata(self.top_talkers),
            "timeline_summary": safe_metadata(self.timeline_summary),
            "statistics": safe_metadata(self.statistics),
        }
