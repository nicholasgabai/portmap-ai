"""Packet intelligence integration models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List


FORBIDDEN_PACKET_INTELLIGENCE_FIELDS = {
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
        if normalized_key in FORBIDDEN_PACKET_INTELLIGENCE_FIELDS:
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
class PacketIntelligenceSummary:
    summary_id: str
    generated_at: str = "-"
    packet_count: int = 0
    protocol_count: int = 0
    conversation_count: int = 0
    flow_count: int = 0
    timeline_event_count: int = 0
    hunt_result_count: int = 0
    top_protocol: str = "-"
    top_talker: str = "-"
    top_conversation: str = "-"
    top_flow: str = "-"
    protocol_distribution: Dict[str, Any] = field(default_factory=dict)
    port_distribution: Dict[str, Any] = field(default_factory=dict)
    traffic_direction_summary: Dict[str, Any] = field(default_factory=dict)
    packet_activity_summary: Dict[str, Any] = field(default_factory=dict)
    hunting_summary: Dict[str, Any] = field(default_factory=dict)
    timeline_summary: Dict[str, Any] = field(default_factory=dict)
    visualization_summary: Dict[str, Any] = field(default_factory=dict)
    risk_relevant_signals: List[str] = field(default_factory=list)
    attribution_hints: List[str] = field(default_factory=list)
    behavior_graph_hints: List[str] = field(default_factory=list)
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    operator_summary: str = "-"
    operator_next_steps: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary_id": self.summary_id,
            "generated_at": self.generated_at,
            "packet_count": self.packet_count,
            "protocol_count": self.protocol_count,
            "conversation_count": self.conversation_count,
            "flow_count": self.flow_count,
            "timeline_event_count": self.timeline_event_count,
            "hunt_result_count": self.hunt_result_count,
            "top_protocol": self.top_protocol,
            "top_talker": self.top_talker,
            "top_conversation": self.top_conversation,
            "top_flow": self.top_flow,
            "protocol_distribution": safe_metadata(self.protocol_distribution),
            "port_distribution": safe_metadata(self.port_distribution),
            "traffic_direction_summary": safe_metadata(self.traffic_direction_summary),
            "packet_activity_summary": safe_metadata(self.packet_activity_summary),
            "hunting_summary": safe_metadata(self.hunting_summary),
            "timeline_summary": safe_metadata(self.timeline_summary),
            "visualization_summary": safe_metadata(self.visualization_summary),
            "risk_relevant_signals": list(self.risk_relevant_signals),
            "attribution_hints": list(self.attribution_hints),
            "behavior_graph_hints": list(self.behavior_graph_hints),
            "confidence": round(float(self.confidence), 3),
            "evidence": list(self.evidence),
            "limitations": list(self.limitations),
            "operator_summary": self.operator_summary,
            "operator_next_steps": list(self.operator_next_steps),
            "metadata": safe_metadata(self.metadata),
        }
