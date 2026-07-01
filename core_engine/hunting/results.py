"""Packet hunting result models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from .filters import stable_sort
from .models import safe_float, safe_metadata, stable_id
from .statistics import hunt_statistics, hunt_summary


@dataclass(frozen=True)
class HuntResult:
    result_id: str
    query_id: str
    matched_packets: List[Dict[str, Any]] = field(default_factory=list)
    matched_protocols: List[Dict[str, Any]] = field(default_factory=list)
    matched_conversations: List[Dict[str, Any]] = field(default_factory=list)
    matched_sessions: List[Dict[str, Any]] = field(default_factory=list)
    matched_timeline_events: List[Dict[str, Any]] = field(default_factory=list)
    matched_visualizations: List[Dict[str, Any]] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    statistics: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        *,
        query_id: str,
        matched_packets: List[Dict[str, Any]] | None = None,
        matched_protocols: List[Dict[str, Any]] | None = None,
        matched_conversations: List[Dict[str, Any]] | None = None,
        matched_sessions: List[Dict[str, Any]] | None = None,
        matched_timeline_events: List[Dict[str, Any]] | None = None,
        matched_visualizations: List[Dict[str, Any]] | None = None,
        metadata: Dict[str, Any] | None = None,
    ) -> "HuntResult":
        packets = stable_sort(matched_packets or [])
        protocols = stable_sort(matched_protocols or [])
        conversations = stable_sort(matched_conversations or [])
        sessions = stable_sort(matched_sessions or [])
        timeline = stable_sort(matched_timeline_events or [])
        visualizations = stable_sort(matched_visualizations or [])
        stats = hunt_statistics(
            packets=packets,
            protocols=protocols,
            conversations=conversations,
            sessions=sessions,
            timeline_events=timeline,
            visualizations=visualizations,
        )
        summary = hunt_summary(stats)
        confidence_values = [
            safe_float(row.get("confidence"))
            for row in [*packets, *protocols, *conversations, *sessions, *timeline, *visualizations]
            if "confidence" in row
        ]
        confidence = sum(confidence_values) / len(confidence_values) if confidence_values else 0.0
        result_basis = {
            "query_id": query_id,
            "packets": [row.get("packet_id", "-") for row in packets],
            "protocols": [row.get("protocol_id", "-") for row in protocols],
            "conversations": [row.get("conversation_id", "-") for row in conversations],
            "sessions": [row.get("session_id", "-") for row in sessions],
            "timeline": [row.get("event_id", "-") for row in timeline],
            "visualizations": [
                row.get("timeline_id")
                or row.get("graph_id")
                or row.get("distribution_id")
                or row.get("snapshot_id")
                or row.get("model_id")
                or "-"
                for row in visualizations
            ],
        }
        return cls(
            result_id=stable_id("hunt-result", result_basis),
            query_id=query_id,
            matched_packets=packets,
            matched_protocols=protocols,
            matched_conversations=conversations,
            matched_sessions=sessions,
            matched_timeline_events=timeline,
            matched_visualizations=visualizations,
            summary=summary,
            statistics=stats,
            confidence=confidence,
            metadata=safe_metadata(metadata or {}),
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "query_id": self.query_id,
            "matched_packets": [safe_metadata(row) for row in self.matched_packets],
            "matched_protocols": [safe_metadata(row) for row in self.matched_protocols],
            "matched_conversations": [safe_metadata(row) for row in self.matched_conversations],
            "matched_sessions": [safe_metadata(row) for row in self.matched_sessions],
            "matched_timeline_events": [safe_metadata(row) for row in self.matched_timeline_events],
            "matched_visualizations": [safe_metadata(row) for row in self.matched_visualizations],
            "summary": safe_metadata(self.summary),
            "statistics": safe_metadata(self.statistics),
            "confidence": round(float(self.confidence), 3),
            "metadata": safe_metadata(self.metadata),
        }
