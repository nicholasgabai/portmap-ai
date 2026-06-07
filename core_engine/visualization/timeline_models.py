from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.visualization.topology_models import (
    TOPOLOGY_VISUAL_SAFETY_FLAGS,
    clamp_score,
    normalize_source_mode,
)


TIMELINE_RECORD_VERSION = 1
TIMELINE_EVENT_TYPES = {
    "node_seen",
    "node_missing",
    "flow_started",
    "flow_changed",
    "service_seen",
    "service_changed",
    "topology_edge_seen",
    "topology_edge_changed",
    "asset_classified",
    "drift_detected",
    "policy_matched",
    "remediation_recommended",
    "guardrail_blocked",
    "runtime_degraded",
    "unknown",
}
TIMELINE_CATEGORIES = {
    "topology",
    "flow",
    "service",
    "asset",
    "drift",
    "policy",
    "remediation",
    "guardrail",
    "runtime",
    "unknown",
}
TIMELINE_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}
TIMELINE_SAFETY_FLAGS = {
    **TOPOLOGY_VISUAL_SAFETY_FLAGS,
    "replay_safe": True,
    "bounded": True,
    "export_safe": True,
    "preview_only": True,
    "destructive_action": False,
    "filesystem_write_performed": False,
}


class TimelineVisualizationError(ValueError):
    """Raised when historical timeline inputs are malformed."""


@dataclass(frozen=True)
class TimelineEvent:
    event_id: str
    event_type: str
    event_category: str
    timestamp: str
    source_reference: str = ""
    target_reference: str = ""
    summary: str = ""
    severity_level: str = "info"
    confidence_score: float = 0.0
    related_flow_references: list[str] = field(default_factory=list)
    related_topology_references: list[str] = field(default_factory=list)
    related_asset_references: list[str] = field(default_factory=list)
    related_policy_references: list[str] = field(default_factory=list)
    source_mode: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "visual_timeline_event",
            "record_version": TIMELINE_RECORD_VERSION,
            "event_id": self.event_id,
            "event_type": normalize_event_type(self.event_type),
            "event_category": normalize_event_category(self.event_category),
            "timestamp": normalize_timestamp(self.timestamp),
            "source_reference": sanitize_reference(self.source_reference),
            "target_reference": sanitize_reference(self.target_reference),
            "summary": sanitize_summary(self.summary),
            "severity_level": normalize_severity(self.severity_level),
            "confidence_score": clamp_score(self.confidence_score),
            "related_flow_references": sanitize_references(self.related_flow_references),
            "related_topology_references": sanitize_references(self.related_topology_references),
            "related_asset_references": sanitize_references(self.related_asset_references),
            "related_policy_references": sanitize_references(self.related_policy_references),
            "source_mode": mode,
            "data_source": mode,
            "preview_only": True,
            "destructive_action": False,
            "advisory_notes": [sanitize_summary(note) for note in self.advisory_notes],
            **TIMELINE_SAFETY_FLAGS,
        }


@dataclass(frozen=True)
class TimelineWindow:
    timeline_window_id: str
    start_timestamp: str
    end_timestamp: str
    event_count: int
    category_counts: dict[str, int]
    severity_counts: dict[str, int]
    events: list[TimelineEvent] = field(default_factory=list)
    bounded: bool = True
    max_events: int = 256
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        rows = [event.to_dict() for event in self.events]
        return {
            "record_type": "visual_timeline_window",
            "record_version": TIMELINE_RECORD_VERSION,
            "timeline_window_id": self.timeline_window_id,
            "start_timestamp": normalize_timestamp(self.start_timestamp),
            "end_timestamp": normalize_timestamp(self.end_timestamp),
            "event_count": max(0, int(self.event_count or 0)),
            "category_counts": dict(self.category_counts),
            "severity_counts": dict(self.severity_counts),
            "events": rows,
            "bounded": True,
            "max_events": max(0, int(self.max_events or 0)),
            "export_safe": True,
            **TIMELINE_SAFETY_FLAGS,
        }


def make_timeline_event(
    *,
    event_type: str,
    event_category: str,
    timestamp: str | None = None,
    source_reference: Any = "",
    target_reference: Any = "",
    summary: Any = "",
    severity_level: str = "info",
    confidence_score: Any = 0.0,
    related_flow_references: list[Any] | None = None,
    related_topology_references: list[Any] | None = None,
    related_asset_references: list[Any] | None = None,
    related_policy_references: list[Any] | None = None,
    source_mode: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> TimelineEvent:
    normalized_type = normalize_event_type(event_type)
    category = normalize_event_category(event_category)
    when = normalize_timestamp(timestamp)
    source_ref = sanitize_reference(source_reference)
    target_ref = sanitize_reference(target_reference)
    event_summary = sanitize_summary(summary or f"{normalized_type.replace('_', ' ')} event")
    flow_refs = sanitize_references(related_flow_references or [])
    topology_refs = sanitize_references(related_topology_references or [])
    asset_refs = sanitize_references(related_asset_references or [])
    policy_refs = sanitize_references(related_policy_references or [])
    mode = normalize_source_mode(source_mode)
    event_id = "timeline-event-" + _digest(
        {
            "event_type": normalized_type,
            "event_category": category,
            "timestamp": when,
            "source_reference": source_ref,
            "target_reference": target_ref,
            "flow_refs": flow_refs,
            "topology_refs": topology_refs,
            "asset_refs": asset_refs,
            "policy_refs": policy_refs,
            "source_mode": mode,
        }
    )[:16]
    return TimelineEvent(
        event_id=event_id,
        event_type=normalized_type,
        event_category=category,
        timestamp=when,
        source_reference=source_ref,
        target_reference=target_ref,
        summary=event_summary,
        severity_level=normalize_severity(severity_level),
        confidence_score=clamp_score(confidence_score),
        related_flow_references=flow_refs,
        related_topology_references=topology_refs,
        related_asset_references=asset_refs,
        related_policy_references=policy_refs,
        source_mode=mode,
        preview_only=True,
        destructive_action=False,
        advisory_notes=[sanitize_summary(note) for note in advisory_notes or ["replay-safe visual timeline event"]],
    )


def deterministic_timeline_json(record: TimelineWindow | TimelineEvent | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, (TimelineWindow, TimelineEvent)) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def normalize_event_type(value: Any) -> str:
    event_type = _safe_token(value)
    return event_type if event_type in TIMELINE_EVENT_TYPES else "unknown"


def normalize_event_category(value: Any) -> str:
    category = _safe_token(value)
    return category if category in TIMELINE_CATEGORIES else "unknown"


def normalize_severity(value: Any) -> str:
    severity = _safe_token(value)
    return severity if severity in TIMELINE_SEVERITIES else "unknown"


def normalize_timestamp(value: Any = None) -> str:
    if not value:
        return datetime.now(UTC).isoformat()
    text = str(value)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return datetime.now(UTC).isoformat()
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.isoformat()


def sanitize_references(values: list[Any]) -> list[str]:
    return sorted({ref for ref in (sanitize_reference(value) for value in values) if ref})


def sanitize_reference(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if _looks_sensitive(text):
        return "ref-" + _digest(text)[:16]
    safe = "".join(char for char in text if char.isalnum() or char in {"-", "_", ":"})
    if not safe:
        return "ref-" + _digest(text)[:16]
    return safe[:96]


def sanitize_summary(value: Any) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if _looks_sensitive(text):
        return "redacted metadata timeline summary"
    compact = " ".join(text.replace("\n", " ").split())
    return compact[:180]


def _looks_sensitive(text: str) -> bool:
    lowered = text.lower()
    if any(marker in lowered for marker in {"password", "secret", "token", "private key", "hostname", "username"}):
        return True
    if "/" in text or "\\" in text or "@" in text:
        return True
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text):
        return True
    if re.search(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b", text):
        return True
    return False


def _safe_token(value: Any) -> str:
    token = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    safe = "".join(char for char in token if char.isalnum() or char == "_")
    return safe[:64] or "unknown"


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()
