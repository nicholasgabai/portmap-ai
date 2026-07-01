"""Session reconstruction helpers for packet timelines."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List

from .models import TimelineEvent


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def build_timeline_sessions(events: Iterable[TimelineEvent | Dict[str, Any]]) -> List[Dict[str, Any]]:
    groups: dict[str, list[TimelineEvent]] = defaultdict(list)
    for event in events:
        item = TimelineEvent.from_dict(event)
        if item.session_id == "-":
            continue
        groups[item.session_id].append(item)
    results: list[Dict[str, Any]] = []
    for session_id in sorted(groups):
        group = sorted(groups[session_id], key=lambda item: (item.timestamp, item.event_id))
        observed = [_parse_time(item.timestamp) for item in group]
        observed = [item for item in observed if item is not None]
        first_seen = min(observed).isoformat() if observed else "-"
        last_seen = max(observed).isoformat() if observed else "-"
        duration = int((max(observed) - min(observed)).total_seconds()) if len(observed) >= 2 else 0
        protocols = [item.protocol for item in group if item.protocol not in {"", "-", "unknown"}]
        directions = [item.direction for item in group if item.direction not in {"", "-", "unknown"}]
        conversation_states = sorted({item.event_type for item in group if item.event_type.startswith("conversation_")})
        packet_events = [item for item in group if item.event_type == "packet_observed"]
        results.append(
            {
                "session_id": session_id,
                "first_seen": first_seen,
                "last_seen": last_seen,
                "duration": duration,
                "packet_count": len(packet_events),
                "byte_count": sum(int(item.metadata.get("length") or 0) for item in packet_events),
                "protocol_changes": max(len(set(protocols)) - 1, 0),
                "direction_changes": max(len(set(directions)) - 1, 0),
                "conversation_state": conversation_states[-1] if conversation_states else "unknown",
                "confidence": round(sum(item.confidence for item in group) / len(group), 3) if group else 0,
                "summary": f"{len(packet_events)} packets across {len(set(protocols))} protocols.",
            }
        )
    return results


def session_lifecycle_events(events: Iterable[TimelineEvent | Dict[str, Any]]) -> List[Dict[str, Any]]:
    lifecycle = []
    for session in build_timeline_sessions(events):
        for event_type, timestamp, summary in (
            ("session_started", session["first_seen"], "Timeline session started."),
            ("session_updated", session["last_seen"], session["summary"]),
            ("session_completed", session["last_seen"], "Timeline session completed."),
        ):
            lifecycle.append(
                TimelineEvent.from_dict(
                    {
                        "timestamp": timestamp,
                        "event_type": event_type,
                        "session_id": session["session_id"],
                        "confidence": session["confidence"],
                        "summary": summary,
                        "metadata": session,
                        "tags": ["session", "metadata_only"],
                    }
                ).to_dict()
            )
    return sorted(lifecycle, key=lambda item: (item["timestamp"], item["event_id"]))
