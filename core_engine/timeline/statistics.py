"""Timeline statistics helpers."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable

from .models import TimelineEvent


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _counter(counter: Counter) -> Dict[str, int]:
    return {
        key: counter[key]
        for key in sorted(counter, key=lambda item: (-counter[item], str(item)))
        if str(key) not in {"", "-"}
    }


def timeline_statistics(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, Any]:
    rows = [TimelineEvent.from_dict(event).to_dict() for event in events]
    observed = [_parse_time(row["timestamp"]) for row in rows]
    observed = [item for item in observed if item is not None]
    duration = int((max(observed) - min(observed)).total_seconds()) if len(observed) >= 2 else 0
    conversations = {row["conversation_id"] for row in rows if row["conversation_id"] not in {"", "-"}}
    flows = {row["flow_key"] for row in rows if row["flow_key"] not in {"", "-"}}
    sessions = {row["session_id"] for row in rows if row["session_id"] not in {"", "-"}}
    largest_conversation = _largest(rows, "conversation_id")
    largest_session = _largest(rows, "session_id")
    return {
        "event_count": len(rows),
        "conversation_count": len(conversations),
        "flow_count": len(flows),
        "session_count": len(sessions),
        "duration": duration,
        "events_per_protocol": _counter(Counter(row["protocol"] for row in rows)),
        "events_per_interface": _counter(Counter(row["interface"] for row in rows)),
        "events_per_host": _counter(Counter(host for row in rows for host in (row["src_ip"], row["dst_ip"]))),
        "events_per_port": _counter(Counter(str(port) for row in rows for port in (row["src_port"], row["dst_port"]) if port)),
        "timeline_density": round(len(rows) / duration, 3) if duration else 0,
        "first_event": min(rows, key=lambda row: (row["timestamp"], row["event_id"]))["event_id"] if rows else "-",
        "last_event": max(rows, key=lambda row: (row["timestamp"], row["event_id"]))["event_id"] if rows else "-",
        "largest_conversation": largest_conversation,
        "largest_session": largest_session,
    }


def _largest(rows: list[Dict[str, Any]], key: str) -> str:
    counts = Counter(row[key] for row in rows if row[key] not in {"", "-"})
    if not counts:
        return "-"
    return sorted(counts, key=lambda item: (-counts[item], item))[0]
