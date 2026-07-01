"""Timeline visualization model builders."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Iterable, List

from core_engine.timeline import export_timeline, timeline_statistics
from core_engine.timeline.models import TimelineEvent

from .models import TimelineLane, TimelineModel, safe_text, stable_id


LANE_GROUP_FIELDS = {
    "interface": "interface",
    "host": "host",
    "conversation": "conversation_id",
    "session": "session_id",
    "protocol": "protocol",
    "flow": "flow_key",
}


def build_timeline_model(
    events: Iterable[TimelineEvent | Dict[str, Any]],
    *,
    group_by: str = "protocol",
) -> Dict[str, Any]:
    rows = export_timeline(events)
    lanes = build_timeline_lanes(rows, group_by=group_by)
    stats = timeline_statistics(rows)
    start_time = rows[0]["timestamp"] if rows else "-"
    end_time = rows[-1]["timestamp"] if rows else "-"
    model = TimelineModel(
        timeline_id=stable_id("timeline-model", {"events": [row["event_id"] for row in rows], "group_by": group_by}),
        start_time=start_time,
        end_time=end_time,
        duration=_duration_seconds(start_time, end_time),
        event_count=len(rows),
        lane_count=len(lanes),
        events=rows,
        summaries={
            "first_event": stats.get("first_event", "-"),
            "last_event": stats.get("last_event", "-"),
            "largest_conversation": stats.get("largest_conversation", "-"),
            "largest_session": stats.get("largest_session", "-"),
        },
        statistics=stats,
        lanes=lanes,
    )
    return model.to_dict()


def build_timeline_lanes(
    events: Iterable[TimelineEvent | Dict[str, Any]],
    *,
    group_by: str = "protocol",
) -> List[Dict[str, Any]]:
    rows = export_timeline(events)
    group_key = safe_text(group_by, "protocol").lower()
    if group_key not in LANE_GROUP_FIELDS:
        group_key = "protocol"
    groups: dict[str, list[Dict[str, Any]]] = {}
    for row in rows:
        label = _lane_label(row, group_key)
        groups.setdefault(label, []).append(row)
    lanes: list[Dict[str, Any]] = []
    for label in sorted(groups):
        lane_events = sorted(groups[label], key=lambda item: (item["timestamp"], item["event_id"]))
        lanes.append(
            TimelineLane(
                lane_id=stable_id("timeline-lane", {"group_by": group_key, "label": label}),
                label=label,
                events=lane_events,
                first_seen=lane_events[0]["timestamp"] if lane_events else "-",
                last_seen=lane_events[-1]["timestamp"] if lane_events else "-",
                event_count=len(lane_events),
            ).to_dict()
        )
    return lanes


def _lane_label(row: Dict[str, Any], group_by: str) -> str:
    if group_by == "host":
        hosts = sorted({safe_text(row.get("src_ip")), safe_text(row.get("dst_ip"))} - {"-"})
        return " <-> ".join(hosts) if hosts else "-"
    return safe_text(row.get(LANE_GROUP_FIELDS[group_by]))


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _duration_seconds(start: Any, end: Any) -> int:
    parsed_start = _parse_time(start)
    parsed_end = _parse_time(end)
    if not parsed_start or not parsed_end:
        return 0
    return max(0, int((parsed_end - parsed_start).total_seconds()))
