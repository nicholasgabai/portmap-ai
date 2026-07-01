"""Aggregate packet visualization statistics and snapshot builders."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List

from core_engine.timeline import export_timeline, timeline_statistics
from core_engine.timeline.models import TimelineEvent

from .conversations import build_top_talkers
from .models import ActivityHeatmap, NetworkSnapshot, safe_int, safe_text, stable_id
from .protocols import build_protocol_distribution


def build_activity_heatmap(
    events: Iterable[TimelineEvent | Dict[str, Any]],
    *,
    granularity: str = "minute",
) -> Dict[str, Any]:
    rows = export_timeline(events)
    granularity = safe_text(granularity, "minute").lower()
    if granularity not in {"minute", "hour", "day"}:
        granularity = "minute"
    buckets: dict[str, dict[str, Any]] = {}
    conversations_by_bucket: dict[str, set[str]] = defaultdict(set)
    for row in rows:
        parsed = _parse_time(row["timestamp"])
        if not parsed:
            continue
        start = _bucket_start(parsed, granularity)
        end = _bucket_end(start, granularity)
        key = start.isoformat()
        bucket = buckets.setdefault(
            key,
            {
                "start": key,
                "end": end.isoformat(),
                "event_count": 0,
                "conversation_count": 0,
                "activity_score": 0.0,
            },
        )
        bucket["event_count"] += 1
        conversation_id = safe_text(row.get("conversation_id"))
        if conversation_id != "-":
            conversations_by_bucket[key].add(conversation_id)
    max_events = max((bucket["event_count"] for bucket in buckets.values()), default=0)
    bucket_rows = []
    for key in sorted(buckets):
        bucket = buckets[key]
        bucket["conversation_count"] = len(conversations_by_bucket[key])
        bucket["activity_score"] = round(bucket["event_count"] / max_events, 3) if max_events else 0.0
        bucket_rows.append(bucket)
    return ActivityHeatmap(
        heatmap_id=stable_id("activity-heatmap", {"granularity": granularity, "buckets": bucket_rows}),
        granularity=granularity,
        buckets=bucket_rows,
        bucket_count=len(bucket_rows),
    ).to_dict()


def build_network_snapshot(
    *,
    timestamp: str = "-",
    events: Iterable[TimelineEvent | Dict[str, Any]] | None = None,
    protocol_records: Iterable[Dict[str, Any]] | None = None,
    conversations: Iterable[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    event_rows = export_timeline(events or [])
    record_rows = [dict(row or {}) for row in protocol_records or []]
    conversation_rows = [dict(row or {}) for row in conversations or []]
    hosts = sorted(
        {
            safe_text(row.get("src_ip"))
            for row in conversation_rows
            if safe_text(row.get("src_ip")) != "-"
        }
        | {
            safe_text(row.get("dst_ip"))
            for row in conversation_rows
            if safe_text(row.get("dst_ip")) != "-"
        }
    )
    flow_keys = sorted({safe_text(row.get("flow_key")) for row in conversation_rows if safe_text(row.get("flow_key")) != "-"})
    sessions = sorted({safe_text(row.get("session_id")) for row in event_rows if safe_text(row.get("session_id")) != "-"})
    protocol_distribution = build_protocol_distribution(record_rows, conversations=conversation_rows)
    top_talkers = build_top_talkers(conversation_rows)
    timeline_stats = timeline_statistics(event_rows)
    statistics = visualization_statistics(
        events=event_rows,
        protocol_records=record_rows,
        conversations=conversation_rows,
    )
    snapshot = NetworkSnapshot(
        snapshot_id=stable_id(
            "network-snapshot",
            {
                "timestamp": timestamp,
                "events": sorted(row["event_id"] for row in event_rows),
                "records": sorted(safe_text(row.get("protocol_id")) for row in record_rows),
                "conversations": sorted(safe_text(row.get("conversation_id")) for row in conversation_rows),
            },
        ),
        timestamp=safe_text(timestamp),
        host_count=len(hosts),
        conversation_count=len(conversation_rows),
        flow_count=len(flow_keys),
        session_count=len(sessions),
        protocol_distribution=protocol_distribution,
        top_talkers=top_talkers,
        timeline_summary={
            "event_count": len(event_rows),
            "first_event": timeline_stats.get("first_event", "-"),
            "last_event": timeline_stats.get("last_event", "-"),
            "duration": timeline_stats.get("duration", 0),
        },
        statistics=statistics,
    )
    return snapshot.to_dict()


def visualization_statistics(
    *,
    events: Iterable[TimelineEvent | Dict[str, Any]] | None = None,
    protocol_records: Iterable[Dict[str, Any]] | None = None,
    conversations: Iterable[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    event_rows = export_timeline(events or [])
    record_rows = [dict(row or {}) for row in protocol_records or []]
    conversation_rows = [dict(row or {}) for row in conversations or []]
    timeline_stats = timeline_statistics(event_rows)
    largest_conversation = _largest(conversation_rows, "conversation_id", "byte_count")
    largest_flow = _largest(conversation_rows, "flow_key", "byte_count")
    host_bytes: Counter = Counter()
    for row in conversation_rows:
        for host in (safe_text(row.get("src_ip")), safe_text(row.get("dst_ip"))):
            if host != "-":
                host_bytes[host] += safe_int(row.get("byte_count"))
    protocol_counts = Counter(safe_text(row.get("protocol"), "unknown") for row in record_rows)
    interface_counts = Counter(safe_text(row.get("interface")) for row in event_rows)
    host_count = len(host_bytes)
    conversation_count = len(conversation_rows)
    flow_count = len({safe_text(row.get("flow_key")) for row in conversation_rows if safe_text(row.get("flow_key")) != "-"})
    duration = safe_int(timeline_stats.get("duration"))
    return {
        "largest_conversation": largest_conversation,
        "largest_flow": largest_flow,
        "largest_host": _top_counter_key(host_bytes),
        "most_active_protocol": _top_counter_key(protocol_counts),
        "most_active_interface": _top_counter_key(interface_counts),
        "conversation_density": round(conversation_count / host_count, 3) if host_count else 0.0,
        "host_density": round(host_count / max(flow_count, 1), 3) if flow_count else 0.0,
        "timeline_density": round(len(event_rows) / duration, 3) if duration else 0.0,
    }


def _parse_time(value: Any) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except Exception:
        return None


def _bucket_start(value: datetime, granularity: str) -> datetime:
    if granularity == "day":
        return value.replace(hour=0, minute=0, second=0, microsecond=0)
    if granularity == "hour":
        return value.replace(minute=0, second=0, microsecond=0)
    return value.replace(second=0, microsecond=0)


def _bucket_end(start: datetime, granularity: str) -> datetime:
    if granularity == "day":
        return start + timedelta(days=1)
    if granularity == "hour":
        return start + timedelta(hours=1)
    return start + timedelta(minutes=1)


def _largest(rows: List[Dict[str, Any]], label: str, metric: str) -> str:
    if not rows:
        return "-"
    ranked = sorted(rows, key=lambda row: (-safe_int(row.get(metric)), safe_text(row.get(label))))
    return safe_text(ranked[0].get(label))


def _top_counter_key(counter: Counter) -> str:
    if not counter:
        return "-"
    return str(sorted(counter, key=lambda item: (-counter[item], str(item)))[0])
