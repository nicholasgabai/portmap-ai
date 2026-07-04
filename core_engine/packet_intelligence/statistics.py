"""Deterministic packet intelligence statistics."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List

from .models import safe_int, safe_metadata, safe_text


def top_protocol(protocol_records: Iterable[Dict[str, Any]]) -> str:
    counter = Counter(safe_text(row.get("protocol"), "unknown") for row in protocol_records)
    return _top_counter_key(counter)


def top_talker(conversations: Iterable[Dict[str, Any]]) -> str:
    host_bytes: Counter = Counter()
    for row in conversations:
        for host in (safe_text(row.get("src_ip")), safe_text(row.get("dst_ip"))):
            if host != "-":
                host_bytes[host] += safe_int(row.get("byte_count"))
    return _top_counter_key(host_bytes)


def top_conversation(conversations: Iterable[Dict[str, Any]]) -> str:
    rows = [safe_metadata(dict(row or {})) for row in conversations]
    if not rows:
        return "-"
    ranked = sorted(rows, key=lambda row: (-safe_int(row.get("byte_count")), safe_text(row.get("conversation_id"))))
    return safe_text(ranked[0].get("conversation_id"))


def top_flow(conversations: Iterable[Dict[str, Any]]) -> str:
    flow_bytes: Counter = Counter()
    for row in conversations:
        flow_key = safe_text(row.get("flow_key"))
        if flow_key != "-":
            flow_bytes[flow_key] += safe_int(row.get("byte_count"))
    return _top_counter_key(flow_bytes)


def traffic_direction_summary(packets: Iterable[Dict[str, Any]], timeline_events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    counter = Counter()
    for row in [*list(packets), *list(timeline_events)]:
        direction = safe_text(row.get("direction"), "unknown")
        if direction != "-":
            counter[direction] += 1
    return {"directions": _counter_dict(counter), "dominant_direction": _top_counter_key(counter)}


def packet_activity_summary(packets: Iterable[Dict[str, Any]], conversations: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    packet_rows = [safe_metadata(dict(row or {})) for row in packets]
    conversation_rows = [safe_metadata(dict(row or {})) for row in conversations]
    packet_times = sorted(_time(row) for row in packet_rows if _time(row) != "-")
    total_bytes = sum(safe_int(row.get("length")) for row in packet_rows)
    conversation_bytes = sum(safe_int(row.get("byte_count")) for row in conversation_rows)
    return {
        "first_observed": packet_times[0] if packet_times else "-",
        "last_observed": packet_times[-1] if packet_times else "-",
        "packet_count": len(packet_rows),
        "conversation_count": len(conversation_rows),
        "total_packet_bytes": total_bytes,
        "conversation_bytes": conversation_bytes,
        "average_packet_size": round(total_bytes / len(packet_rows), 3) if packet_rows else 0.0,
        "activity_window_seconds": _duration_seconds(packet_times[0], packet_times[-1]) if len(packet_times) >= 2 else 0,
    }


def historical_flow_aggregation(
    conversations: Iterable[Dict[str, Any]],
    protocol_records: Iterable[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    conversation_rows = [safe_metadata(dict(row or {})) for row in conversations]
    protocol_rows = [safe_metadata(dict(row or {})) for row in protocol_records or []]
    times = sorted(
        time
        for row in conversation_rows
        for time in (_time({"first_observed": row.get("first_observed")}), _time({"first_observed": row.get("last_observed")}))
        if time != "-"
    )
    flow_keys = sorted({safe_text(row.get("flow_key")) for row in conversation_rows if safe_text(row.get("flow_key")) != "-"})
    protocols = sorted({safe_text(row.get("protocol"), "unknown") for row in conversation_rows if safe_text(row.get("protocol")) != "-"})
    service_candidates = sorted(
        {
            _service_candidate(row)
            for row in [*conversation_rows, *protocol_rows]
            if _service_candidate(row) != "-"
        }
    )
    short_lived = [
        row
        for row in conversation_rows
        if _duration_seconds(row.get("first_observed"), row.get("last_observed")) <= 2
    ]
    burst = len(short_lived) >= 10 or len(conversation_rows) >= 50
    return {
        "observation_count": sum(safe_int(row.get("packet_count"), 1) for row in conversation_rows),
        "connection_count": len(conversation_rows),
        "session_count": len(conversation_rows),
        "unique_flow_count": len(flow_keys),
        "first_seen": times[0] if times else "-",
        "last_seen": times[-1] if times else "-",
        "status": "historical_aggregate" if conversation_rows else "empty",
        "protocols": protocols,
        "service_candidates": service_candidates,
        "trend_indicators": ["short_lived_flow_burst"] if burst else [],
        "active_vs_historical": "historical_summary_preserved" if conversation_rows else "no_flow_history",
    }


def hunting_summary(hunt_results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [safe_metadata(dict(row or {})) for row in hunt_results]
    packet_matches = sum(safe_int((row.get("statistics") or {}).get("packet_matches")) for row in rows)
    conversation_matches = sum(safe_int((row.get("statistics") or {}).get("conversation_matches")) for row in rows)
    related_hosts = sorted({host for row in rows for host in (row.get("metadata") or {}).get("related_hosts", [])})
    return {
        "hunt_result_count": len(rows),
        "packet_matches": packet_matches,
        "conversation_matches": conversation_matches,
        "related_hosts": related_hosts,
    }


def timeline_summary(timeline_events: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [safe_metadata(dict(row or {})) for row in timeline_events]
    event_types = Counter(safe_text(row.get("event_type"), "unknown") for row in rows)
    times = sorted(_time(row) for row in rows if _time(row) != "-")
    return {
        "event_count": len(rows),
        "first_event_time": times[0] if times else "-",
        "last_event_time": times[-1] if times else "-",
        "event_types": _counter_dict(event_types),
        "coverage_seconds": _duration_seconds(times[0], times[-1]) if len(times) >= 2 else 0,
    }


def visualization_summary(visualization_models: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = [safe_metadata(dict(row or {})) for row in visualization_models]
    model_types = Counter(_visualization_type(row) for row in rows)
    return {
        "visualization_model_count": len(rows),
        "model_types": _counter_dict(model_types),
        "has_timeline_model": any("timeline_id" in row for row in rows),
        "has_network_snapshot": any("snapshot_id" in row for row in rows),
    }


def _top_counter_key(counter: Counter) -> str:
    if not counter:
        return "-"
    return str(sorted(counter, key=lambda item: (-counter[item], str(item)))[0])


def _counter_dict(counter: Counter) -> Dict[str, int]:
    return {str(key): counter[key] for key in sorted(counter, key=lambda item: (-counter[item], str(item)))}


def _time(row: Dict[str, Any]) -> str:
    for key in ("observed_at", "timestamp", "first_observed", "start", "start_time"):
        value = safe_text(row.get(key))
        if value != "-":
            return value
    return "-"


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


def _visualization_type(row: Dict[str, Any]) -> str:
    for key, name in (
        ("timeline_id", "timeline_model"),
        ("graph_id", "graph_model"),
        ("distribution_id", "distribution_model"),
        ("snapshot_id", "network_snapshot"),
        ("matrix_id", "communication_matrix"),
        ("heatmap_id", "activity_heatmap"),
        ("model_id", "model"),
        ("bandwidth_id", "bandwidth_model"),
    ):
        if key in row:
            return name
    return "unknown"


def _service_candidate(row: Dict[str, Any]) -> str:
    protocol = safe_text(row.get("application_protocol") or row.get("protocol"), "unknown").lower()
    if protocol == "dns":
        return "dns"
    if protocol == "ssh":
        return "ssh"
    if protocol in {"https", "tls"}:
        return "https_service"
    if protocol == "http":
        return "http_service"
    for port in (safe_int(row.get("src_port")), safe_int(row.get("dst_port"))):
        if port == 53:
            return "dns"
        if port == 22:
            return "ssh"
        if port == 80:
            return "http_service"
        if port == 443:
            return "https_service"
    return "-"
