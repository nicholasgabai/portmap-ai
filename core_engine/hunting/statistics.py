"""Statistics helpers for packet hunting results."""

from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List

from .filters import normalize_row
from .models import safe_int, safe_text


def hunt_statistics(
    *,
    packets: Iterable[Dict[str, Any]] | None = None,
    protocols: Iterable[Dict[str, Any]] | None = None,
    conversations: Iterable[Dict[str, Any]] | None = None,
    sessions: Iterable[Dict[str, Any]] | None = None,
    timeline_events: Iterable[Dict[str, Any]] | None = None,
    visualizations: Iterable[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    packet_rows = [normalize_row(row) for row in packets or []]
    protocol_rows = [normalize_row(row) for row in protocols or []]
    conversation_rows = [normalize_row(row) for row in conversations or []]
    session_rows = [normalize_row(row) for row in sessions or []]
    timeline_rows = [normalize_row(row) for row in timeline_events or []]
    visualization_rows = [normalize_row(row) for row in visualizations or []]
    all_rows = packet_rows + protocol_rows + conversation_rows + session_rows + timeline_rows + visualization_rows
    host_counter = Counter(host for row in all_rows for host in _hosts(row))
    protocol_counter = Counter(_protocol(row) for row in all_rows if _protocol(row) != "-")
    port_counter = Counter(port for row in all_rows for port in _ports(row))
    flow_ids = {safe_text(row.get("flow_key")) for row in all_rows if safe_text(row.get("flow_key")) != "-"}
    session_ids = {safe_text(row.get("session_id")) for row in all_rows if safe_text(row.get("session_id")) != "-"}
    conversation_ids = {
        safe_text(row.get("conversation_id")) for row in all_rows if safe_text(row.get("conversation_id")) != "-"
    }
    times = sorted({time for row in all_rows for time in [_time(row)] if time != "-"})
    return {
        "packet_matches": len(packet_rows),
        "protocol_matches": len(protocol_rows),
        "conversation_matches": len(conversation_rows),
        "flow_matches": len(flow_ids),
        "session_matches": len(session_ids or {safe_text(row.get("session_id")) for row in session_rows if safe_text(row.get("session_id")) != "-"}),
        "timeline_matches": len(timeline_rows),
        "visualization_matches": len(visualization_rows),
        "host_count": len(host_counter),
        "protocol_distribution": _counter_dict(protocol_counter),
        "top_protocols": _top_rows(protocol_counter, "protocol"),
        "top_hosts": _top_rows(host_counter, "host"),
        "top_ports": _top_rows(port_counter, "port"),
        "timeline_coverage": {
            "start": times[0] if times else "-",
            "end": times[-1] if times else "-",
            "event_count": len(timeline_rows),
        },
        "search_duration": len(all_rows),
        "related_conversations": sorted(conversation_ids),
        "related_sessions": sorted(session_ids),
        "related_flows": sorted(flow_ids),
    }


def hunt_summary(statistics: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "packet_matches": safe_int(statistics.get("packet_matches")),
        "conversation_matches": safe_int(statistics.get("conversation_matches")),
        "flow_matches": safe_int(statistics.get("flow_matches")),
        "session_matches": safe_int(statistics.get("session_matches")),
        "host_count": safe_int(statistics.get("host_count")),
        "top_protocol": (statistics.get("top_protocols") or [{"protocol": "-"}])[0].get("protocol", "-"),
        "top_host": (statistics.get("top_hosts") or [{"host": "-"}])[0].get("host", "-"),
        "top_port": (statistics.get("top_ports") or [{"port": 0}])[0].get("port", 0),
    }


def _hosts(row: Dict[str, Any]) -> List[str]:
    hosts = [safe_text(row.get("src_ip")), safe_text(row.get("dst_ip")), safe_text(row.get("ip")), safe_text(row.get("host"))]
    for key in ("participants", "hosts"):
        value = row.get(key)
        if isinstance(value, (list, tuple)):
            hosts.extend(safe_text(item) for item in value)
    return sorted({host for host in hosts if host != "-"})


def _protocol(row: Dict[str, Any]) -> str:
    return safe_text(row.get("protocol") or row.get("application_protocol"), "-").lower()


def _ports(row: Dict[str, Any]) -> List[int]:
    ports = [safe_int(row.get("src_port")), safe_int(row.get("dst_port")), safe_int(row.get("port"))]
    value = row.get("ports")
    if isinstance(value, (list, tuple)):
        ports.extend(safe_int(item) for item in value)
    return sorted({port for port in ports if port})


def _time(row: Dict[str, Any]) -> str:
    for key in ("observed_at", "timestamp", "first_observed", "start", "start_time"):
        value = safe_text(row.get(key))
        if value != "-":
            return value
    return "-"


def _counter_dict(counter: Counter) -> Dict[str, int]:
    return {str(key): counter[key] for key in sorted(counter, key=lambda item: (-counter[item], str(item)))}


def _top_rows(counter: Counter, key_name: str) -> List[Dict[str, Any]]:
    return [
        {key_name: key, "count": counter[key], "rank": index}
        for index, key in enumerate(sorted(counter, key=lambda item: (-counter[item], str(item))), start=1)
    ]
