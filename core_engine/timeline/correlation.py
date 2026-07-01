"""Deterministic timeline correlation and filter helpers."""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Callable, Dict, Iterable, List

from .models import TimelineEvent


def group_events(events: Iterable[TimelineEvent | Dict[str, Any]], key: str) -> Dict[str, List[Dict[str, Any]]]:
    groups: dict[str, list[Dict[str, Any]]] = defaultdict(list)
    for event in events:
        item = TimelineEvent.from_dict(event).to_dict()
        if key == "host_pair":
            value = "|".join(sorted([item["src_ip"], item["dst_ip"]]))
        elif key == "port_pair":
            value = "|".join(str(port) for port in sorted([item["src_port"], item["dst_port"]]))
        else:
            value = str(item.get(key) or "-")
        groups[value].append(item)
    return {
        group_key: sorted(rows, key=lambda row: (row["timestamp"], row["event_id"]))
        for group_key, rows in sorted(groups.items())
    }


def group_by_conversation(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    return group_events(events, "conversation_id")


def group_by_flow(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    return group_events(events, "flow_key")


def group_by_protocol(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    return group_events(events, "protocol")


def group_by_session(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    return group_events(events, "session_id")


def group_by_interface(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    return group_events(events, "interface")


def group_by_host_pair(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    return group_events(events, "host_pair")


def group_by_port_pair(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    return group_events(events, "port_pair")


def filter_events(events: Iterable[TimelineEvent | Dict[str, Any]], predicate: Callable[[Dict[str, Any]], bool]) -> List[Dict[str, Any]]:
    rows = [TimelineEvent.from_dict(event).to_dict() for event in events]
    return [row for row in sorted(rows, key=lambda item: (item["timestamp"], item["event_id"])) if predicate(row)]


def filter_by_time_range(events: Iterable[TimelineEvent | Dict[str, Any]], *, start: str = "-", end: str = "-") -> List[Dict[str, Any]]:
    return filter_events(
        events,
        lambda row: (start == "-" or row["timestamp"] >= start) and (end == "-" or row["timestamp"] <= end),
    )


def filter_by_conversation(events: Iterable[TimelineEvent | Dict[str, Any]], conversation_id: str) -> List[Dict[str, Any]]:
    return filter_events(events, lambda row: row["conversation_id"] == conversation_id)


def filter_by_protocol(events: Iterable[TimelineEvent | Dict[str, Any]], protocol: str) -> List[Dict[str, Any]]:
    return filter_events(events, lambda row: row["protocol"] == protocol)


def filter_by_host(events: Iterable[TimelineEvent | Dict[str, Any]], host: str) -> List[Dict[str, Any]]:
    return filter_events(events, lambda row: row["src_ip"] == host or row["dst_ip"] == host)


def filter_by_session(events: Iterable[TimelineEvent | Dict[str, Any]], session_id: str) -> List[Dict[str, Any]]:
    return filter_events(events, lambda row: row["session_id"] == session_id)


def filter_by_importance(events: Iterable[TimelineEvent | Dict[str, Any]], importance: str) -> List[Dict[str, Any]]:
    return filter_events(events, lambda row: row["importance"] == importance)
