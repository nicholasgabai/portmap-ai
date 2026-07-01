"""Reusable packet hunting query builders."""

from __future__ import annotations

from .models import HuntQuery, SavedQuery


def find_traffic_for_host(host: str, **overrides) -> HuntQuery:
    return HuntQuery(host=host, **overrides)


def find_traffic_for_ip(ip: str, **overrides) -> HuntQuery:
    return HuntQuery(host=ip, **overrides)


def find_conversations_for_protocol(protocol: str, **overrides) -> HuntQuery:
    return HuntQuery(protocol=protocol, **overrides)


def find_conversations_for_interface(interface: str, **overrides) -> HuntQuery:
    return HuntQuery(interface=interface, **overrides)


def find_flows_between_hosts(src_ip: str, dst_ip: str, **overrides) -> HuntQuery:
    return HuntQuery(src_ip=src_ip, dst_ip=dst_ip, **overrides)


def find_conversations_during_time_window(time_start: str, time_end: str, **overrides) -> HuntQuery:
    return HuntQuery(time_start=time_start, time_end=time_end, **overrides)


def find_newest_observations(limit: int = 10, **overrides) -> HuntQuery:
    return HuntQuery(sort_by="time", sort_direction="desc", limit=limit, **overrides)


def find_oldest_observations(limit: int = 10, **overrides) -> HuntQuery:
    return HuntQuery(sort_by="time", sort_direction="asc", limit=limit, **overrides)


def find_largest_conversations(limit: int = 10, **overrides) -> HuntQuery:
    return HuntQuery(sort_by="bytes", sort_direction="desc", limit=limit, **overrides)


def find_highest_confidence_conversations(limit: int = 10, **overrides) -> HuntQuery:
    return HuntQuery(sort_by="confidence", sort_direction="desc", limit=limit, **overrides)


def find_unknown_protocols(**overrides) -> HuntQuery:
    return HuntQuery(protocol="unknown", **overrides)


def find_protocol_transitions(**overrides) -> HuntQuery:
    return HuntQuery(metadata={"event_type": "protocol_changed"}, **overrides)


def find_inactive_conversations(**overrides) -> HuntQuery:
    return HuntQuery(metadata={"state": "inactive"}, **overrides)


def save_query(
    *,
    name: str,
    description: str,
    query: HuntQuery,
    tags=(),
    created_at: str = "-",
    updated_at: str = "-",
    version: str = "1",
) -> SavedQuery:
    return SavedQuery(
        name=name,
        description=description,
        query=query,
        tags=tags,
        created_at=created_at,
        updated_at=updated_at,
        version=version,
    )
