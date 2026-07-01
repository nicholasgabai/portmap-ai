"""Deterministic packet hunting filters and set operations."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .models import HuntQuery, safe_float, safe_int, safe_metadata, safe_tags, safe_text


def normalize_row(row: Any) -> Dict[str, Any]:
    if hasattr(row, "to_dict"):
        row = row.to_dict()
    return safe_metadata(dict(row or {}))


def row_identity(row: Dict[str, Any]) -> str:
    for key in (
        "packet_id",
        "protocol_id",
        "conversation_id",
        "session_id",
        "event_id",
        "timeline_id",
        "graph_id",
        "distribution_id",
        "matrix_id",
        "heatmap_id",
        "model_id",
        "snapshot_id",
        "bandwidth_id",
    ):
        value = safe_text(row.get(key))
        if value != "-":
            return f"{key}:{value}"
    return f"row:{safe_text(row)}"


def match_row(row: Dict[str, Any], query: HuntQuery | Dict[str, Any]) -> bool:
    item = normalize_row(row)
    hunt = HuntQuery.from_dict(query)
    if hunt.time_start != "-" and _row_time(item) < hunt.time_start:
        return False
    if hunt.time_end != "-" and _row_time(item) > hunt.time_end:
        return False
    if hunt.src_ip != "-" and safe_text(item.get("src_ip")) != hunt.src_ip:
        return False
    if hunt.dst_ip != "-" and safe_text(item.get("dst_ip")) != hunt.dst_ip:
        return False
    if hunt.host != "-" and hunt.host not in _row_hosts(item):
        return False
    if hunt.mac != "-" and hunt.mac.lower() not in {mac.lower() for mac in _row_macs(item)}:
        return False
    if hunt.protocol != "-" and safe_text(item.get("protocol"), "unknown").lower() != hunt.protocol:
        return False
    if hunt.application_protocol != "-" and safe_text(item.get("application_protocol")).lower() != hunt.application_protocol:
        return False
    if hunt.transport_protocol != "-" and safe_text(item.get("transport_protocol")).lower() != hunt.transport_protocol:
        return False
    if hunt.port and hunt.port not in _row_ports(item):
        return False
    if hunt.src_port and safe_int(item.get("src_port")) != hunt.src_port:
        return False
    if hunt.dst_port and safe_int(item.get("dst_port")) != hunt.dst_port:
        return False
    if hunt.flow_key != "-" and safe_text(item.get("flow_key")) != hunt.flow_key:
        return False
    if hunt.conversation_id != "-" and safe_text(item.get("conversation_id")) != hunt.conversation_id:
        return False
    if hunt.session_id != "-" and safe_text(item.get("session_id")) != hunt.session_id:
        return False
    if hunt.interface != "-" and safe_text(item.get("interface")) != hunt.interface:
        return False
    if hunt.importance != "-" and safe_text(item.get("importance")).lower() != hunt.importance:
        return False
    if hunt.confidence and _row_confidence(item) < hunt.confidence:
        return False
    if hunt.tags and not set(hunt.tags).issubset(_row_tags(item)):
        return False
    for key, value in hunt.metadata.items():
        if str(item.get(key)) != str(value):
            nested = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            if str(nested.get(key)) != str(value):
                return False
    return True


def exact_search(rows: Iterable[Dict[str, Any]], field: str, value: Any) -> List[Dict[str, Any]]:
    field = safe_text(field)
    expected = safe_text(value)
    return stable_sort([row for row in map(normalize_row, rows) if safe_text(row.get(field)) == expected])


def contains_search(rows: Iterable[Dict[str, Any]], field: str, value: Any) -> List[Dict[str, Any]]:
    field = safe_text(field)
    needle = safe_text(value).lower()
    return stable_sort([row for row in map(normalize_row, rows) if needle in safe_text(row.get(field)).lower()])


def prefix_search(rows: Iterable[Dict[str, Any]], field: str, value: Any) -> List[Dict[str, Any]]:
    field = safe_text(field)
    needle = safe_text(value).lower()
    return stable_sort([row for row in map(normalize_row, rows) if safe_text(row.get(field)).lower().startswith(needle)])


def suffix_search(rows: Iterable[Dict[str, Any]], field: str, value: Any) -> List[Dict[str, Any]]:
    field = safe_text(field)
    needle = safe_text(value).lower()
    return stable_sort([row for row in map(normalize_row, rows) if safe_text(row.get(field)).lower().endswith(needle)])


def deduplicate(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: dict[str, Dict[str, Any]] = {}
    for row in rows:
        item = normalize_row(row)
        deduped[row_identity(item)] = item
    return stable_sort(deduped.values())


def intersection(left: Iterable[Dict[str, Any]], right: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    right_ids = {row_identity(normalize_row(row)) for row in right}
    return stable_sort([normalize_row(row) for row in left if row_identity(normalize_row(row)) in right_ids])


def union(left: Iterable[Dict[str, Any]], right: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return deduplicate([*list(left), *list(right)])


def difference(left: Iterable[Dict[str, Any]], right: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    right_ids = {row_identity(normalize_row(row)) for row in right}
    return stable_sort([normalize_row(row) for row in left if row_identity(normalize_row(row)) not in right_ids])


def stable_sort(
    rows: Iterable[Dict[str, Any]],
    *,
    sort_by: str = "time",
    sort_direction: str = "asc",
) -> List[Dict[str, Any]]:
    normalized = [normalize_row(row) for row in rows]
    reverse = safe_text(sort_direction).lower() == "desc"
    sort_by = safe_text(sort_by, "time").lower()
    return sorted(normalized, key=lambda row: _sort_key(row, sort_by), reverse=reverse)


def apply_offset_limit(rows: Iterable[Dict[str, Any]], *, offset: int = 0, limit: int = 0) -> List[Dict[str, Any]]:
    normalized = list(rows)
    start = safe_int(offset)
    end = start + safe_int(limit) if safe_int(limit) else None
    return normalized[start:end]


def _sort_key(row: Dict[str, Any], sort_by: str) -> tuple[Any, ...]:
    if sort_by == "confidence":
        primary: Any = _row_confidence(row)
    elif sort_by in {"bytes", "byte_count"}:
        primary = safe_int(row.get("byte_count") or row.get("bytes") or row.get("length"))
    elif sort_by in {"packets", "packet_count"}:
        primary = safe_int(row.get("packet_count"))
    elif sort_by == "protocol":
        primary = safe_text(row.get("protocol"), "unknown")
    else:
        primary = _row_time(row)
    return (primary, row_identity(row), safe_text(row))


def _row_time(row: Dict[str, Any]) -> str:
    for key in ("observed_at", "timestamp", "first_observed", "start", "start_time", "created_at"):
        value = safe_text(row.get(key))
        if value != "-":
            return value
    return "-"


def _row_hosts(row: Dict[str, Any]) -> set[str]:
    hosts = {safe_text(row.get("src_ip")), safe_text(row.get("dst_ip")), safe_text(row.get("ip")), safe_text(row.get("host"))}
    for key in ("participants", "hosts"):
        value = row.get(key)
        if isinstance(value, (list, tuple, set)):
            hosts.update(safe_text(item) for item in value)
    return hosts - {"-"}


def _row_macs(row: Dict[str, Any]) -> set[str]:
    return {safe_text(row.get("eth_src")), safe_text(row.get("eth_dst")), safe_text(row.get("mac"))} - {"-"}


def _row_ports(row: Dict[str, Any]) -> set[int]:
    ports = {safe_int(row.get("src_port")), safe_int(row.get("dst_port")), safe_int(row.get("port"))}
    value = row.get("ports")
    if isinstance(value, (list, tuple, set)):
        ports.update(safe_int(item) for item in value)
    return ports - {0}


def _row_confidence(row: Dict[str, Any]) -> float:
    for key in ("confidence", "confidence_score", "activity_score"):
        if key in row:
            return safe_float(row.get(key))
    return 0.0


def _row_tags(row: Dict[str, Any]) -> set[str]:
    tags = set(safe_tags(row.get("tags")))
    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
    tags.update(safe_tags(metadata.get("tags")))
    return tags
