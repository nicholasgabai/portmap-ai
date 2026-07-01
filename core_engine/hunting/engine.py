"""Deterministic packet hunting engine."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from core_engine.capture import PacketMetadata
from core_engine.timeline import build_timeline_sessions
from core_engine.timeline.models import TimelineEvent

from .filters import apply_offset_limit, match_row, normalize_row, stable_sort
from .models import HuntQuery, safe_metadata
from .results import HuntResult


class PacketHuntEngine:
    """Search metadata-only packet intelligence artifacts."""

    def search(
        self,
        query: HuntQuery | Dict[str, Any] | None = None,
        *,
        packets: Iterable[PacketMetadata | Dict[str, Any]] | None = None,
        protocol_records: Iterable[Dict[str, Any]] | None = None,
        timeline_events: Iterable[TimelineEvent | Dict[str, Any]] | None = None,
        conversations: Iterable[Dict[str, Any]] | None = None,
        sessions: Iterable[Dict[str, Any]] | None = None,
        visualizations: Iterable[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        hunt = HuntQuery.from_dict(query or {})
        packet_rows = [PacketMetadata.from_dict(packet).to_dict() for packet in packets or []]
        packet_by_id = {row["packet_id"]: row for row in packet_rows}
        protocol_rows = [_enrich_protocol_record(safe_metadata(dict(record or {})), packet_by_id) for record in protocol_records or []]
        timeline_rows = [TimelineEvent.from_dict(event).to_dict() for event in timeline_events or []]
        conversation_rows = [safe_metadata(dict(row or {})) for row in conversations or []]
        session_rows = [safe_metadata(dict(row or {})) for row in sessions] if sessions is not None else build_timeline_sessions(timeline_rows)
        visualization_rows = [safe_metadata(dict(row or {})) for row in visualizations or []]

        matched_packets = _page(_search_rows(packet_rows, hunt), hunt)
        matched_protocols = _page(_search_rows(protocol_rows, hunt), hunt)
        matched_timeline = _page(_search_rows(timeline_rows, hunt), hunt)
        matched_conversations = _page(_search_rows(conversation_rows, hunt), hunt)
        related_session_ids = {
            row.get("session_id")
            for row in [*matched_packets, *matched_protocols, *matched_timeline]
            if row.get("session_id") not in {None, "", "-"}
        }
        matched_sessions = _page(
            stable_sort(
                [
                    row
                    for row in session_rows
                    if match_row(row, hunt) or row.get("session_id") in related_session_ids
                ],
                sort_by=hunt.sort_by,
                sort_direction=hunt.sort_direction,
            ),
            hunt,
        )
        matched_visualizations = _page(_search_visualizations(visualization_rows, hunt), hunt)

        metadata = _correlation_metadata(
            packets=matched_packets,
            protocols=matched_protocols,
            timeline_events=matched_timeline,
            conversations=matched_conversations,
            sessions=matched_sessions,
            visualizations=matched_visualizations,
        )
        return HuntResult.create(
            query_id=hunt.query_id,
            matched_packets=matched_packets,
            matched_protocols=matched_protocols,
            matched_conversations=matched_conversations,
            matched_sessions=matched_sessions,
            matched_timeline_events=matched_timeline,
            matched_visualizations=matched_visualizations,
            metadata=metadata,
        ).to_dict()


def search_packets(query: HuntQuery | Dict[str, Any] | None = None, **kwargs: Any) -> Dict[str, Any]:
    return PacketHuntEngine().search(query, **kwargs)


def _search_rows(rows: Iterable[Dict[str, Any]], query: HuntQuery) -> List[Dict[str, Any]]:
    return stable_sort(
        [normalize_row(row) for row in rows if match_row(row, query)],
        sort_by=query.sort_by,
        sort_direction=query.sort_direction,
    )


def _enrich_protocol_record(record: Dict[str, Any], packet_by_id: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    packet = packet_by_id.get(record.get("packet_id"), {})
    enriched = dict(record)
    for key in ("interface", "eth_src", "eth_dst", "tags", "direction"):
        if key not in enriched and key in packet:
            enriched[key] = packet[key]
    return safe_metadata(enriched)


def _page(rows: List[Dict[str, Any]], query: HuntQuery) -> List[Dict[str, Any]]:
    return apply_offset_limit(rows, offset=query.offset, limit=query.limit)


def _search_visualizations(rows: Iterable[Dict[str, Any]], query: HuntQuery) -> List[Dict[str, Any]]:
    matches = []
    for row in rows:
        item = normalize_row(row)
        if match_row(item, query) or any(match_row(nested, query) for nested in _nested_dicts(item)):
            matches.append(item)
    return stable_sort(matches, sort_by=query.sort_by, sort_direction=query.sort_direction)


def _nested_dicts(value: Any) -> List[Dict[str, Any]]:
    nested: list[Dict[str, Any]] = []
    if isinstance(value, dict):
        nested.append(safe_metadata(value))
        for item in value.values():
            nested.extend(_nested_dicts(item))
    elif isinstance(value, list):
        for item in value:
            nested.extend(_nested_dicts(item))
    return nested


def _correlation_metadata(
    *,
    packets: List[Dict[str, Any]],
    protocols: List[Dict[str, Any]],
    timeline_events: List[Dict[str, Any]],
    conversations: List[Dict[str, Any]],
    sessions: List[Dict[str, Any]],
    visualizations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    rows = packets + protocols + timeline_events + conversations + sessions + visualizations
    return {
        "related_hosts": sorted(
            {
                host
                for row in rows
                for host in (row.get("src_ip"), row.get("dst_ip"), row.get("ip"), row.get("host"))
                if host not in {None, "", "-"}
            }
        ),
        "related_conversations": sorted(
            {row.get("conversation_id") for row in rows if row.get("conversation_id") not in {None, "", "-"}}
        ),
        "related_sessions": sorted({row.get("session_id") for row in rows if row.get("session_id") not in {None, "", "-"}}),
        "related_flows": sorted({row.get("flow_key") for row in rows if row.get("flow_key") not in {None, "", "-"}}),
        "related_timeline_events": sorted({row.get("event_id") for row in timeline_events if row.get("event_id") not in {None, "", "-"}}),
    }
