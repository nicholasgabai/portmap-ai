"""Timeline engine for packet metadata and protocol intelligence."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from core_engine.capture import PacketMetadata
from core_engine.protocols import classify_packets, summarize_conversations

from .models import TimelineEvent, event_sort_key, safe_text, stable_id


class PacketTimelineEngine:
    """Build deterministic metadata-only timeline events."""

    def build_timeline(
        self,
        packets: Iterable[PacketMetadata | Dict[str, Any]],
        *,
        protocol_records: Iterable[Dict[str, Any]] | None = None,
        conversations: Iterable[Dict[str, Any]] | None = None,
        include_lifecycle: bool = True,
    ) -> List[Dict[str, Any]]:
        normalized_packets = [PacketMetadata.from_dict(packet) for packet in packets]
        records = list(protocol_records) if protocol_records is not None else classify_packets(normalized_packets)
        conversations_list = list(conversations) if conversations is not None else summarize_conversations(normalized_packets)
        record_by_packet = {record["packet_id"]: record for record in records}
        conversation_by_flow = {conversation["flow_key"]: conversation for conversation in conversations_list}
        events: list[TimelineEvent] = []

        if include_lifecycle:
            events.extend(_conversation_lifecycle_events(conversations_list))

        for packet in sorted(normalized_packets, key=lambda item: (item.observed_at, item.packet_id)):
            record = record_by_packet.get(packet.packet_id, {})
            conversation = conversation_by_flow.get(packet.flow_key, {})
            base = _base_event(packet, record, conversation)
            events.append(
                TimelineEvent.from_dict(
                    {
                        **base,
                        "event_type": "packet_observed",
                        "importance": "normal",
                        "summary": f"Packet metadata observed for {base['protocol']} on {packet.interface}.",
                        "tags": ["packet", "metadata_only"],
                    }
                )
            )
            if record:
                events.append(
                    TimelineEvent.from_dict(
                        {
                            **base,
                            "event_type": "protocol_detected",
                            "importance": _importance_from_confidence(record.get("confidence")),
                            "summary": f"Protocol {record.get('protocol', 'unknown')} detected from metadata.",
                            "evidence": record.get("evidence", []),
                            "tags": ["protocol", "metadata_only"],
                        }
                    )
                )

        return export_timeline(events)


def build_packet_timeline(
    packets: Iterable[PacketMetadata | Dict[str, Any]],
    *,
    protocol_records: Iterable[Dict[str, Any]] | None = None,
    conversations: Iterable[Dict[str, Any]] | None = None,
) -> List[Dict[str, Any]]:
    return PacketTimelineEngine().build_timeline(
        packets,
        protocol_records=protocol_records,
        conversations=conversations,
    )


def merge_timelines(*timelines: Iterable[TimelineEvent | Dict[str, Any]]) -> List[Dict[str, Any]]:
    merged: dict[str, TimelineEvent] = {}
    for timeline in timelines:
        for event in timeline:
            item = TimelineEvent.from_dict(event)
            merged[item.event_id] = item
    merge_marker = TimelineEvent.from_dict(
        {
            "timestamp": "-",
            "event_type": "timeline_merge",
            "summary": f"Merged {len(timelines)} timelines with duplicate suppression.",
            "importance": "low",
            "confidence": 1.0,
            "tags": ["timeline_merge", "metadata_only"],
        }
    )
    if timelines:
        merged[merge_marker.event_id] = merge_marker
    return export_timeline(merged.values())


def export_timeline(events: Iterable[TimelineEvent | Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = [TimelineEvent.from_dict(event) for event in events]
    return [event.to_dict() for event in sorted(normalized, key=event_sort_key)]


def timeline_export_summary(events: Iterable[TimelineEvent | Dict[str, Any]]) -> Dict[str, Any]:
    exported = export_timeline(events)
    return {
        "event_count": len(exported),
        "first_event": exported[0]["event_id"] if exported else "-",
        "last_event": exported[-1]["event_id"] if exported else "-",
        "events": exported,
    }


def _base_event(packet: PacketMetadata, record: Dict[str, Any], conversation: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": packet.observed_at,
        "packet_id": packet.packet_id,
        "protocol_id": record.get("protocol_id", "-"),
        "session_id": packet.session_id,
        "conversation_id": conversation.get("conversation_id", "-"),
        "flow_key": packet.flow_key,
        "interface": packet.interface,
        "protocol": safe_text(record.get("protocol"), safe_text(packet.protocol, "unknown").lower()),
        "application_protocol": safe_text(record.get("application_protocol")),
        "transport_protocol": safe_text(record.get("transport_protocol"), safe_text(packet.protocol).lower()),
        "src_ip": packet.src_ip,
        "dst_ip": packet.dst_ip,
        "src_port": packet.src_port,
        "dst_port": packet.dst_port,
        "direction": packet.direction,
        "confidence": record.get("confidence", 0.0),
        "metadata": {
            "length": packet.length,
            "captured_length": packet.captured_length,
            "payload_length": packet.payload_length,
        },
    }


def _conversation_lifecycle_events(conversations: Iterable[Dict[str, Any]]) -> List[TimelineEvent]:
    events: list[TimelineEvent] = []
    for conversation in sorted(conversations, key=lambda item: (item.get("first_observed", "-"), item.get("conversation_id", "-"))):
        first = conversation.get("first_observed", "-")
        last = conversation.get("last_observed", "-")
        base = {
            "conversation_id": conversation.get("conversation_id", "-"),
            "flow_key": conversation.get("flow_key", "-"),
            "protocol": conversation.get("protocol", "unknown"),
            "src_ip": conversation.get("src_ip", "-"),
            "dst_ip": conversation.get("dst_ip", "-"),
            "src_port": conversation.get("src_port", 0),
            "dst_port": conversation.get("dst_port", 0),
            "direction": conversation.get("direction", "unknown"),
            "confidence": conversation.get("confidence", 0.0),
            "evidence": [conversation.get("evidence_summary", "metadata_only")],
            "tags": ["conversation", "metadata_only"],
            "metadata": {
                "packet_count": conversation.get("packet_count", 0),
                "byte_count": conversation.get("byte_count", 0),
            },
        }
        events.append(
            TimelineEvent.from_dict(
                {
                    **base,
                    "timestamp": first,
                    "event_type": "conversation_started",
                    "importance": "normal",
                    "summary": f"Conversation started for {conversation.get('protocol', 'unknown')}.",
                }
            )
        )
        events.append(
            TimelineEvent.from_dict(
                {
                    **base,
                    "timestamp": last,
                    "event_type": "conversation_updated",
                    "importance": "normal",
                    "summary": f"Conversation updated with {conversation.get('packet_count', 0)} packets.",
                }
            )
        )
        events.append(
            TimelineEvent.from_dict(
                {
                    **base,
                    "timestamp": last,
                    "event_type": "conversation_completed",
                    "importance": "low",
                    "summary": "Conversation metadata window completed.",
                }
            )
        )
    return events


def timeline_gap_event(previous: Dict[str, Any], current: Dict[str, Any], *, gap_seconds: int) -> Dict[str, Any]:
    return TimelineEvent.from_dict(
        {
            "timestamp": current.get("timestamp", "-"),
            "event_type": "timeline_gap",
            "flow_key": current.get("flow_key", "-"),
            "importance": "medium",
            "confidence": 1.0,
            "summary": f"Timeline gap of {gap_seconds}s detected.",
            "evidence": [previous.get("event_id", "-"), current.get("event_id", "-")],
            "metadata": {"gap_seconds": gap_seconds},
        }
    ).to_dict()


def flow_lifecycle_events(conversations: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    events: list[TimelineEvent] = []
    for conversation in conversations:
        basis = {
            "conversation_id": conversation.get("conversation_id", "-"),
            "flow_key": conversation.get("flow_key", "-"),
            "protocol": conversation.get("protocol", "unknown"),
            "src_ip": conversation.get("src_ip", "-"),
            "dst_ip": conversation.get("dst_ip", "-"),
            "src_port": conversation.get("src_port", 0),
            "dst_port": conversation.get("dst_port", 0),
            "direction": conversation.get("direction", "unknown"),
            "confidence": conversation.get("confidence", 0.0),
            "tags": ["flow", "metadata_only"],
        }
        for event_type, timestamp, summary in (
            ("flow_created", conversation.get("first_observed", "-"), "Flow metadata created."),
            ("flow_updated", conversation.get("last_observed", "-"), "Flow metadata updated."),
            ("flow_completed", conversation.get("last_observed", "-"), "Flow metadata completed."),
        ):
            events.append(TimelineEvent.from_dict({**basis, "event_type": event_type, "timestamp": timestamp, "summary": summary}))
    return export_timeline(events)


def _importance_from_confidence(value: Any) -> str:
    try:
        confidence = float(value)
    except Exception:
        confidence = 0.0
    if confidence >= 0.8:
        return "high"
    if confidence >= 0.5:
        return "normal"
    return "low"
