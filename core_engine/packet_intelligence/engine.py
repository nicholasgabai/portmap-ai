"""Packet intelligence integration engine."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from core_engine.capture import PacketMetadata
from core_engine.protocols import classify_packets, summarize_conversations
from core_engine.timeline import build_packet_timeline
from core_engine.visualization import (
    build_network_snapshot,
    build_port_distribution,
    build_protocol_distribution,
    build_timeline_model,
    build_top_talkers,
)

from .correlation import (
    correlate_hunt_results,
    correlate_visualizations,
    derive_attribution_hints,
    derive_behavior_graph_hints,
    derive_risk_relevant_signals,
)
from .models import PacketIntelligenceSummary, safe_metadata, safe_text, stable_id
from .statistics import (
    hunting_summary,
    packet_activity_summary,
    timeline_summary,
    top_conversation,
    top_flow,
    top_protocol,
    top_talker,
    traffic_direction_summary,
    visualization_summary,
)
from .summaries import (
    build_operator_next_steps,
    build_operator_summary,
    derive_confidence,
    derive_evidence,
    derive_limitations,
)


class PacketIntelligenceEngine:
    """Compose packet metadata intelligence into compact summary records."""

    def summarize(
        self,
        *,
        packets: Iterable[PacketMetadata | Dict[str, Any]] | None = None,
        protocol_records: Iterable[Dict[str, Any]] | None = None,
        timeline_events: Iterable[Dict[str, Any]] | None = None,
        visualization_models: Iterable[Dict[str, Any]] | None = None,
        hunt_results: Iterable[Dict[str, Any]] | None = None,
        conversations: Iterable[Dict[str, Any]] | None = None,
        generated_at: str = "-",
        metadata: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        packet_rows = [PacketMetadata.from_dict(packet).to_dict() for packet in packets or []]
        protocol_rows = (
            [safe_metadata(dict(row or {})) for row in protocol_records]
            if protocol_records is not None
            else classify_packets(packet_rows)
        )
        conversation_rows = (
            [safe_metadata(dict(row or {})) for row in conversations]
            if conversations is not None
            else summarize_conversations(packet_rows)
        )
        timeline_rows = (
            [safe_metadata(dict(row or {})) for row in timeline_events]
            if timeline_events is not None
            else build_packet_timeline(packet_rows, protocol_records=protocol_rows, conversations=conversation_rows)
        )
        visualization_rows = (
            [safe_metadata(dict(row or {})) for row in visualization_models]
            if visualization_models is not None
            else _build_default_visualizations(
                protocol_records=protocol_rows,
                conversations=conversation_rows,
                timeline_events=timeline_rows,
            )
        )
        hunt_rows = [safe_metadata(dict(row or {})) for row in hunt_results or []]

        packet_rows = _sort_rows(packet_rows, "packet_id")
        protocol_rows = _sort_rows(protocol_rows, "protocol_id")
        conversation_rows = _sort_rows(conversation_rows, "conversation_id")
        timeline_rows = _sort_rows(timeline_rows, "event_id")
        visualization_rows = _sort_visualizations(visualization_rows)
        hunt_rows = _sort_rows(hunt_rows, "result_id")

        protocol_distribution = build_protocol_distribution(protocol_rows, conversations=conversation_rows)
        port_distribution = build_port_distribution(protocol_rows, conversations=conversation_rows)
        top_talkers = build_top_talkers(conversation_rows)
        top_talker_value = top_talker(conversation_rows)
        risk_signals = derive_risk_relevant_signals(protocol_rows, timeline_rows, hunt_rows, conversation_rows)
        attribution_hints = derive_attribution_hints(protocol_rows, conversation_rows)
        behavior_hints = derive_behavior_graph_hints(protocol_rows, timeline_rows, conversation_rows)
        visualization_stats = visualization_summary(visualization_rows)
        hunt_stats = hunting_summary(hunt_rows)
        timeline_stats = timeline_summary(timeline_rows)
        activity_stats = packet_activity_summary(packet_rows, conversation_rows)
        direction_stats = traffic_direction_summary(packet_rows, timeline_rows)
        confidence = derive_confidence(
            packet_count=len(packet_rows),
            protocol_count=len(protocol_rows),
            conversation_count=len(conversation_rows),
            timeline_event_count=len(timeline_rows),
            hunt_result_count=len(hunt_rows),
            visualization_count=len(visualization_rows),
        )
        evidence = derive_evidence(
            packet_count=len(packet_rows),
            protocol_count=len(protocol_rows),
            conversation_count=len(conversation_rows),
            timeline_event_count=len(timeline_rows),
            hunt_result_count=len(hunt_rows),
            visualization_count=len(visualization_rows),
        )
        limitations = derive_limitations(
            packet_count=len(packet_rows),
            protocol_count=len(protocol_rows),
            conversation_count=len(conversation_rows),
            timeline_event_count=len(timeline_rows),
            hunt_result_count=len(hunt_rows),
        )
        flow_keys = sorted({safe_text(row.get("flow_key")) for row in conversation_rows if safe_text(row.get("flow_key")) != "-"})
        summary_basis = {
            "generated_at": safe_text(generated_at),
            "packets": [row.get("packet_id", "-") for row in packet_rows],
            "protocols": [row.get("protocol_id", "-") for row in protocol_rows],
            "conversations": [row.get("conversation_id", "-") for row in conversation_rows],
            "timeline": [row.get("event_id", "-") for row in timeline_rows],
            "visualizations": [_visualization_id(row) for row in visualization_rows],
            "hunts": [row.get("result_id", "-") for row in hunt_rows],
            "risk_signals": risk_signals,
            "attribution_hints": attribution_hints,
            "behavior_hints": behavior_hints,
        }
        summary = PacketIntelligenceSummary(
            summary_id=stable_id("packet-intelligence", summary_basis),
            generated_at=safe_text(generated_at),
            packet_count=len(packet_rows),
            protocol_count=len(protocol_rows),
            conversation_count=len(conversation_rows),
            flow_count=len(flow_keys),
            timeline_event_count=len(timeline_rows),
            hunt_result_count=len(hunt_rows),
            top_protocol=top_protocol(protocol_rows),
            top_talker=top_talker_value,
            top_conversation=top_conversation(conversation_rows),
            top_flow=top_flow(conversation_rows),
            protocol_distribution=protocol_distribution,
            port_distribution=port_distribution,
            traffic_direction_summary=direction_stats,
            packet_activity_summary=activity_stats,
            hunting_summary=hunt_stats,
            timeline_summary=timeline_stats,
            visualization_summary=visualization_stats,
            risk_relevant_signals=risk_signals,
            attribution_hints=attribution_hints,
            behavior_graph_hints=behavior_hints,
            confidence=confidence,
            evidence=evidence,
            limitations=limitations,
            operator_summary=build_operator_summary(
                packet_count=len(packet_rows),
                conversation_count=len(conversation_rows),
                top_protocol=top_protocol(protocol_rows),
                top_talker=top_talker_value,
                risk_signals=risk_signals,
            ),
            operator_next_steps=build_operator_next_steps(risk_signals, attribution_hints),
            metadata={
                **safe_metadata(metadata or {}),
                "hunt_correlation": correlate_hunt_results(hunt_rows),
                "visualization_correlation": correlate_visualizations(visualization_rows),
                "top_talkers": top_talkers,
            },
        )
        return summary.to_dict()


def build_packet_intelligence_summary(**kwargs: Any) -> Dict[str, Any]:
    return PacketIntelligenceEngine().summarize(**kwargs)


def _build_default_visualizations(
    *,
    protocol_records: List[Dict[str, Any]],
    conversations: List[Dict[str, Any]],
    timeline_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    if not protocol_records and not conversations and not timeline_events:
        return []
    return [
        build_timeline_model(timeline_events),
        build_protocol_distribution(protocol_records, conversations=conversations),
        build_port_distribution(protocol_records, conversations=conversations),
        build_network_snapshot(
            events=timeline_events,
            protocol_records=protocol_records,
            conversations=conversations,
        ),
    ]


def _sort_rows(rows: Iterable[Dict[str, Any]], identity_key: str) -> List[Dict[str, Any]]:
    return sorted(
        [safe_metadata(dict(row or {})) for row in rows],
        key=lambda row: (
            safe_text(row.get("observed_at") or row.get("timestamp") or row.get("first_observed") or row.get("start_time")),
            safe_text(row.get(identity_key)),
            safe_text(row),
        ),
    )


def _sort_visualizations(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return sorted([safe_metadata(dict(row or {})) for row in rows], key=lambda row: (_visualization_id(row), safe_text(row)))


def _visualization_id(row: Dict[str, Any]) -> str:
    for key in (
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
    return "visualization:-"
