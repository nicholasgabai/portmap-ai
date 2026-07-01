"""Operator summary helpers for packet intelligence integration."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List

from .models import safe_int


def derive_confidence(
    *,
    packet_count: int,
    protocol_count: int,
    conversation_count: int,
    timeline_event_count: int,
    hunt_result_count: int,
    visualization_count: int,
) -> float:
    score = 0.0
    if packet_count:
        score += 0.2
    if protocol_count:
        score += 0.2
    if conversation_count:
        score += 0.2
    if timeline_event_count:
        score += 0.15
    if visualization_count:
        score += 0.15
    if hunt_result_count:
        score += 0.1
    return round(min(1.0, score), 3)


def derive_evidence(
    *,
    packet_count: int,
    protocol_count: int,
    conversation_count: int,
    timeline_event_count: int,
    hunt_result_count: int,
    visualization_count: int,
) -> List[str]:
    evidence = []
    if packet_count:
        evidence.append(f"packet_metadata:{packet_count}")
    if protocol_count:
        evidence.append(f"protocol_records:{protocol_count}")
    if conversation_count:
        evidence.append(f"conversation_summaries:{conversation_count}")
    if timeline_event_count:
        evidence.append(f"timeline_events:{timeline_event_count}")
    if visualization_count:
        evidence.append(f"visualization_models:{visualization_count}")
    if hunt_result_count:
        evidence.append(f"hunt_results:{hunt_result_count}")
    return sorted(evidence)


def derive_limitations(
    *,
    packet_count: int,
    protocol_count: int,
    conversation_count: int,
    timeline_event_count: int,
    hunt_result_count: int,
) -> List[str]:
    limitations = {
        "metadata_only_no_payload_inspection",
        "no_packet_payload_storage",
        "no_packet_payload_display",
        "no_active_capture_or_enforcement",
    }
    if not packet_count:
        limitations.add("no_packet_metadata_available")
    if not protocol_count:
        limitations.add("no_protocol_records_available")
    if not conversation_count:
        limitations.add("no_conversation_history_available")
    if not timeline_event_count:
        limitations.add("no_timeline_events_available")
    if not hunt_result_count:
        limitations.add("no_hunt_results_available")
    return sorted(limitations)


def build_operator_summary(
    *,
    packet_count: int,
    conversation_count: int,
    top_protocol: str,
    top_talker: str,
    risk_signals: Iterable[str],
) -> str:
    risk_count = len(list(risk_signals))
    if not packet_count:
        return "No packet metadata was available for integration."
    return (
        f"Integrated {packet_count} packet metadata records across {conversation_count} conversations; "
        f"top protocol is {top_protocol}, top talker is {top_talker}, and {risk_count} risk-relevant signals were derived."
    )


def build_operator_next_steps(risk_signals: Iterable[str], attribution_hints: Iterable[str]) -> List[str]:
    signals = set(risk_signals)
    hints = set(attribution_hints)
    steps = {"Review packet intelligence summary alongside existing attribution and risk details."}
    if "unknown_protocol_observed" in signals or "unknown_application_protocol" in hints:
        steps.add("Review unknown protocol metadata and confirm expected service identity.")
    if "repeated_sensitive_port" in signals:
        steps.add("Validate repeated sensitive-port observations against expected service exposure.")
    if "insufficient_packet_history" in signals:
        steps.add("Collect additional approved metadata observations before drawing conclusions.")
    if "protocol_transition" in signals:
        steps.add("Compare protocol transition timeline with related flow and conversation metadata.")
    return sorted(steps)


def compact_count_summary(items: Dict[str, Any]) -> Dict[str, int]:
    return {key: safe_int(value) for key, value in sorted(items.items())}
