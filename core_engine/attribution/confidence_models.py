from __future__ import annotations

import json
from typing import Any


ATTRIBUTION_CONFIDENCE_RECORD_VERSION = 1
ATTRIBUTION_STATES = {"attributed", "probable", "possible", "unattributed", "conflicting", "unknown"}

ATTRIBUTION_SAFETY_FLAGS = {
    "local_only": True,
    "metadata_only": True,
    "advisory_only": True,
    "read_only": True,
    "raw_payload_stored": False,
    "raw_packet_stored": False,
    "packet_payload_inspected": False,
    "pcap_generated": False,
    "raw_dns_history_stored": False,
    "credential_material_stored": False,
    "hostname_stored": False,
    "ip_address_stored": False,
    "mac_address_stored": False,
    "username_stored": False,
    "hardcoded_live_identity": False,
    "automatic_changes": False,
    "enforcement_enabled": False,
}


def score_application_attribution_confidence(
    *,
    process_confidence: float = 0.0,
    service_confidence: float = 0.0,
    protocol_confidence: float = 0.0,
    destination_confidence: float = 0.0,
    flow_confidence: float = 0.0,
    recurrence_confidence: float = 0.0,
    conflict_penalty: float = 0.0,
) -> float:
    """Combine bounded metadata confidence signals into one advisory score."""
    weighted = (
        _clamp(process_confidence) * 0.22
        + _clamp(service_confidence) * 0.2
        + _clamp(protocol_confidence) * 0.16
        + _clamp(destination_confidence) * 0.13
        + _clamp(flow_confidence) * 0.15
        + _clamp(recurrence_confidence) * 0.14
    )
    return round(max(0.0, min(1.0, weighted - _clamp(conflict_penalty))), 3)


def classify_attribution_state(
    *,
    confidence_score: float,
    unresolved: bool = False,
    conflicting: bool = False,
    malformed: bool = False,
) -> str:
    if malformed:
        return "unknown"
    if conflicting:
        return "conflicting"
    if unresolved:
        return "unattributed"
    score = _clamp(confidence_score)
    if score >= 0.82:
        return "attributed"
    if score >= 0.6:
        return "probable"
    if score >= 0.32:
        return "possible"
    return "unattributed"


def build_confidence_breakdown(
    *,
    process_confidence: float = 0.0,
    service_confidence: float = 0.0,
    protocol_confidence: float = 0.0,
    destination_confidence: float = 0.0,
    flow_confidence: float = 0.0,
    recurrence_confidence: float = 0.0,
    conflict_penalty: float = 0.0,
) -> dict[str, Any]:
    score = score_application_attribution_confidence(
        process_confidence=process_confidence,
        service_confidence=service_confidence,
        protocol_confidence=protocol_confidence,
        destination_confidence=destination_confidence,
        flow_confidence=flow_confidence,
        recurrence_confidence=recurrence_confidence,
        conflict_penalty=conflict_penalty,
    )
    return {
        "record_type": "application_attribution_confidence",
        "record_version": ATTRIBUTION_CONFIDENCE_RECORD_VERSION,
        "process_confidence": _clamp(process_confidence),
        "service_confidence": _clamp(service_confidence),
        "protocol_confidence": _clamp(protocol_confidence),
        "destination_confidence": _clamp(destination_confidence),
        "flow_confidence": _clamp(flow_confidence),
        "recurrence_confidence": _clamp(recurrence_confidence),
        "conflict_penalty": _clamp(conflict_penalty),
        "confidence_score": score,
        "confidence_level": confidence_level(score),
        **ATTRIBUTION_SAFETY_FLAGS,
    }


def confidence_level(score: float) -> str:
    value = _clamp(score)
    if value >= 0.82:
        return "high"
    if value >= 0.6:
        return "medium"
    if value >= 0.32:
        return "low"
    return "minimal"


def deterministic_confidence_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _clamp(value: Any) -> float:
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 0.0
    return round(max(0.0, min(1.0, number)), 3)
