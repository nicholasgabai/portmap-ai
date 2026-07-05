from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.flows.session_tracking import (
    FLOW_SAFETY_FLAGS,
    FLOW_SESSION_RECORD_VERSION,
    FLOW_SESSION_STATES,
    FlowSessionTrackingError,
    build_session_tracking_record,
    deterministic_session_tracking_json,
    normalize_socket_observations,
)


FLOW_RECONSTRUCTION_RECORD_VERSION = 1
SESSION_CLASSIFICATIONS = {"active", "transient", "recurring", "dormant", "unknown"}


class BidirectionalFlowReconstructionError(ValueError):
    """Raised when bidirectional flow reconstruction inputs are malformed."""


def reconstruct_bidirectional_flows(
    observations: Iterable[dict[str, Any]],
    *,
    previous_observations: Iterable[dict[str, Any]] | None = None,
    dns_correlations: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    try:
        sessions = normalize_socket_observations(
            observations,
            previous_observations=previous_observations,
            generated_at=timestamp,
        )
    except (FlowSessionTrackingError, TypeError) as exc:
        raise BidirectionalFlowReconstructionError(str(exc)) from exc
    dns_index = _dns_index(dns_correlations)
    flow_pairs = build_flow_pairs(sessions, dns_index=dns_index)
    relationships = build_flow_relationships(flow_pairs, generated_at=timestamp)
    inferred = [pair for pair in flow_pairs if pair["session_classification"] in {"active", "recurring", "dormant"}]
    transient = [pair for pair in flow_pairs if pair["session_classification"] == "transient"]
    recurring = [pair for pair in flow_pairs if pair["session_classification"] == "recurring"]
    summary = summarize_bidirectional_flows(sessions=sessions, flow_pairs=flow_pairs, relationships=relationships, generated_at=timestamp)
    return {
        "record_type": "bidirectional_flow_reconstruction_report",
        "record_version": FLOW_RECONSTRUCTION_RECORD_VERSION,
        "report_id": "bidirectional-flow-report-" + _digest({"generated_at": timestamp, "pairs": [row["flow_pair_id"] for row in flow_pairs]})[:16],
        "generated_at": timestamp,
        "normalized_sessions": sessions,
        "flow_pairs": flow_pairs,
        "flow_relationships": relationships,
        "inferred_sessions": inferred,
        "transient_sessions": transient,
        "recurring_sessions": recurring,
        "summary": summary,
        "dashboard_status": build_bidirectional_flow_dashboard_record(summary=summary, flow_pairs=flow_pairs, generated_at=timestamp),
        "api_status": build_bidirectional_flow_api_response(summary=summary, flow_pairs=flow_pairs, relationships=relationships, generated_at=timestamp),
        **FLOW_SAFETY_FLAGS,
    }


def build_flow_pairs(sessions: Iterable[dict[str, Any]], *, dns_index: dict[str, list[dict[str, Any]]] | None = None) -> list[dict[str, Any]]:
    pairs = []
    for session in sessions or []:
        if not isinstance(session, dict):
            continue
        classification = classify_reconstructed_session(session)
        recurrence = score_recurrence(session)
        confidence = score_reconstruction_confidence(session, recurrence_score=recurrence)
        pair = {
            "record_type": "bidirectional_flow_pair",
            "record_version": FLOW_RECONSTRUCTION_RECORD_VERSION,
            "flow_pair_id": "flow-pair-" + _digest(_pair_key(session))[:16],
            "session_ref": session.get("session_id"),
            "session_id": session.get("session_id"),
            "observation_id": session.get("observation_id") or "",
            "source_observation_id": session.get("source_observation_id") or "",
            "flow_key": session.get("flow_key") or "",
            "flow_direction": session.get("flow_direction", "unknown_direction"),
            "local_address": session.get("local_address") or "",
            "remote_address": session.get("remote_address") or "",
            "local_endpoint_class": session.get("local_endpoint_class", "unknown"),
            "remote_endpoint_class": session.get("remote_endpoint_class", "unknown"),
            "local_port": session.get("local_port"),
            "remote_port": session.get("remote_port"),
            "protocol": session.get("protocol", "unknown"),
            "transport_state": session.get("transport_state", "unknown"),
            "evidence_origin": session.get("evidence_origin") or "",
            "observation_type": session.get("observation_type") or "",
            "identity_scope": session.get("identity_scope") or "",
            "process_attribution": session.get("process_attribution", "Unattributed"),
            "service_attribution": session.get("service_attribution", "Unattributed"),
            "source_mode": session.get("source_mode", "unknown"),
            "dns_destination_correlations": _correlations_for(session, dns_index or {}),
            "relationship_strength": score_relationship_strength(session, recurrence_score=recurrence),
            "recurrence_score": recurrence,
            "drift_detected": bool(session.get("session_state") == "dormant" and recurrence >= 0.5),
            "reconstruction_confidence": confidence,
            "session_classification": classification,
            **FLOW_SAFETY_FLAGS,
        }
        pairs.append(pair)
    return sorted(pairs, key=lambda item: str(item.get("flow_pair_id") or ""))


def build_flow_relationships(flow_pairs: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    grouped: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
    for pair in flow_pairs or []:
        if not isinstance(pair, dict):
            continue
        key = (
            pair.get("local_endpoint_class"),
            pair.get("remote_endpoint_class"),
            pair.get("protocol"),
            pair.get("service_attribution"),
            pair.get("flow_direction"),
            pair.get("source_mode"),
        )
        grouped.setdefault(key, []).append(pair)
    relationships = []
    for key, rows in grouped.items():
        relationship_strength = round(sum(float(row.get("relationship_strength") or 0.0) for row in rows) / len(rows), 3)
        recurrence_score = round(sum(float(row.get("recurrence_score") or 0.0) for row in rows) / len(rows), 3)
        classification = _relationship_classification(rows, recurrence_score=recurrence_score)
        relationships.append(
            {
                "record_type": "flow_relationship",
                "record_version": FLOW_RECONSTRUCTION_RECORD_VERSION,
                "relationship_id": "flow-rel-" + _digest({"key": key, "pairs": [row.get("flow_pair_id") for row in rows]})[:16],
                "generated_at": timestamp,
                "local_endpoint_class": key[0],
                "remote_endpoint_class": key[1],
                "protocol": key[2],
                "service_attribution": key[3],
                "flow_direction": key[4],
                "source_mode": key[5],
                "flow_pair_refs": sorted(str(row.get("flow_pair_id") or "") for row in rows),
                "relationship_strength": relationship_strength,
                "recurrence_score": recurrence_score,
                "drift_detected": any(bool(row.get("drift_detected")) for row in rows),
                "reconstruction_confidence": round(sum(float(row.get("reconstruction_confidence") or 0.0) for row in rows) / len(rows), 3),
                "session_classification": classification,
                **FLOW_SAFETY_FLAGS,
            }
        )
    return sorted(relationships, key=lambda item: str(item.get("relationship_id") or ""))


def classify_reconstructed_session(session: dict[str, Any]) -> str:
    state = str(session.get("session_state") or "unknown")
    return state if state in SESSION_CLASSIFICATIONS else "unknown"


def score_relationship_strength(session: dict[str, Any], *, recurrence_score: float = 0.0) -> float:
    score = 0.2
    if session.get("flow_direction") != "unknown_direction":
        score += 0.2
    if session.get("local_port") is not None and session.get("remote_port") is not None:
        score += 0.15
    if session.get("service_attribution") not in {"Unknown", "Unattributed"}:
        score += 0.12
    if session.get("process_attribution") not in {"Unknown", "Unattributed"}:
        score += 0.08
    score += min(float(recurrence_score) * 0.25, 0.25)
    return round(min(1.0, score), 3)


def score_recurrence(session: dict[str, Any]) -> float:
    timestamps = session.get("observed_timestamps") if isinstance(session.get("observed_timestamps"), list) else []
    duration = (session.get("session_duration_preview") or {}).get("duration_seconds") if isinstance(session.get("session_duration_preview"), dict) else 0
    score = min(len(timestamps) / 4, 0.5)
    if int(duration or 0) >= 60:
        score += 0.2
    if session.get("session_state") == "recurring":
        score += 0.3
    return round(min(1.0, score), 3)


def score_reconstruction_confidence(session: dict[str, Any], *, recurrence_score: float = 0.0) -> float:
    base = float(session.get("confidence_score") or 0.0)
    if session.get("flow_direction") == "unknown_direction":
        base -= 0.1
    if session.get("protocol") == "unknown":
        base -= 0.1
    base += min(float(recurrence_score) * 0.15, 0.15)
    return round(max(0.0, min(1.0, base)), 3)


def summarize_bidirectional_flows(
    *,
    sessions: Iterable[dict[str, Any]],
    flow_pairs: Iterable[dict[str, Any]],
    relationships: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    session_rows = [dict(row) for row in sessions or [] if isinstance(row, dict)]
    pair_rows = [dict(row) for row in flow_pairs or [] if isinstance(row, dict)]
    relationship_rows = [dict(row) for row in relationships or [] if isinstance(row, dict)]
    return {
        "record_type": "bidirectional_flow_reconstruction_summary",
        "record_version": FLOW_RECONSTRUCTION_RECORD_VERSION,
        "generated_at": timestamp,
        "session_count": len(session_rows),
        "flow_pair_count": len(pair_rows),
        "relationship_count": len(relationship_rows),
        "inbound_count": sum(1 for row in session_rows if row.get("flow_direction") == "inbound"),
        "outbound_count": sum(1 for row in session_rows if row.get("flow_direction") == "outbound"),
        "loopback_count": sum(1 for row in session_rows if row.get("flow_direction") == "local_loopback"),
        "unknown_direction_count": sum(1 for row in session_rows if row.get("flow_direction") == "unknown_direction"),
        "transient_count": sum(1 for row in pair_rows if row.get("session_classification") == "transient"),
        "recurring_count": sum(1 for row in pair_rows if row.get("session_classification") == "recurring"),
        "dormant_count": sum(1 for row in pair_rows if row.get("session_classification") == "dormant"),
        "drift_detected_count": sum(1 for row in pair_rows if row.get("drift_detected")),
        "average_relationship_strength": _average(pair_rows, "relationship_strength"),
        "average_reconstruction_confidence": _average(pair_rows, "reconstruction_confidence"),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in pair_rows}) or ["unknown"],
        **FLOW_SAFETY_FLAGS,
    }


def build_bidirectional_flow_dashboard_record(*, summary: dict[str, Any], flow_pairs: Iterable[dict[str, Any]], generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in flow_pairs or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("unknown_direction_count") or 0) or int(summary.get("drift_detected_count") or 0) else "ok"
    return {
        "record_type": "bidirectional_flow_dashboard",
        "panel": "bidirectional_flow_reconstruction",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "session_count": int(summary.get("session_count") or 0),
            "flow_pair_count": int(summary.get("flow_pair_count") or 0),
            "relationship_count": int(summary.get("relationship_count") or 0),
            "recurring_count": int(summary.get("recurring_count") or 0),
            "transient_count": int(summary.get("transient_count") or 0),
            "average_reconstruction_confidence": float(summary.get("average_reconstruction_confidence") or 0.0),
        },
        "rows": [
            {
                "flow_pair_id": row.get("flow_pair_id"),
                "observation_id": row.get("observation_id"),
                "flow_key": row.get("flow_key"),
                "session_id": row.get("session_id") or row.get("session_ref"),
                "evidence_origin": row.get("evidence_origin"),
                "observation_type": row.get("observation_type"),
                "identity_scope": row.get("identity_scope"),
                "flow_direction": row.get("flow_direction"),
                "protocol": row.get("protocol"),
                "service_attribution": row.get("service_attribution"),
                "session_classification": row.get("session_classification"),
                "relationship_strength": row.get("relationship_strength"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status == "review_required",
        **FLOW_SAFETY_FLAGS,
    }


def build_bidirectional_flow_api_response(
    *,
    summary: dict[str, Any],
    flow_pairs: Iterable[dict[str, Any]],
    relationships: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in flow_pairs or [] if isinstance(row, dict)]
    relationship_rows = [dict(row) for row in relationships or [] if isinstance(row, dict)]
    return {
        "record_type": "bidirectional_flow_api",
        "status": "ok" if int(summary.get("unknown_direction_count") or 0) == 0 else "review_required",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "flow_pairs": rows,
        "flow_relationships": relationship_rows,
        **FLOW_SAFETY_FLAGS,
    }


def deterministic_bidirectional_flow_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _pair_key(session: dict[str, Any]) -> dict[str, Any]:
    return {
        "flow_direction": session.get("flow_direction"),
        "local_endpoint_class": session.get("local_endpoint_class"),
        "remote_endpoint_class": session.get("remote_endpoint_class"),
        "local_port": session.get("local_port"),
        "remote_port": session.get("remote_port"),
        "protocol": session.get("protocol"),
        "process_attribution": session.get("process_attribution"),
        "service_attribution": session.get("service_attribution"),
        "source_mode": session.get("source_mode"),
    }


def _dns_index(dns_correlations: Iterable[dict[str, Any]] | None) -> dict[str, list[dict[str, Any]]]:
    index: dict[str, list[dict[str, Any]]] = {}
    for row in dns_correlations or []:
        if not isinstance(row, dict):
            continue
        service = str(row.get("service_attribution") or row.get("service_name") or "unknown")
        index.setdefault(service, []).append({"domain_summary": str(row.get("domain_summary") or row.get("domain") or "redacted"), "confidence": float(row.get("confidence") or 0.0)})
    return index


def _correlations_for(session: dict[str, Any], dns_index: dict[str, list[dict[str, Any]]]) -> list[dict[str, Any]]:
    service = str(session.get("service_attribution") or "unknown")
    return list(dns_index.get(service) or [])


def _relationship_classification(rows: list[dict[str, Any]], *, recurrence_score: float) -> str:
    states = {str(row.get("session_classification") or "unknown") for row in rows}
    if "recurring" in states or recurrence_score >= 0.6:
        return "recurring"
    if "active" in states:
        return "active"
    if "dormant" in states:
        return "dormant"
    if "transient" in states:
        return "transient"
    return "unknown"


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
