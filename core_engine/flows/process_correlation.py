from __future__ import annotations

import json
from hashlib import sha256
from typing import Any, Iterable

from core_engine.time_utils import normalize_timestamp, utc_now_iso
from core_engine.flows.session_tracking import FLOW_SAFETY_FLAGS
from core_engine.telemetry.process_attribution import normalize_source_mode


PROCESS_CORRELATION_RECORD_VERSION = 1
PROCESS_ATTRIBUTION_STATES = {"attributed", "partially_attributed", "unattributed", "conflicting", "unknown"}
DEMO_ATTRIBUTION_LABELS = {"dummy_app", "dummy_db"}


class ProcessCorrelationError(ValueError):
    """Raised when process correlation inputs are malformed."""


def build_process_correlation_record(
    session_record: dict[str, Any] | None,
    *,
    process_attribution: Any = None,
    service_attribution: Any = None,
    attribution_source: str = "unknown",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = normalize_timestamp(generated_at or _now(), preserve_ambiguous=True)
    if session_record is not None and not isinstance(session_record, dict):
        raise ProcessCorrelationError("session_record must be an object")
    session = dict(session_record or {})
    mode = normalize_source_mode(
        session.get("source_mode")
        or session.get("data_source")
        or _source_mode_from_value(process_attribution)
        or _source_mode_from_value(service_attribution)
        or "unknown"
    )
    process_value = _safe_attribution(
        process_attribution if process_attribution is not None else session.get("process_attribution"),
        source_mode=mode,
        fallback="Unknown",
    )
    service_value = _safe_attribution(
        service_attribution if service_attribution is not None else session.get("service_attribution"),
        source_mode=mode,
        fallback="Unattributed",
    )
    conflict_reason = _conflict_reason(
        session=session,
        process_value=process_value,
        service_value=service_value,
        raw_process=process_attribution,
        raw_service=service_attribution,
        source_mode=mode,
    )
    state = _attribution_state(process_value=process_value, service_value=service_value, conflict_reason=conflict_reason, session=session)
    confidence = score_process_attribution_confidence(
        attribution_state=state,
        process_attribution=process_value,
        service_attribution=service_value,
        attribution_source=attribution_source,
        session=session,
    )
    record = {
        "record_type": "process_flow_correlation",
        "record_version": PROCESS_CORRELATION_RECORD_VERSION,
        "process_correlation_id": "process-correlation-"
        + _digest(
            {
                "session_reference": session.get("session_id") or "",
                "process_attribution": process_value,
                "service_attribution": service_value,
                "attribution_source": attribution_source,
                "source_mode": mode,
            }
        )[:16],
        "generated_at": timestamp,
        "observation_id": _first_text(session, ("observation_id", "event_id", "record_id")),
        "flow_key": _first_text(session, ("flow_key", "flow_id")),
        "session_id": _first_text(session, ("session_id", "session_ref", "session_reference")),
        "local_address": _first_text(session, ("local_address", "source_ip", "src_ip")),
        "remote_address": _first_text(session, ("remote_address", "destination_ip", "dst_ip")),
        "local_port": session.get("local_port") if session.get("local_port") not in {None, ""} else session.get("port"),
        "remote_port": session.get("remote_port"),
        "protocol": _first_text(session, ("protocol", "transport", "transport_protocol")),
        "socket_state": _first_text(session, ("transport_state", "socket_state", "state", "status")),
        "evidence_origin": _identity_text(session, "evidence_origin"),
        "observation_type": _identity_text(session, "observation_type"),
        "identity_scope": _identity_text(session, "identity_scope"),
        "session_reference": str(session.get("session_id") or ""),
        "flow_reference": str(session.get("flow_pair_id") or session.get("flow_ref") or ""),
        "process_attribution": process_value,
        "service_attribution": service_value,
        "attribution_source": _safe_token(attribution_source),
        "attribution_confidence": confidence,
        "attribution_state": state,
        "conflict_reason": conflict_reason,
        "operator_summary": _operator_summary(state=state, process_value=process_value, service_value=service_value, conflict_reason=conflict_reason, source_mode=mode),
        "source_mode": mode,
        "data_source": mode,
        **FLOW_SAFETY_FLAGS,
    }
    return record


def build_process_correlation_report(
    sessions: Iterable[dict[str, Any]],
    *,
    process_attributions: Iterable[dict[str, Any]] | None = None,
    service_attributions: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = normalize_timestamp(generated_at or _now(), preserve_ambiguous=True)
    try:
        session_rows = [dict(row) for row in sessions or [] if isinstance(row, dict)]
    except TypeError as exc:
        raise ProcessCorrelationError("sessions must be iterable") from exc
    process_index = _attribution_index(process_attributions)
    service_index = _attribution_index(service_attributions)
    correlations = [
        build_process_correlation_record(
            session,
            process_attribution=process_index.get(str(session.get("session_id") or "")),
            service_attribution=service_index.get(str(session.get("session_id") or "")),
            generated_at=timestamp,
        )
        for session in session_rows
    ]
    summary = summarize_process_correlations(correlations, generated_at=timestamp)
    return {
        "record_type": "process_correlation_report",
        "record_version": PROCESS_CORRELATION_RECORD_VERSION,
        "report_id": "process-correlation-report-" + _digest({"generated_at": timestamp, "correlations": [row["process_correlation_id"] for row in correlations]})[:16],
        "generated_at": timestamp,
        "process_correlations": correlations,
        "summary": summary,
        "dashboard_status": build_process_correlation_dashboard_record(summary=summary, correlations=correlations, generated_at=timestamp),
        "api_status": build_process_correlation_api_response(summary=summary, correlations=correlations, generated_at=timestamp),
        **FLOW_SAFETY_FLAGS,
    }


def summarize_process_correlations(correlations: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in correlations or [] if isinstance(row, dict)]
    return {
        "record_type": "process_correlation_summary",
        "record_version": PROCESS_CORRELATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "correlation_count": len(rows),
        "attributed_count": _count_state(rows, "attributed"),
        "partially_attributed_count": _count_state(rows, "partially_attributed"),
        "unattributed_count": _count_state(rows, "unattributed"),
        "conflicting_count": _count_state(rows, "conflicting"),
        "unknown_count": _count_state(rows, "unknown"),
        "average_attribution_confidence": _average(rows, "attribution_confidence"),
        "source_modes": sorted({str(row.get("source_mode") or "unknown") for row in rows}) or ["unknown"],
        **FLOW_SAFETY_FLAGS,
    }


def build_process_correlation_dashboard_record(
    *,
    summary: dict[str, Any],
    correlations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in correlations or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("conflicting_count") or 0) else "degraded" if int(summary.get("unattributed_count") or 0) else "ok"
    return {
        "record_type": "process_correlation_dashboard",
        "panel": "packet_metadata_process_correlation",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "correlation_count": int(summary.get("correlation_count") or 0),
            "attributed_count": int(summary.get("attributed_count") or 0),
            "unattributed_count": int(summary.get("unattributed_count") or 0),
            "conflicting_count": int(summary.get("conflicting_count") or 0),
            "average_attribution_confidence": float(summary.get("average_attribution_confidence") or 0.0),
        },
        "rows": [
            {
                "process_correlation_id": row.get("process_correlation_id"),
                "observation_id": row.get("observation_id"),
                "flow_key": row.get("flow_key"),
                "session_id": row.get("session_id"),
                "evidence_origin": row.get("evidence_origin"),
                "observation_type": row.get("observation_type"),
                "identity_scope": row.get("identity_scope"),
                "session_reference": row.get("session_reference"),
                "process_attribution": row.get("process_attribution"),
                "service_attribution": row.get("service_attribution"),
                "attribution_state": row.get("attribution_state"),
                "source_mode": row.get("source_mode"),
            }
            for row in rows
        ],
        "recommended_review": status != "ok",
        **FLOW_SAFETY_FLAGS,
    }


def build_process_correlation_api_response(
    *,
    summary: dict[str, Any],
    correlations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in correlations or [] if isinstance(row, dict)]
    return {
        "record_type": "process_correlation_api",
        "status": "review_required" if int(summary.get("conflicting_count") or 0) else "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "process_correlations": rows,
        **FLOW_SAFETY_FLAGS,
    }


def score_process_attribution_confidence(
    *,
    attribution_state: str,
    process_attribution: str,
    service_attribution: str,
    attribution_source: str,
    session: dict[str, Any] | None = None,
) -> float:
    score = 0.0
    if attribution_state == "conflicting":
        return 0.1
    if attribution_state == "unknown":
        return 0.0
    if process_attribution not in {"Unknown", "Unattributed"}:
        score += 0.35
    if service_attribution not in {"Unknown", "Unattributed"}:
        score += 0.3
    if str(attribution_source or "unknown") not in {"", "unknown"}:
        score += 0.1
    session = session or {}
    if session.get("protocol") not in {None, "", "unknown"}:
        score += 0.08
    if session.get("local_port") is not None or session.get("remote_port") is not None:
        score += 0.07
    if session.get("source_mode") in {"fixture", "simulated"}:
        score = min(score, 0.82)
    return round(max(0.0, min(1.0, score)), 3)


def deterministic_process_correlation_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _first_text(source: dict[str, Any], fields: tuple[str, ...]) -> str:
    for field in fields:
        value = source.get(field)
        if value in {None, ""}:
            continue
        text = str(value).strip()
        if text and text != "-":
            return text
    return ""


def _identity_text(session: dict[str, Any], field: str) -> str:
    existing = _first_text(session, (field,))
    if existing:
        return existing
    state = _first_text(session, ("transport_state", "state", "status")).lower()
    if field == "identity_scope":
        return "listener" if session.get("remote_port") in {None, ""} or state in {"listen", "listening"} else "flow"
    if field == "observation_type":
        return "listener" if _identity_text(session, "identity_scope") == "listener" else "socket_conversation"
    if field == "evidence_origin":
        return "listener_socket_observation" if _identity_text(session, "identity_scope") == "listener" else "reconstructed_flow"
    return ""


def _attribution_index(records: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in records or []:
        if not isinstance(row, dict):
            continue
        session_ref = str(row.get("session_reference") or row.get("session_ref") or row.get("session_id") or "")
        if session_ref:
            index[session_ref] = dict(row)
    return index


def _attribution_state(*, process_value: str, service_value: str, conflict_reason: str, session: dict[str, Any]) -> str:
    if conflict_reason:
        return "conflicting"
    if not session:
        return "unknown" if process_value == "Unknown" and service_value in {"Unknown", "Unattributed"} else "partially_attributed"
    process_known = process_value not in {"Unknown", "Unattributed"}
    service_known = service_value not in {"Unknown", "Unattributed"}
    if process_known and service_known:
        return "attributed"
    if process_known or service_known:
        return "partially_attributed"
    return "unattributed"


def _conflict_reason(
    *,
    session: dict[str, Any],
    process_value: str,
    service_value: str,
    raw_process: Any,
    raw_service: Any,
    source_mode: str,
) -> str:
    if source_mode not in {"fixture", "simulated"} and (_raw_label(raw_process).lower() in DEMO_ATTRIBUTION_LABELS or _raw_label(raw_service).lower() in DEMO_ATTRIBUTION_LABELS):
        return "demo_label_not_allowed_for_live_source"
    session_process = _safe_attribution(session.get("process_attribution"), source_mode=source_mode, fallback="Unknown")
    session_service = _safe_attribution(session.get("service_attribution"), source_mode=source_mode, fallback="Unattributed")
    if process_value not in {"Unknown", "Unattributed"} and session_process not in {"Unknown", "Unattributed"} and process_value != session_process:
        return "process_attribution_conflict"
    if service_value not in {"Unknown", "Unattributed"} and session_service not in {"Unknown", "Unattributed"} and service_value != session_service:
        return "service_attribution_conflict"
    return ""


def _safe_attribution(value: Any, *, source_mode: str, fallback: str) -> str:
    if isinstance(value, dict):
        value = value.get("display_name") or value.get("service_name") or value.get("process_name") or value.get("name") or value.get("value")
    text = str(value or "").strip()
    if not text:
        return fallback
    lowered = text.lower()
    if lowered in {"unknown", "none"}:
        return "Unknown"
    if lowered == "unattributed":
        return fallback if fallback in {"Unknown", "Unattributed"} else "Unattributed"
    if lowered in DEMO_ATTRIBUTION_LABELS and normalize_source_mode(source_mode) not in {"fixture", "simulated"}:
        return fallback
    return text[:80]


def _operator_summary(*, state: str, process_value: str, service_value: str, conflict_reason: str, source_mode: str) -> str:
    if state == "conflicting":
        return f"Review attribution conflict: {conflict_reason or 'conflicting metadata'}."
    if state == "unattributed":
        return f"Live attribution unresolved for source mode {source_mode}; display remains Unknown or Unattributed."
    if state == "unknown":
        return "Attribution could not be evaluated from the provided metadata."
    return f"{process_value} / {service_value} attribution is {state}."


def _source_mode_from_value(value: Any) -> str:
    if isinstance(value, dict):
        return normalize_source_mode(value.get("source_mode") or value.get("data_source") or "unknown")
    return "unknown"


def _raw_label(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("display_name") or value.get("service_name") or value.get("process_name") or value.get("name") or value.get("value")
    return str(value or "").strip()


def _safe_token(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace(" ", "_").replace("-", "_")
    return text[:80] if text else "unknown"


def _count_state(rows: list[dict[str, Any]], state: str) -> int:
    return sum(1 for row in rows if row.get("attribution_state") == state)


def _average(rows: list[dict[str, Any]], field_name: str) -> float:
    if not rows:
        return 0.0
    return round(sum(float(row.get(field_name) or 0.0) for row in rows) / len(rows), 3)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return utc_now_iso()
