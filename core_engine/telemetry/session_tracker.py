from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.flows import (
    FLOW_RECORD_VERSION,
    build_flow_api_response,
    build_flow_dashboard_record,
    deterministic_flow_json,
    normalize_flow_key,
    reconstruct_flow_record,
    summarize_flows,
)
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


SESSION_TRACKER_RECORD_VERSION = 1
DEFAULT_FLOW_TIMEOUT_SECONDS = 300


class FlowSessionTrackerError(ValueError):
    """Raised when flow session tracking inputs are invalid."""


def reconstruct_flows_from_packet_window(
    packet_window: dict[str, Any],
    *,
    timeout_seconds: int = DEFAULT_FLOW_TIMEOUT_SECONDS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(packet_window, dict):
        raise FlowSessionTrackerError("packet_window must be an object")
    return track_flow_sessions(
        packets=packet_window.get("packet_records") or [],
        packet_window_ref=str(packet_window.get("window_id") or ""),
        timeout_seconds=timeout_seconds,
        generated_at=generated_at or packet_window.get("generated_at"),
    )


def track_flow_sessions(
    *,
    packets: Iterable[dict[str, Any]],
    packet_window_ref: str = "",
    timeout_seconds: int = DEFAULT_FLOW_TIMEOUT_SECONDS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if int(timeout_seconds) < 0:
        raise FlowSessionTrackerError("timeout_seconds cannot be negative")
    rows = sorted([dict(row) for row in packets or [] if isinstance(row, dict)], key=lambda item: (str(item.get("timestamp") or ""), int(item.get("window_sequence") or 0)))
    sessions = build_flow_session_records(rows, timeout_seconds=timeout_seconds, generated_at=timestamp)
    flows = [
        reconstruct_flow_record(
            packets=session["packet_records"],
            flow_key=session["flow_key"],
            session_index=session["session_index"],
            timeout_seconds=timeout_seconds,
            generated_at=timestamp,
        )
        for session in sessions
    ]
    summary = summarize_flow_sessions(
        sessions=sessions,
        flows=flows,
        packet_count=len(rows),
        timeout_seconds=timeout_seconds,
        generated_at=timestamp,
    )
    flow_summary = summarize_flows(flows, generated_at=timestamp)
    dashboard = build_flow_dashboard_record(summary=flow_summary, flows=flows, generated_at=timestamp)
    api = build_flow_api_response(summary=flow_summary, flows=flows, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "flow_session_tracking_report",
        "record_version": SESSION_TRACKER_RECORD_VERSION,
        "tracker_id": _stable_id("flow-session-tracker", timestamp, packet_window_ref, summary, [flow.get("flow_id") for flow in flows]),
        "generated_at": timestamp,
        "packet_window_ref": packet_window_ref,
        "timeout_seconds": int(timeout_seconds),
        "sessions": sessions,
        "flows": flows,
        "summary": summary,
        "flow_summary": flow_summary,
        "topology_edges": [dict(flow["topology_edge"]) for flow in flows if isinstance(flow.get("topology_edge"), dict)],
        "dashboard_status": dashboard,
        "api_status": api,
        "payload_bytes_stored": 0,
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_flow_session_records(
    packets: Iterable[dict[str, Any]],
    *,
    timeout_seconds: int = DEFAULT_FLOW_TIMEOUT_SECONDS,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    sessions_by_key: dict[str, list[dict[str, Any]]] = {}
    for packet in packets or []:
        if not isinstance(packet, dict):
            continue
        key = normalize_flow_key(packet)
        sessions_by_key.setdefault(str(key["flow_key"]), [])
        target_sessions = sessions_by_key[str(key["flow_key"])]
        if not target_sessions or _session_gap_exceeded(target_sessions[-1], packet, timeout_seconds=timeout_seconds):
            target_sessions.append(_new_session_record(key, len(target_sessions) + 1, timestamp))
        _append_packet_to_session(target_sessions[-1], packet)
    sessions = []
    for session_list in sessions_by_key.values():
        sessions.extend(_finalize_session_record(session) for session in session_list)
    return sorted(sessions, key=lambda item: (str(item.get("first_seen") or ""), str(item.get("flow_key", {}).get("flow_key") or ""), int(item.get("session_index") or 0)))


def summarize_flow_sessions(
    *,
    sessions: Iterable[dict[str, Any]],
    flows: Iterable[dict[str, Any]],
    packet_count: int,
    timeout_seconds: int,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    session_rows = [dict(row) for row in sessions or [] if isinstance(row, dict)]
    flow_rows = [dict(row) for row in flows or [] if isinstance(row, dict)]
    return {
        "record_type": "flow_session_summary",
        "record_version": SESSION_TRACKER_RECORD_VERSION,
        "generated_at": timestamp,
        "packet_count": int(packet_count),
        "session_count": len(session_rows),
        "flow_count": len(flow_rows),
        "timeout_seconds": int(timeout_seconds),
        "timed_out_session_count": sum(1 for row in session_rows if row.get("timeout_closed")),
        "complete_flow_count": sum(1 for row in flow_rows if row.get("classification") == "complete"),
        "partial_flow_count": sum(1 for row in flow_rows if row.get("classification") == "partial"),
        "malformed_flow_count": sum(1 for row in flow_rows if row.get("classification") == "malformed"),
        "topology_edge_count": len([row for row in flow_rows if isinstance(row.get("topology_edge"), dict)]),
        "payload_bytes_stored": 0,
        **TELEMETRY_SAFETY_FLAGS,
    }


def deterministic_session_tracker_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _new_session_record(flow_key: dict[str, Any], session_index: int, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": "flow_session",
        "record_version": SESSION_TRACKER_RECORD_VERSION,
        "session_id": _stable_id("flow-session", flow_key.get("flow_key"), session_index, generated_at),
        "flow_key": dict(flow_key),
        "session_index": int(session_index),
        "first_seen": "",
        "last_seen": "",
        "packet_count": 0,
        "byte_count": 0,
        "packet_records": [],
        "timeout_closed": False,
        "generated_at": generated_at,
        **TELEMETRY_SAFETY_FLAGS,
    }


def _append_packet_to_session(session: dict[str, Any], packet: dict[str, Any]) -> None:
    timestamp = str(packet.get("timestamp") or "")
    if not session["first_seen"]:
        session["first_seen"] = timestamp
    session["last_seen"] = timestamp or session["last_seen"]
    session["packet_count"] = int(session.get("packet_count") or 0) + 1
    session["byte_count"] = int(session.get("byte_count") or 0) + int(packet.get("size_bytes") or 0)
    session["packet_records"].append(dict(packet))


def _finalize_session_record(session: dict[str, Any]) -> dict[str, Any]:
    return {
        **session,
        "packet_records": list(session.get("packet_records") or []),
        "session_digest": "sha256:" + sha256(deterministic_flow_json({
            "flow_key": session.get("flow_key"),
            "session_index": session.get("session_index"),
            "first_seen": session.get("first_seen"),
            "last_seen": session.get("last_seen"),
            "packet_count": session.get("packet_count"),
            "byte_count": session.get("byte_count"),
        }).encode("utf-8")).hexdigest(),
        "payload_bytes_stored": 0,
    }


def _session_gap_exceeded(session: dict[str, Any], packet: dict[str, Any], *, timeout_seconds: int) -> bool:
    if not session.get("last_seen"):
        return False
    gap = _duration_seconds(str(session.get("last_seen") or ""), str(packet.get("timestamp") or ""))
    exceeded = gap > int(timeout_seconds)
    if exceeded:
        session["timeout_closed"] = True
    return exceeded


def _duration_seconds(first_seen: str, last_seen: str) -> int:
    try:
        first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((last - first).total_seconds()))


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
