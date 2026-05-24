from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.signing import SIGNING_SAFETY_FLAGS, canonical_json
from core_engine.federation.transport import build_transport_session_summary
from core_engine.federation.trust import summarize_trust_profile


FEDERATION_RUNTIME_RECORD_VERSION = 1
FEDERATION_RUNTIME_STATES = frozenset({"active", "inactive", "paused", "error"})
FEDERATION_RUNTIME_LOOP_TYPES = frozenset({"signed_exchange", "synchronization", "event_propagation"})
DEFAULT_LOOP_INTERVALS = {
    "signed_exchange": 60,
    "synchronization": 60,
    "event_propagation": 30,
}
FEDERATION_RUNTIME_SAFETY_FLAGS = {
    **SIGNING_SAFETY_FLAGS,
    "active_runtime_record": True,
    "network_listener_enabled": False,
    "background_daemon_enabled": False,
    "remote_command_execution": False,
    "api_compatible": True,
    "read_only": True,
}


class FederationRuntimeStateError(ValueError):
    """Raised when federation runtime state records are malformed."""


def build_federation_runtime_state(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    runtime_session_ref: dict[str, Any] | None = None,
    state: str = "inactive",
    loop_plans: Iterable[dict[str, Any]] | None = None,
    last_success_at: str | None = None,
    last_error_at: str | None = None,
    warnings: Iterable[str] | None = None,
    errors: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    runtime_state = _runtime_state(state)
    session_rows = _rows(transport_sessions)
    exchange_rows = _exchange_rows(signed_exchanges)
    peer_counters = build_peer_runtime_counters(
        trust_profile=trust_profile,
        transport_sessions=session_rows,
        signed_exchanges=signed_exchanges,
        sync_result=sync_result,
        event_batch=event_batch,
        generated_at=timestamp,
    )
    peer_enrollments = build_trusted_peer_runtime_enrollments(
        trust_profile=trust_profile,
        transport_sessions=session_rows,
        peer_counters=peer_counters,
        generated_at=timestamp,
    )
    plans = _loop_plans(loop_plans, trust_profile=trust_profile, generated_at=timestamp)
    warning_rows = _strings(warnings)
    error_rows = _strings(errors)
    if error_rows and runtime_state != "error":
        runtime_state = "error"
    summary = summarize_federation_runtime_state(
        state=runtime_state,
        peer_enrollments=peer_enrollments,
        loop_plans=plans,
        peer_counters=peer_counters,
        diagnostics=diagnostics,
        warnings=warning_rows,
        errors=error_rows,
        generated_at=timestamp,
    )
    dashboard = build_federation_runtime_dashboard_record(summary=summary, generated_at=timestamp)
    api = build_federation_runtime_api_response(summary=summary, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "federation_runtime_state",
        "record_version": FEDERATION_RUNTIME_RECORD_VERSION,
        "state_id": _stable_id("federation-runtime-state", timestamp, runtime_state, summary, runtime_session_ref or {}),
        "state": runtime_state,
        "generated_at": timestamp,
        "runtime_session_ref": dict(runtime_session_ref or {}),
        "trust_profile_summary": summarize_trust_profile(trust_profile, generated_at=timestamp) if trust_profile else {},
        "transport_session_summary": build_transport_session_summary(session_rows, generated_at=timestamp) if session_rows else {},
        "peer_enrollments": peer_enrollments,
        "peer_counters": peer_counters,
        "loop_plans": plans,
        "last_success_at": str(last_success_at or _latest_success_timestamp(peer_counters, sync_result=sync_result, event_batch=event_batch, signed_exchanges=exchange_rows)),
        "last_error_at": str(last_error_at or _latest_error_timestamp(peer_counters, diagnostics=diagnostics)),
        "warnings": warning_rows,
        "errors": error_rows,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_trusted_peer_runtime_enrollments(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    peer_counters: dict[str, dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    counters = peer_counters or {}
    sessions_by_peer = _sessions_by_peer(_rows(transport_sessions))
    peers = [dict(peer) for peer in (trust_profile or {}).get("approved_peers") or [] if isinstance(peer, dict)]
    enrollments: list[dict[str, Any]] = []
    for peer in sorted(peers, key=lambda item: str(item.get("peer_node_id") or "")):
        peer_id = str(peer.get("peer_node_id") or "")
        peer_sessions = sessions_by_peer.get(peer_id, [])
        counter = counters.get(peer_id, _empty_peer_counter(peer_id, generated_at=timestamp))
        status = _peer_runtime_status(peer, peer_sessions, counter)
        enrollments.append(
            {
                "record_type": "trusted_peer_runtime_enrollment",
                "record_version": FEDERATION_RUNTIME_RECORD_VERSION,
                "enrollment_id": _stable_id("peer-runtime-enrollment", peer_id, status, peer.get("approval_status"), peer_sessions),
                "peer_node_id": peer_id,
                "peer_role": str(peer.get("peer_role") or "worker"),
                "peer_label": str(peer.get("peer_label") or peer_id),
                "runtime_status": status,
                "approval_status": str(peer.get("approval_status") or "unknown"),
                "trust_scope_labels": sorted(str(item) for item in peer.get("trust_scope_labels") or []),
                "transport_session_ids": sorted(str(session.get("session_id") or "") for session in peer_sessions if session.get("session_id")),
                "transport_session_count": len(peer_sessions),
                "counter_summary": counter,
                "last_success_at": str(counter.get("last_success_at") or ""),
                "last_error_at": str(counter.get("last_error_at") or ""),
                "source_refs": list(peer.get("source_refs") or [f"node:{peer_id}"]),
                "generated_at": timestamp,
                **FEDERATION_RUNTIME_SAFETY_FLAGS,
            }
        )
    return enrollments


def build_synchronization_loop_plan(
    *,
    peer_node_id: str = "",
    trust_scope_label: str = "runtime-summary",
    interval_seconds: int = DEFAULT_LOOP_INTERVALS["synchronization"],
    enabled: bool = True,
    state: str = "inactive",
    last_success_at: str | None = None,
    last_error_at: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return build_federation_loop_plan(
        "synchronization",
        peer_node_id=peer_node_id,
        trust_scope_label=trust_scope_label,
        interval_seconds=interval_seconds,
        enabled=enabled,
        state=state,
        last_success_at=last_success_at,
        last_error_at=last_error_at,
        generated_at=generated_at,
    )


def build_event_propagation_loop_plan(
    *,
    peer_node_id: str = "",
    trust_scope_label: str = "event-summary",
    interval_seconds: int = DEFAULT_LOOP_INTERVALS["event_propagation"],
    enabled: bool = True,
    state: str = "inactive",
    last_success_at: str | None = None,
    last_error_at: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return build_federation_loop_plan(
        "event_propagation",
        peer_node_id=peer_node_id,
        trust_scope_label=trust_scope_label,
        interval_seconds=interval_seconds,
        enabled=enabled,
        state=state,
        last_success_at=last_success_at,
        last_error_at=last_error_at,
        generated_at=generated_at,
    )


def build_signed_exchange_loop_plan(
    *,
    peer_node_id: str = "",
    trust_scope_label: str = "runtime-summary",
    interval_seconds: int = DEFAULT_LOOP_INTERVALS["signed_exchange"],
    enabled: bool = True,
    state: str = "inactive",
    last_success_at: str | None = None,
    last_error_at: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    return build_federation_loop_plan(
        "signed_exchange",
        peer_node_id=peer_node_id,
        trust_scope_label=trust_scope_label,
        interval_seconds=interval_seconds,
        enabled=enabled,
        state=state,
        last_success_at=last_success_at,
        last_error_at=last_error_at,
        generated_at=generated_at,
    )


def build_federation_loop_plan(
    loop_type: str,
    *,
    peer_node_id: str = "",
    trust_scope_label: str = "runtime-summary",
    interval_seconds: int | None = None,
    enabled: bool = True,
    state: str = "inactive",
    last_success_at: str | None = None,
    last_error_at: str | None = None,
    source_refs: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    normalized_type = _loop_type(loop_type)
    normalized_state = _runtime_state(state)
    interval = int(interval_seconds or DEFAULT_LOOP_INTERVALS[normalized_type])
    if interval <= 0:
        raise FederationRuntimeStateError("interval_seconds must be greater than zero")
    payload = {
        "record_type": "federation_runtime_loop_plan",
        "record_version": FEDERATION_RUNTIME_RECORD_VERSION,
        "loop_plan_id": _stable_id("federation-loop-plan", normalized_type, peer_node_id, trust_scope_label, interval, timestamp),
        "loop_type": normalized_type,
        "peer_node_id": str(peer_node_id or ""),
        "trust_scope_label": str(trust_scope_label or "runtime-summary"),
        "interval_seconds": interval,
        "enabled": bool(enabled),
        "state": normalized_state,
        "last_success_at": str(last_success_at or ""),
        "last_error_at": str(last_error_at or ""),
        "next_run_after": timestamp if enabled and normalized_state == "active" else "",
        "source_refs": sorted(set(str(item) for item in source_refs or [f"node:{peer_node_id or 'all'}"] if str(item).strip())),
        "loop_execution_enabled": False,
        "planning_record_only": True,
        "generated_at": timestamp,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }
    return payload


def build_peer_runtime_counters(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, dict[str, Any]]:
    timestamp = generated_at or _now()
    peer_ids = set(str(peer.get("peer_node_id") or "") for peer in (trust_profile or {}).get("approved_peers") or [] if isinstance(peer, dict))
    for session in _rows(transport_sessions):
        peer_ids.add(str(session.get("destination_node_id") or ""))
        peer_ids.add(str(session.get("source_node_id") or ""))
    for row in _exchange_rows(signed_exchanges):
        peer_ids.add(str(row.get("source_node_id") or ""))
        peer_ids.add(str(row.get("destination_node_id") or ""))
    for row in [*_rows((sync_result or {}).get("accepted_updates")), *_rows((sync_result or {}).get("rejected_updates"))]:
        peer_ids.add(str(row.get("source_node_id") or ""))
    for row in [*_rows((event_batch or {}).get("accepted_events")), *_rows((event_batch or {}).get("rejected_events"))]:
        peer_ids.add(str(row.get("source_node_id") or ""))
    counters = {_id: _empty_peer_counter(_id, generated_at=timestamp) for _id in sorted(peer_id for peer_id in peer_ids if peer_id)}
    for session in _rows(transport_sessions):
        for peer_id in (str(session.get("source_node_id") or ""), str(session.get("destination_node_id") or "")):
            if not peer_id:
                continue
            counter = counters.setdefault(peer_id, _empty_peer_counter(peer_id, generated_at=timestamp))
            counter["transport_session_count"] += 1
            if session.get("status") in {"established", "planned", "handshake-pending"}:
                counter["planned_session_count"] += 1
            if session.get("status") in {"expired", "rejected", "closed"}:
                counter["error_count"] += 1
                counter["last_error_at"] = _max_time(counter.get("last_error_at"), session.get("expires_at") or session.get("started_at"))
    for row in _exchange_rows(signed_exchanges):
        status = str(row.get("exchange_status") or "unknown")
        for peer_id in (str(row.get("source_node_id") or ""), str(row.get("destination_node_id") or "")):
            if not peer_id:
                continue
            counter = counters.setdefault(peer_id, _empty_peer_counter(peer_id, generated_at=timestamp))
            counter["signed_exchange_count"] += 1
            if status in {"accepted", "exchange-ready"}:
                counter["successful_exchange_count"] += 1
                counter["last_success_at"] = _max_time(counter.get("last_success_at"), row.get("issued_at") or row.get("generated_at"))
            else:
                counter["error_count"] += 1
                counter["last_error_at"] = _max_time(counter.get("last_error_at"), row.get("issued_at") or row.get("generated_at"))
    for row in _rows((sync_result or {}).get("accepted_updates")):
        peer_id = str(row.get("source_node_id") or "")
        if peer_id:
            counter = counters.setdefault(peer_id, _empty_peer_counter(peer_id, generated_at=timestamp))
            counter["accepted_update_count"] += 1
            counter["last_success_at"] = _max_time(counter.get("last_success_at"), row.get("applied_at") or row.get("issued_at"))
    for row in _rows((sync_result or {}).get("rejected_updates")):
        peer_id = str(row.get("source_node_id") or "")
        if peer_id:
            counter = counters.setdefault(peer_id, _empty_peer_counter(peer_id, generated_at=timestamp))
            counter["rejected_update_count"] += 1
            counter["error_count"] += 1
            counter["last_error_at"] = _max_time(counter.get("last_error_at"), row.get("rejected_at") or row.get("issued_at"))
    for row in _rows((event_batch or {}).get("accepted_events")):
        peer_id = str(row.get("source_node_id") or "")
        if peer_id:
            counter = counters.setdefault(peer_id, _empty_peer_counter(peer_id, generated_at=timestamp))
            counter["accepted_event_count"] += 1
            counter["last_success_at"] = _max_time(counter.get("last_success_at"), row.get("accepted_at") or row.get("issued_at"))
    for row in _rows((event_batch or {}).get("rejected_events")):
        peer_id = str(row.get("source_node_id") or "")
        if peer_id:
            counter = counters.setdefault(peer_id, _empty_peer_counter(peer_id, generated_at=timestamp))
            counter["rejected_event_count"] += 1
            counter["error_count"] += 1
            counter["last_error_at"] = _max_time(counter.get("last_error_at"), row.get("rejected_at") or row.get("issued_at"))
    return {peer_id: {**counter, **FEDERATION_RUNTIME_SAFETY_FLAGS} for peer_id, counter in sorted(counters.items())}


def summarize_federation_runtime_state(
    *,
    state: str,
    peer_enrollments: Iterable[dict[str, Any]],
    loop_plans: Iterable[dict[str, Any]],
    peer_counters: dict[str, dict[str, Any]],
    diagnostics: dict[str, Any] | None = None,
    warnings: Iterable[str] | None = None,
    errors: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    enrollments = _rows(peer_enrollments)
    plans = _rows(loop_plans)
    by_peer_status: dict[str, int] = {}
    by_loop_type: dict[str, int] = {}
    for enrollment in enrollments:
        status = str(enrollment.get("runtime_status") or "unknown")
        by_peer_status[status] = by_peer_status.get(status, 0) + 1
    for plan in plans:
        loop_type = str(plan.get("loop_type") or "unknown")
        by_loop_type[loop_type] = by_loop_type.get(loop_type, 0) + 1
    error_count = sum(int(counter.get("error_count") or 0) for counter in peer_counters.values())
    diagnostics_status = str((diagnostics or {}).get("status") or "")
    warning_rows = _strings(warnings)
    error_rows = _strings(errors)
    status = _runtime_state(state)
    if status != "error" and (error_count or error_rows or diagnostics_status == "degraded"):
        status = "error"
    return {
        "record_type": "federation_runtime_state_summary",
        "generated_at": timestamp,
        "status": status,
        "peer_count": len(enrollments),
        "active_peer_count": by_peer_status.get("active", 0),
        "inactive_peer_count": by_peer_status.get("inactive", 0),
        "paused_peer_count": by_peer_status.get("paused", 0),
        "error_peer_count": by_peer_status.get("error", 0),
        "loop_plan_count": len(plans),
        "enabled_loop_plan_count": sum(1 for plan in plans if plan.get("enabled")),
        "by_peer_runtime_status": dict(sorted(by_peer_status.items())),
        "by_loop_type": dict(sorted(by_loop_type.items())),
        "signed_exchange_count": sum(int(counter.get("signed_exchange_count") or 0) for counter in peer_counters.values()),
        "accepted_update_count": sum(int(counter.get("accepted_update_count") or 0) for counter in peer_counters.values()),
        "rejected_update_count": sum(int(counter.get("rejected_update_count") or 0) for counter in peer_counters.values()),
        "accepted_event_count": sum(int(counter.get("accepted_event_count") or 0) for counter in peer_counters.values()),
        "rejected_event_count": sum(int(counter.get("rejected_event_count") or 0) for counter in peer_counters.values()),
        "warning_count": len(warning_rows),
        "error_count": error_count + len(error_rows),
        "operator_summary": _operator_summary(status, enrollments, plans, error_count + len(error_rows)),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_federation_runtime_dashboard_record(
    *,
    summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "federation_runtime_dashboard",
        "panel": "federation_runtime",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": timestamp,
        "metrics": {
            "peer_count": int(summary.get("peer_count") or 0),
            "active_peer_count": int(summary.get("active_peer_count") or 0),
            "loop_plan_count": int(summary.get("loop_plan_count") or 0),
            "enabled_loop_plan_count": int(summary.get("enabled_loop_plan_count") or 0),
            "signed_exchange_count": int(summary.get("signed_exchange_count") or 0),
            "rejected_update_count": int(summary.get("rejected_update_count") or 0),
            "rejected_event_count": int(summary.get("rejected_event_count") or 0),
            "error_count": int(summary.get("error_count") or 0),
        },
        "recommended_review": bool(int(summary.get("error_count") or 0)),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_federation_runtime_api_response(
    *,
    summary: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "federation_runtime_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "dashboard": dict(dashboard),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def deterministic_federation_runtime_state_json(record: dict[str, Any]) -> str:
    return canonical_json(record)


def _loop_plans(
    loop_plans: Iterable[dict[str, Any]] | None,
    *,
    trust_profile: dict[str, Any] | None,
    generated_at: str,
) -> list[dict[str, Any]]:
    provided = _rows(loop_plans)
    if provided:
        return sorted((dict(plan) for plan in provided), key=lambda item: (str(item.get("peer_node_id") or ""), str(item.get("loop_type") or "")))
    peers = [dict(peer) for peer in (trust_profile or {}).get("approved_peers") or [] if isinstance(peer, dict)]
    plans: list[dict[str, Any]] = []
    for peer in sorted(peers, key=lambda item: str(item.get("peer_node_id") or "")):
        peer_id = str(peer.get("peer_node_id") or "")
        scopes = set(str(item) for item in peer.get("trust_scope_labels") or [])
        if "runtime-summary" in scopes:
            plans.append(build_signed_exchange_loop_plan(peer_node_id=peer_id, state="inactive", generated_at=generated_at))
            plans.append(build_synchronization_loop_plan(peer_node_id=peer_id, state="inactive", generated_at=generated_at))
        if "event-summary" in scopes:
            plans.append(build_event_propagation_loop_plan(peer_node_id=peer_id, state="inactive", generated_at=generated_at))
    return plans


def _peer_runtime_status(peer: dict[str, Any], sessions: list[dict[str, Any]], counter: dict[str, Any]) -> str:
    if peer.get("approval_status") != "approved":
        return "paused"
    if int(counter.get("error_count") or 0):
        return "error"
    if any(session.get("status") in {"planned", "handshake-pending", "established"} for session in sessions):
        return "active"
    return "inactive"


def _empty_peer_counter(peer_node_id: str, *, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": "federation_peer_runtime_counter",
        "peer_node_id": str(peer_node_id or ""),
        "transport_session_count": 0,
        "planned_session_count": 0,
        "signed_exchange_count": 0,
        "successful_exchange_count": 0,
        "accepted_update_count": 0,
        "rejected_update_count": 0,
        "accepted_event_count": 0,
        "rejected_event_count": 0,
        "error_count": 0,
        "last_success_at": "",
        "last_error_at": "",
        "generated_at": generated_at,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def _operator_summary(status: str, enrollments: list[dict[str, Any]], plans: list[dict[str, Any]], error_count: int) -> str:
    if status == "error":
        return f"Federation runtime requires operator review for {error_count} error records."
    if status == "active":
        return f"Federation runtime has {len(enrollments)} trusted peers and {len(plans)} planned exchange loops."
    if status == "paused":
        return "Federation runtime is paused; loop plans are retained for operator review."
    return "Federation runtime is inactive; records describe planned trusted exchange loops only."


def _latest_success_timestamp(
    peer_counters: dict[str, dict[str, Any]],
    *,
    sync_result: dict[str, Any] | None,
    event_batch: dict[str, Any] | None,
    signed_exchanges: list[dict[str, Any]],
) -> str:
    values = [str(counter.get("last_success_at") or "") for counter in peer_counters.values()]
    values.extend(str(row.get("applied_at") or row.get("issued_at") or "") for row in _rows((sync_result or {}).get("accepted_updates")))
    values.extend(str(row.get("accepted_at") or "") for row in _rows((event_batch or {}).get("accepted_events")))
    values.extend(str(row.get("issued_at") or "") for row in signed_exchanges if str(row.get("exchange_status") or "") in {"accepted", "exchange-ready"})
    return max([value for value in values if value], default="")


def _latest_error_timestamp(peer_counters: dict[str, dict[str, Any]], *, diagnostics: dict[str, Any] | None) -> str:
    values = [str(counter.get("last_error_at") or "") for counter in peer_counters.values()]
    values.append(str((diagnostics or {}).get("generated_at") or "") if (diagnostics or {}).get("status") == "degraded" else "")
    return max([value for value in values if value], default="")


def _sessions_by_peer(sessions: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    result: dict[str, list[dict[str, Any]]] = {}
    for session in sessions:
        for peer_id in (str(session.get("source_node_id") or ""), str(session.get("destination_node_id") or "")):
            if not peer_id:
                continue
            result.setdefault(peer_id, []).append(session)
    return result


def _exchange_rows(value: Iterable[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if not value:
        return []
    if isinstance(value, dict):
        if isinstance(value.get("envelopes"), list):
            return _rows(value.get("envelopes"))
        if value.get("record_type") == "signed_runtime_summary_envelope":
            return [dict(value)]
        return []
    return _rows(value)


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in value or [] if isinstance(row, dict)]


def _strings(value: Iterable[str] | None) -> list[str]:
    return sorted(str(item).strip() for item in value or [] if str(item).strip())


def _loop_type(value: str) -> str:
    loop_type = str(value or "")
    if loop_type not in FEDERATION_RUNTIME_LOOP_TYPES:
        raise FederationRuntimeStateError(f"unsupported federation loop type: {loop_type}")
    return loop_type


def _runtime_state(value: str) -> str:
    state = str(value or "inactive")
    if state not in FEDERATION_RUNTIME_STATES:
        raise FederationRuntimeStateError(f"unsupported federation runtime state: {state}")
    return state


def _max_time(left: Any, right: Any) -> str:
    values = [str(item) for item in (left, right) if str(item or "").strip()]
    return max(values, default="")


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
