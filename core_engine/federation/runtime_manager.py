from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.diagnostics import build_federation_diagnostics
from core_engine.federation.runtime_state import (
    FEDERATION_RUNTIME_RECORD_VERSION,
    FEDERATION_RUNTIME_SAFETY_FLAGS,
    build_event_propagation_loop_plan,
    build_federation_runtime_state,
    build_signed_exchange_loop_plan,
    build_synchronization_loop_plan,
    deterministic_federation_runtime_state_json,
)
from core_engine.runtime.session_state import summarize_runtime_session


def build_federation_runtime_manager(
    *,
    trust_profile: dict[str, Any] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    signed_exchanges: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    sync_result: dict[str, Any] | None = None,
    event_batch: dict[str, Any] | None = None,
    diagnostics: dict[str, Any] | None = None,
    runtime_session: dict[str, Any] | Any | None = None,
    state: str = "inactive",
    loop_plans: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build an active federation runtime manager record.

    The record plans exchange loops and summarizes runtime state only. It does
    not open network listeners, start daemon execution, or persist records.
    """
    timestamp = generated_at or _now()
    sessions = [dict(row) for row in transport_sessions or [] if isinstance(row, dict)]
    diagnostic_record = diagnostics or build_federation_diagnostics(
        trust_profile=trust_profile,
        transport_sessions=sessions,
        signed_exchanges=signed_exchanges,
        sync_result=sync_result,
        event_batch=event_batch,
        generated_at=timestamp,
    )
    runtime_session_ref = build_federation_runtime_session_ref(runtime_session, generated_at=timestamp)
    plans = list(loop_plans or build_default_federation_loop_plans(trust_profile=trust_profile, state=state, generated_at=timestamp))
    runtime_state = build_federation_runtime_state(
        trust_profile=trust_profile,
        transport_sessions=sessions,
        signed_exchanges=signed_exchanges,
        sync_result=sync_result,
        event_batch=event_batch,
        diagnostics=diagnostic_record,
        runtime_session_ref=runtime_session_ref,
        state=state,
        loop_plans=plans,
        generated_at=timestamp,
    )
    summary = build_federation_runtime_manager_summary(runtime_state=runtime_state, diagnostics=diagnostic_record, generated_at=timestamp)
    return {
        "record_type": "active_federation_runtime_manager",
        "record_version": FEDERATION_RUNTIME_RECORD_VERSION,
        "manager_id": _stable_id("federation-runtime-manager", timestamp, runtime_state.get("state_id"), runtime_session_ref),
        "generated_at": timestamp,
        "state": runtime_state["state"],
        "runtime_session_ref": runtime_session_ref,
        "runtime_state": runtime_state,
        "diagnostics": diagnostic_record,
        "loop_plans": runtime_state["loop_plans"],
        "peer_enrollments": runtime_state["peer_enrollments"],
        "peer_counters": runtime_state["peer_counters"],
        "summary": summary,
        "dashboard_status": runtime_state["dashboard_status"],
        "api_status": build_federation_runtime_manager_api_response(runtime_state=runtime_state, summary=summary, generated_at=timestamp),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_default_federation_loop_plans(
    *,
    trust_profile: dict[str, Any] | None = None,
    state: str = "inactive",
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    plans: list[dict[str, Any]] = []
    for peer in sorted((trust_profile or {}).get("approved_peers") or [], key=lambda item: str(item.get("peer_node_id") or "")):
        if not isinstance(peer, dict):
            continue
        peer_id = str(peer.get("peer_node_id") or "")
        scopes = set(str(item) for item in peer.get("trust_scope_labels") or [])
        if "runtime-summary" in scopes:
            plans.append(build_signed_exchange_loop_plan(peer_node_id=peer_id, state=state, generated_at=timestamp))
            plans.append(build_synchronization_loop_plan(peer_node_id=peer_id, state=state, generated_at=timestamp))
        if "event-summary" in scopes:
            plans.append(build_event_propagation_loop_plan(peer_node_id=peer_id, state=state, generated_at=timestamp))
    return plans


def build_federation_runtime_session_ref(runtime_session: dict[str, Any] | Any | None, *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if runtime_session is None:
        return {
            "record_type": "federation_runtime_session_reference",
            "status": "missing",
            "generated_at": timestamp,
            "summary": {},
            **FEDERATION_RUNTIME_SAFETY_FLAGS,
        }
    summary = summarize_runtime_session(runtime_session)
    return {
        "record_type": "federation_runtime_session_reference",
        "status": str(summary.get("status") or "unknown"),
        "session_id": str(summary.get("session_id") or ""),
        "mode": str(summary.get("mode") or "dry-run"),
        "generated_at": timestamp,
        "summary": summary,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_federation_runtime_manager_summary(
    *,
    runtime_state: dict[str, Any],
    diagnostics: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    state_summary = runtime_state.get("summary") if isinstance(runtime_state.get("summary"), dict) else {}
    diagnostic_status = str((diagnostics or {}).get("status") or "unknown")
    return {
        "record_type": "federation_runtime_manager_summary",
        "generated_at": timestamp,
        "status": str(state_summary.get("status") or runtime_state.get("state") or "unknown"),
        "diagnostics_status": diagnostic_status,
        "peer_count": int(state_summary.get("peer_count") or 0),
        "active_peer_count": int(state_summary.get("active_peer_count") or 0),
        "loop_plan_count": int(state_summary.get("loop_plan_count") or 0),
        "enabled_loop_plan_count": int(state_summary.get("enabled_loop_plan_count") or 0),
        "signed_exchange_count": int(state_summary.get("signed_exchange_count") or 0),
        "accepted_update_count": int(state_summary.get("accepted_update_count") or 0),
        "accepted_event_count": int(state_summary.get("accepted_event_count") or 0),
        "error_count": int(state_summary.get("error_count") or 0),
        "operator_summary": str(state_summary.get("operator_summary") or ""),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_federation_runtime_manager_api_response(
    *,
    runtime_state: dict[str, Any],
    summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "federation_runtime_manager_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "runtime_state": {
            "state_id": runtime_state.get("state_id"),
            "state": runtime_state.get("state"),
            "summary": runtime_state.get("summary"),
            "dashboard_status": runtime_state.get("dashboard_status"),
            "peer_enrollments": runtime_state.get("peer_enrollments"),
            "loop_plans": runtime_state.get("loop_plans"),
        },
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def deterministic_federation_runtime_manager_json(record: dict[str, Any]) -> str:
    return deterministic_federation_runtime_state_json(record)


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
