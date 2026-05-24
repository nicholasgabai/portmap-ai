from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.peer_lifecycle import (
    PEER_LIFECYCLE_RECORD_VERSION,
    build_peer_lifecycle_record,
    summarize_peer_lifecycle,
)
from core_engine.federation.runtime_state import FEDERATION_RUNTIME_SAFETY_FLAGS


DEFAULT_STALE_AFTER_SECONDS = 900


def build_trusted_peer_registry(
    *,
    trust_profile: dict[str, Any] | None = None,
    peer_lifecycle_records: Iterable[dict[str, Any]] | None = None,
    transport_sessions: Iterable[dict[str, Any]] | None = None,
    stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    sessions = _rows(transport_sessions)
    session_ids_by_peer = _session_ids_by_peer(sessions)
    records = _lifecycle_records(
        trust_profile=trust_profile,
        peer_lifecycle_records=peer_lifecycle_records,
        session_ids_by_peer=session_ids_by_peer,
        generated_at=timestamp,
    )
    summary = summarize_trusted_peer_registry(
        records,
        stale_after_seconds=stale_after_seconds,
        generated_at=timestamp,
    )
    dashboard = build_peer_registry_dashboard_record(summary=summary, generated_at=timestamp)
    api = build_peer_registry_api_response(records=records, summary=summary, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "trusted_peer_registry",
        "record_version": PEER_LIFECYCLE_RECORD_VERSION,
        "registry_id": _stable_id("trusted-peer-registry", timestamp, [record["lifecycle_id"] for record in records]),
        "generated_at": timestamp,
        "peer_records": records,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def summarize_trusted_peer_registry(
    peer_lifecycle_records: Iterable[dict[str, Any]],
    *,
    stale_after_seconds: int = DEFAULT_STALE_AFTER_SECONDS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    records = _rows(peer_lifecycle_records)
    by_state: dict[str, int] = {}
    stale: list[str] = []
    expired: list[str] = []
    revoked: list[str] = []
    for record in records:
        state = str(record.get("lifecycle_state") or "unknown")
        by_state[state] = by_state.get(state, 0) + 1
        peer_id = str(record.get("peer_node_id") or "")
        if state == "revoked":
            revoked.append(peer_id)
        if state == "expired" or _is_expired(record.get("expires_at"), generated_at=timestamp):
            expired.append(peer_id)
        if _is_stale(record.get("last_seen_at"), generated_at=timestamp, stale_after_seconds=stale_after_seconds):
            stale.append(peer_id)
    status = "review_required" if stale or expired or revoked else "ok"
    return {
        "record_type": "trusted_peer_registry_summary",
        "generated_at": timestamp,
        "status": status,
        "peer_count": len(records),
        "approved_peer_count": by_state.get("approved", 0),
        "paused_peer_count": by_state.get("paused", 0),
        "enrolled_peer_count": by_state.get("enrolled", 0),
        "expired_peer_count": len(sorted(set(expired))),
        "revoked_peer_count": len(sorted(set(revoked))),
        "stale_peer_count": len(sorted(set(stale))),
        "by_lifecycle_state": dict(sorted(by_state.items())),
        "stale_peer_ids": sorted(set(stale)),
        "expired_peer_ids": sorted(set(expired)),
        "revoked_peer_ids": sorted(set(revoked)),
        "operator_summary": _operator_summary(status, len(records), stale, expired, revoked),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_peer_registry_dashboard_record(*, summary: dict[str, Any], generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "trusted_peer_registry_dashboard",
        "panel": "trusted_peer_registry",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "peer_count": int(summary.get("peer_count") or 0),
            "approved_peer_count": int(summary.get("approved_peer_count") or 0),
            "paused_peer_count": int(summary.get("paused_peer_count") or 0),
            "stale_peer_count": int(summary.get("stale_peer_count") or 0),
            "expired_peer_count": int(summary.get("expired_peer_count") or 0),
            "revoked_peer_count": int(summary.get("revoked_peer_count") or 0),
        },
        "recommended_review": str(summary.get("status") or "") == "review_required",
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def build_peer_registry_api_response(
    *,
    records: Iterable[dict[str, Any]],
    summary: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(records)
    return {
        "record_type": "trusted_peer_registry_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "items": [summarize_peer_lifecycle(row, generated_at=generated_at) for row in rows],
        "summary": dict(summary),
        "dashboard": dict(dashboard),
        **FEDERATION_RUNTIME_SAFETY_FLAGS,
    }


def deterministic_peer_registry_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _lifecycle_records(
    *,
    trust_profile: dict[str, Any] | None,
    peer_lifecycle_records: Iterable[dict[str, Any]] | None,
    session_ids_by_peer: dict[str, list[str]],
    generated_at: str,
) -> list[dict[str, Any]]:
    provided = _rows(peer_lifecycle_records)
    if provided:
        records = []
        for record in provided:
            peer_id = str(record.get("peer_node_id") or "")
            records.append(
                {
                    **record,
                    "transport_session_ids": sorted(set([*record.get("transport_session_ids", []), *session_ids_by_peer.get(peer_id, [])])),
                    **FEDERATION_RUNTIME_SAFETY_FLAGS,
                }
            )
        return sorted(records, key=lambda item: str(item.get("peer_node_id") or ""))
    records = []
    for peer in (trust_profile or {}).get("approved_peers") or []:
        if not isinstance(peer, dict):
            continue
        peer_id = str(peer.get("peer_node_id") or "")
        records.append(
            build_peer_lifecycle_record(
                peer,
                transport_session_ids=session_ids_by_peer.get(peer_id, []),
                last_seen_at=generated_at,
                last_verified_at=generated_at,
                generated_at=generated_at,
            )
        )
    return sorted(records, key=lambda item: str(item.get("peer_node_id") or ""))


def _session_ids_by_peer(sessions: list[dict[str, Any]]) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    for session in sessions:
        session_id = str(session.get("session_id") or "")
        for peer_id in (str(session.get("source_node_id") or ""), str(session.get("destination_node_id") or "")):
            if not peer_id or not session_id:
                continue
            result.setdefault(peer_id, [])
            result[peer_id].append(session_id)
    return {peer_id: sorted(set(ids)) for peer_id, ids in sorted(result.items())}


def _operator_summary(status: str, peer_count: int, stale: list[str], expired: list[str], revoked: list[str]) -> str:
    if status == "review_required":
        return f"Review trusted peer registry: {len(set(stale))} stale, {len(set(expired))} expired, and {len(set(revoked))} revoked peer records."
    return f"Trusted peer registry contains {peer_count} peer records with no stale, expired, or revoked records."


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _is_stale(value: Any, *, generated_at: str, stale_after_seconds: int) -> bool:
    text = str(value or "")
    if not text:
        return False
    try:
        return (datetime.fromisoformat(generated_at) - datetime.fromisoformat(text)).total_seconds() >= stale_after_seconds
    except ValueError:
        return False


def _is_expired(value: Any, *, generated_at: str) -> bool:
    text = str(value or "")
    if not text:
        return False
    try:
        return datetime.fromisoformat(text) <= datetime.fromisoformat(generated_at)
    except ValueError:
        return False


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
