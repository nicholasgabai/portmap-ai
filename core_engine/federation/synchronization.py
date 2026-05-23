from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.cluster_state import build_cluster_sync_dashboard_status, build_merged_cluster_state
from core_engine.federation.exchange import verify_signed_runtime_summary_envelope
from core_engine.federation.signing import SIGNING_RECORD_VERSION, SIGNING_SAFETY_FLAGS, build_verification_status_record


SYNC_RECORD_VERSION = 1
SYNC_UPDATE_STATUSES = frozenset({"accepted", "rejected", "stale", "replayed", "untrusted", "malformed"})


class LiveClusterSynchronizationError(ValueError):
    """Raised when live cluster synchronization records are malformed."""


def build_synchronization_window(
    *,
    window_id: str | None = None,
    runtime_session_ref: dict[str, Any] | None = None,
    trusted_node_ids: Iterable[str] | None = None,
    opened_at: str | None = None,
    closes_at: str | None = None,
    replay_window_seconds: int = 300,
    last_sequence_by_node: dict[str, int] | None = None,
    last_digest_by_node: dict[str, str] | None = None,
    seen_nonces: Iterable[str] | None = None,
    source_refs: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timestamp = opened_at or _now()
    if replay_window_seconds <= 0:
        raise LiveClusterSynchronizationError("replay_window_seconds must be greater than zero")
    close_time = closes_at or (_parse_time(timestamp) + timedelta(seconds=replay_window_seconds)).isoformat()
    nodes = sorted(set(str(item) for item in trusted_node_ids or [] if str(item).strip()))
    payload = {
        "record_type": "live_cluster_synchronization_window",
        "record_version": SYNC_RECORD_VERSION,
        "window_id": window_id or _stable_id("sync-window", timestamp, nodes, runtime_session_ref or {}),
        "opened_at": timestamp,
        "closes_at": close_time,
        "replay_window_seconds": replay_window_seconds,
        "trusted_node_ids": nodes,
        "runtime_session_ref": dict(runtime_session_ref or {}),
        "last_sequence_by_node": _int_map(last_sequence_by_node),
        "last_digest_by_node": _str_map(last_digest_by_node),
        "last_seen_update_by_node": {},
        "seen_nonces": sorted(set(str(item) for item in seen_nonces or [] if str(item).strip())),
        "accepted_update_ids": [],
        "rejected_update_ids": [],
        "source_refs": _source_refs(source_refs, fallback="sync-window:local"),
        "metadata": _sorted_dict(metadata or {}),
        **SIGNING_SAFETY_FLAGS,
    }
    payload["summary"] = summarize_synchronization_window(payload, generated_at=timestamp)
    return payload


def apply_signed_summary_updates(
    envelopes: Iterable[dict[str, Any]],
    *,
    sync_window: dict[str, Any],
    trust_profile: dict[str, Any],
    transport_sessions: Iterable[dict[str, Any]] | dict[str, dict[str, Any]],
    expected_nodes: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    window = _copy_window(sync_window)
    transports = _transport_map(transport_sessions)
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    drift: list[dict[str, Any]] = []

    for envelope in sorted([dict(row) for row in envelopes if isinstance(row, dict)], key=lambda item: (str(item.get("source_node_id") or ""), int(item.get("sequence") or 0), str(item.get("envelope_id") or ""))):
        transport = transports.get(str(envelope.get("transport_session_id") or ""))
        if transport is None:
            verified = {
                **envelope,
                "exchange_status": "malformed",
                "verification_status": build_verification_status_record(
                    envelope_id=str(envelope.get("envelope_id") or ""),
                    payload_digest=str(envelope.get("payload_digest") or ""),
                    status="metadata-invalid",
                    errors=["transport session was not provided for envelope"],
                    verified_at=timestamp,
                ),
            }
        else:
            verified = verify_signed_runtime_summary_envelope(
                envelope,
                trust_profile=trust_profile,
                transport_session=transport,
                seen_nonces=window.get("seen_nonces") or [],
                last_sequence_by_node=dict(window.get("last_sequence_by_node") or {}),
                generated_at=timestamp,
            )
        update = build_cluster_state_update_envelope(verified, generated_at=timestamp)
        if update["update_status"] == "accepted":
            previous_digest = _last_digest_for_scope(window, update["source_node_id"], update["trust_scope_label"])
            accepted.append(update)
            _record_accepted_update(window, update)
            if previous_digest and previous_digest != update["payload_digest"]:
                drift.append(
                    build_sync_conflict_record(
                        "summary_digest_drift",
                        update=update,
                        summary=f"Trusted node {update['source_node_id']} reported a new {update['trust_scope_label']} digest.",
                        generated_at=timestamp,
                    )
                )
        else:
            rejected.append(update)
            _record_rejected_update(window, update)
            conflicts.append(
                build_sync_conflict_record(
                    _conflict_type(update),
                    update=update,
                    summary=f"Signed summary update {update['envelope_id']} was classified as {update['update_status']}.",
                    generated_at=timestamp,
                )
            )

    merged_state = build_merged_cluster_state(accepted, expected_nodes=expected_nodes, generated_at=timestamp)
    summary = summarize_live_cluster_sync(
        window=window,
        accepted_updates=accepted,
        rejected_updates=rejected,
        conflicts=conflicts,
        drift=drift,
        merged_cluster_state=merged_state,
        generated_at=timestamp,
    )
    status = build_cluster_sync_dashboard_status(sync_summary=summary, merged_cluster_state=merged_state, generated_at=timestamp)
    return {
        "record_type": "live_cluster_state_synchronization",
        "record_version": SYNC_RECORD_VERSION,
        "sync_id": _stable_id("live-cluster-sync", window["window_id"], timestamp, summary),
        "generated_at": timestamp,
        "sync_window": {**window, "summary": summarize_synchronization_window(window, generated_at=timestamp)},
        "accepted_updates": accepted,
        "rejected_updates": rejected,
        "conflicts": sorted(conflicts, key=lambda item: item["conflict_id"]),
        "drift": sorted(drift, key=lambda item: item["conflict_id"]),
        "merged_cluster_state": merged_state,
        "dashboard_status": status,
        "api_status": status["api"],
        "summary": summary,
        **SIGNING_SAFETY_FLAGS,
    }


def build_cluster_state_update_envelope(
    verified_envelope: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    status = _update_status(str(verified_envelope.get("exchange_status") or "rejected"))
    verification = verified_envelope.get("verification_status") if isinstance(verified_envelope.get("verification_status"), dict) else {}
    payload = {
        "record_type": "live_cluster_state_update",
        "record_version": SIGNING_RECORD_VERSION,
        "update_id": "",
        "update_status": status,
        "envelope_id": str(verified_envelope.get("envelope_id") or ""),
        "source_node_id": str(verified_envelope.get("source_node_id") or ""),
        "destination_node_id": str(verified_envelope.get("destination_node_id") or ""),
        "transport_session_id": str(verified_envelope.get("transport_session_id") or ""),
        "trust_scope_label": str(verified_envelope.get("trust_scope_label") or ""),
        "summary_record_type": str(verified_envelope.get("summary_record_type") or ""),
        "summary_payload": dict(verified_envelope.get("summary_payload") or {}),
        "payload_digest": str(verified_envelope.get("payload_digest") or ""),
        "sequence": int(verified_envelope.get("sequence") or 0),
        "nonce": str(verified_envelope.get("nonce") or ""),
        "issued_at": str(verified_envelope.get("issued_at") or ""),
        "expires_at": str(verified_envelope.get("expires_at") or ""),
        "verification_status": dict(verification),
        "classification_reason": _classification_reason(status, verification),
        "source_refs": _source_refs(verified_envelope.get("source_refs"), fallback=f"node:{verified_envelope.get('source_node_id') or 'unknown'}"),
        "applied_at": timestamp if status == "accepted" else "",
        "rejected_at": timestamp if status != "accepted" else "",
        **SIGNING_SAFETY_FLAGS,
    }
    payload["update_id"] = _stable_id("cluster-update", payload["envelope_id"], payload["update_status"], payload["payload_digest"], payload["sequence"])
    return payload


def summarize_synchronization_window(window: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "generated_at": timestamp,
        "window_id": str(window.get("window_id") or ""),
        "trusted_node_count": len(window.get("trusted_node_ids") or []),
        "last_sequence_node_count": len(window.get("last_sequence_by_node") or {}),
        "last_digest_node_count": len(window.get("last_digest_by_node") or {}),
        "seen_nonce_count": len(window.get("seen_nonces") or []),
        "accepted_update_count": len(window.get("accepted_update_ids") or []),
        "rejected_update_count": len(window.get("rejected_update_ids") or []),
        "closed": _parse_time(str(window.get("closes_at") or timestamp)) <= _parse_time(timestamp),
        **SIGNING_SAFETY_FLAGS,
    }


def summarize_live_cluster_sync(
    *,
    window: dict[str, Any],
    accepted_updates: Iterable[dict[str, Any]],
    rejected_updates: Iterable[dict[str, Any]],
    conflicts: Iterable[dict[str, Any]],
    drift: Iterable[dict[str, Any]],
    merged_cluster_state: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    accepted_rows = _rows(accepted_updates)
    rejected_rows = _rows(rejected_updates)
    conflict_rows = _rows(conflicts)
    drift_rows = _rows(drift)
    by_status: dict[str, int] = {}
    by_scope: dict[str, int] = {}
    for update in [*accepted_rows, *rejected_rows]:
        by_status[update["update_status"]] = by_status.get(update["update_status"], 0) + 1
        scope = str(update.get("trust_scope_label") or "unknown")
        by_scope[scope] = by_scope.get(scope, 0) + 1
    merged_summary = merged_cluster_state.get("summary") if isinstance(merged_cluster_state.get("summary"), dict) else {}
    stale_count = by_status.get("stale", 0)
    replayed_count = by_status.get("replayed", 0)
    return {
        "generated_at": timestamp,
        "status": "review_required" if rejected_rows or conflict_rows or drift_rows else "ok",
        "window_id": str(window.get("window_id") or ""),
        "accepted_update_count": len(accepted_rows),
        "rejected_update_count": len(rejected_rows),
        "stale_update_count": stale_count,
        "replayed_update_count": replayed_count,
        "conflict_count": len(conflict_rows),
        "drift_count": len(drift_rows),
        "by_update_status": dict(sorted(by_status.items())),
        "by_trust_scope": dict(sorted(by_scope.items())),
        "last_sequence_by_node": dict(sorted((window.get("last_sequence_by_node") or {}).items())),
        "last_digest_by_node": dict(sorted((window.get("last_digest_by_node") or {}).items())),
        "last_seen_update_by_node": dict(sorted((window.get("last_seen_update_by_node") or {}).items())),
        "merged_source_node_count": int(merged_summary.get("source_node_count") or 0),
        "administrator_review_required": bool(rejected_rows or conflict_rows or drift_rows),
        **SIGNING_SAFETY_FLAGS,
    }


def build_sync_conflict_record(
    conflict_type: str,
    *,
    update: dict[str, Any],
    summary: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    severity = {
        "replayed_update": "high",
        "stale_update": "medium",
        "untrusted_update": "high",
        "malformed_update": "high",
        "summary_digest_drift": "medium",
    }.get(conflict_type, "medium")
    payload = {
        "record_type": "live_cluster_sync_conflict",
        "record_version": SYNC_RECORD_VERSION,
        "conflict_type": conflict_type,
        "severity": severity,
        "update_id": str(update.get("update_id") or ""),
        "envelope_id": str(update.get("envelope_id") or ""),
        "affected_ref": f"node:{update.get('source_node_id') or 'unknown'}",
        "source_node_ids": [str(update.get("source_node_id") or "unknown")],
        "source_refs": list(update.get("source_refs") or []),
        "summary": summary,
        "recommended_review": True,
        "detected_at": timestamp,
        **SIGNING_SAFETY_FLAGS,
    }
    payload["conflict_id"] = _stable_id("live-sync-conflict", conflict_type, payload["update_id"], summary)
    return payload


def deterministic_sync_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _record_accepted_update(window: dict[str, Any], update: dict[str, Any]) -> None:
    node_id = update["source_node_id"]
    scope = update["trust_scope_label"]
    window["accepted_update_ids"].append(update["update_id"])
    window["seen_nonces"] = sorted(set([*window.get("seen_nonces", []), update["nonce"]]))
    window["last_sequence_by_node"][node_id] = update["sequence"]
    window["last_digest_by_node"][f"{node_id}:{scope}"] = update["payload_digest"]
    window["last_seen_update_by_node"][node_id] = {
        "update_id": update["update_id"],
        "envelope_id": update["envelope_id"],
        "trust_scope_label": scope,
        "payload_digest": update["payload_digest"],
        "sequence": update["sequence"],
        "issued_at": update["issued_at"],
        **SIGNING_SAFETY_FLAGS,
    }


def _record_rejected_update(window: dict[str, Any], update: dict[str, Any]) -> None:
    window["rejected_update_ids"].append(update["update_id"])


def _last_digest_for_scope(window: dict[str, Any], node_id: str, scope: str) -> str:
    return str((window.get("last_digest_by_node") or {}).get(f"{node_id}:{scope}") or "")


def _classification_reason(status: str, verification: dict[str, Any]) -> str:
    errors = verification.get("errors") if isinstance(verification, dict) else []
    if status == "accepted":
        return "verified metadata accepted for synchronization window"
    if errors:
        return "; ".join(str(item) for item in errors)
    return f"exchange status classified as {status}"


def _conflict_type(update: dict[str, Any]) -> str:
    return {
        "replayed": "replayed_update",
        "stale": "stale_update",
        "untrusted": "untrusted_update",
        "malformed": "malformed_update",
    }.get(str(update.get("update_status") or ""), "rejected_update")


def _update_status(exchange_status: str) -> str:
    if exchange_status in SYNC_UPDATE_STATUSES:
        return exchange_status
    if exchange_status == "accepted":
        return "accepted"
    return "rejected"


def _copy_window(window: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(window, dict):
        raise LiveClusterSynchronizationError("sync_window must be an object")
    copied = {
        **dict(window),
        "last_sequence_by_node": _int_map(window.get("last_sequence_by_node")),
        "last_digest_by_node": _str_map(window.get("last_digest_by_node")),
        "last_seen_update_by_node": {
            str(key): dict(value)
            for key, value in dict(window.get("last_seen_update_by_node") or {}).items()
            if isinstance(value, dict)
        },
        "seen_nonces": sorted(set(str(item) for item in window.get("seen_nonces") or [] if str(item).strip())),
        "accepted_update_ids": sorted(set(str(item) for item in window.get("accepted_update_ids") or [] if str(item).strip())),
        "rejected_update_ids": sorted(set(str(item) for item in window.get("rejected_update_ids") or [] if str(item).strip())),
    }
    if not copied.get("window_id"):
        raise LiveClusterSynchronizationError("sync_window.window_id is required")
    return copied


def _transport_map(transport_sessions: Iterable[dict[str, Any]] | dict[str, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    if isinstance(transport_sessions, dict):
        rows = transport_sessions.values()
    else:
        rows = transport_sessions
    return {str(row.get("session_id") or ""): dict(row) for row in rows or [] if isinstance(row, dict) and row.get("session_id")}


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _int_map(value: Any) -> dict[str, int]:
    return {str(key): int(item) for key, item in dict(value or {}).items()}


def _str_map(value: Any) -> dict[str, str]:
    return {str(key): str(item) for key, item in dict(value or {}).items()}


def _source_refs(values: Iterable[str] | None, *, fallback: str) -> list[str]:
    refs = sorted(set(str(item) for item in values or [] if str(item).strip()))
    refs.append(fallback)
    return sorted(set(refs))


def _sorted_dict(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(value):
        item = value[key]
        result[str(key)] = _sorted_dict(item) if isinstance(item, dict) else item
    return result


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise LiveClusterSynchronizationError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
