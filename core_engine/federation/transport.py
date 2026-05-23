from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.trust import (
    DEFAULT_REPLAY_WINDOW_SECONDS,
    TRUST_SCOPE_LABELS,
    TRUST_SAFETY_FLAGS,
    TrustedNodeTrustError,
    build_approved_peer_record,
    deterministic_trust_json,
    is_peer_approved,
    normalize_node_identity_reference,
)


TRANSPORT_RECORD_VERSION = 1
DEFAULT_TRANSPORT_MODE = "local-file"
TRUSTED_TRANSPORT_MODES = frozenset({"local-file", "loopback-api", "trusted-lan-preview"})
TRUSTED_TRANSPORT_STATUSES = frozenset({"planned", "handshake-pending", "established", "expired", "closed", "rejected"})


class TrustedTransportError(ValueError):
    """Raised when trusted transport records are malformed."""


def create_trusted_transport_session(
    *,
    source_node: dict[str, Any],
    destination_node: dict[str, Any],
    trust_profile: dict[str, Any],
    transport_mode: str = DEFAULT_TRANSPORT_MODE,
    trust_scope_label: str = "runtime-summary",
    session_id: str | None = None,
    status: str = "planned",
    started_at: str | None = None,
    expires_at: str | None = None,
    replay_window_seconds: int | None = None,
    source_refs: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Create a local trusted transport session record.

    This builds metadata only. It does not open sockets, start listeners,
    contact destination nodes, or sign records.
    """
    timestamp = started_at or _now()
    mode = _transport_mode(transport_mode)
    scope = _trust_scope(trust_scope_label)
    session_status = _session_status(status)
    source = normalize_node_identity_reference(source_node)
    destination_peer = _peer_record(destination_node, generated_at=timestamp)
    _validate_profile_source(trust_profile, source["node_id"])
    if not is_peer_approved(
        trust_profile,
        destination_peer["peer_node_id"],
        trust_scope_label=scope,
        transport_mode=mode,
        generated_at=timestamp,
    ):
        raise TrustedTransportError(f"destination node is not approved for {scope} over {mode}")
    replay_window = replay_window_seconds or int(trust_profile.get("replay_window_seconds") or DEFAULT_REPLAY_WINDOW_SECONDS)
    expiry = expires_at or _add_seconds(timestamp, replay_window)
    replay = build_replay_window_metadata(
        window_started_at=timestamp,
        window_expires_at=expiry,
        replay_window_seconds=replay_window,
    )
    payload = {
        "record_type": "trusted_node_transport_session",
        "record_version": TRANSPORT_RECORD_VERSION,
        "session_id": session_id or _stable_id("transport-session", source["node_id"], destination_peer["peer_node_id"], scope, mode, timestamp),
        "status": session_status,
        "transport_mode": mode,
        "trust_scope_label": scope,
        "trust_scope_labels": [scope],
        "source_node": source,
        "destination_node": {
            "node_id": destination_peer["peer_node_id"],
            "role": destination_peer["peer_role"],
            "label": destination_peer["peer_label"],
            "identity_reference": destination_peer["identity_reference"],
        },
        "source_node_id": source["node_id"],
        "destination_node_id": destination_peer["peer_node_id"],
        "trust_profile_id": str(trust_profile.get("profile_id") or ""),
        "started_at": timestamp,
        "expires_at": expiry,
        "replay_window": replay,
        "source_refs": _source_refs(source_refs, fallback=f"node:{source['node_id']}"),
        "destination_refs": _source_refs(destination_peer.get("source_refs"), fallback=f"node:{destination_peer['peer_node_id']}"),
        "metadata": _sorted_dict(metadata or {}),
        **TRUST_SAFETY_FLAGS,
    }
    payload["handshake_summary"] = build_handshake_summary(payload, status="pending", generated_at=timestamp)
    payload["validation"] = validate_trusted_transport_session(payload, generated_at=timestamp)
    if not payload["validation"]["ok"]:
        raise TrustedTransportError("; ".join(payload["validation"]["errors"]))
    return payload


def trusted_transport_session_to_dict(session: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(session, dict):
        raise TrustedTransportError("transport session must be an object")
    payload = dict(session)
    payload["transport_mode"] = _transport_mode(payload.get("transport_mode") or DEFAULT_TRANSPORT_MODE)
    payload["status"] = _session_status(payload.get("status") or "planned")
    payload["trust_scope_label"] = _trust_scope(payload.get("trust_scope_label") or "runtime-summary")
    payload["trust_scope_labels"] = sorted(set(str(item) for item in payload.get("trust_scope_labels") or [payload["trust_scope_label"]]))
    payload["source_node"] = dict(payload.get("source_node") or {})
    payload["destination_node"] = dict(payload.get("destination_node") or {})
    payload["replay_window"] = dict(payload.get("replay_window") or {})
    payload["source_refs"] = _source_refs(payload.get("source_refs"), fallback=f"node:{payload.get('source_node_id') or 'unknown'}")
    payload["destination_refs"] = _source_refs(payload.get("destination_refs"), fallback=f"node:{payload.get('destination_node_id') or 'unknown'}")
    payload["metadata"] = _sorted_dict(payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {})
    payload.update(TRUST_SAFETY_FLAGS)
    return payload


def trusted_transport_session_from_dict(payload: dict[str, Any]) -> dict[str, Any]:
    session = trusted_transport_session_to_dict(payload)
    validation = validate_trusted_transport_session(session)
    session["validation"] = validation
    if not validation["ok"]:
        raise TrustedTransportError("; ".join(validation["errors"]))
    return session


def build_handshake_summary(
    session: dict[str, Any],
    *,
    status: str = "pending",
    generated_at: str | None = None,
    message: str = "",
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    source_node_id = str(session.get("source_node_id") or (session.get("source_node") or {}).get("node_id") or "")
    destination_node_id = str(session.get("destination_node_id") or (session.get("destination_node") or {}).get("node_id") or "")
    handshake_status = str(status or "pending")
    payload = {
        "record_type": "trusted_transport_handshake_summary",
        "record_version": TRANSPORT_RECORD_VERSION,
        "session_id": str(session.get("session_id") or ""),
        "handshake_status": handshake_status,
        "source_node_id": source_node_id,
        "destination_node_id": destination_node_id,
        "transport_mode": str(session.get("transport_mode") or DEFAULT_TRANSPORT_MODE),
        "trust_scope_label": str(session.get("trust_scope_label") or "runtime-summary"),
        "expires_at": str(session.get("expires_at") or ""),
        "generated_at": timestamp,
        "message": str(message or ""),
        "source_refs": _source_refs(session.get("source_refs"), fallback=f"node:{source_node_id or 'unknown'}"),
        "destination_refs": _source_refs(session.get("destination_refs"), fallback=f"node:{destination_node_id or 'unknown'}"),
        **TRUST_SAFETY_FLAGS,
    }
    payload["handshake_id"] = _stable_id(
        "transport-handshake",
        payload["session_id"],
        payload["handshake_status"],
        source_node_id,
        destination_node_id,
        timestamp,
    )
    return payload


def build_replay_window_metadata(
    *,
    window_started_at: str,
    window_expires_at: str,
    replay_window_seconds: int = DEFAULT_REPLAY_WINDOW_SECONDS,
    sequence_floor: int = 0,
    sequence_ceiling: int | None = None,
) -> dict[str, Any]:
    if replay_window_seconds <= 0:
        raise TrustedTransportError("replay_window_seconds must be greater than zero")
    if sequence_floor < 0:
        raise TrustedTransportError("sequence_floor must be non-negative")
    ceiling = sequence_ceiling if sequence_ceiling is not None else sequence_floor
    if ceiling < sequence_floor:
        raise TrustedTransportError("sequence_ceiling must be greater than or equal to sequence_floor")
    return {
        "record_type": "trusted_transport_replay_window",
        "record_version": TRANSPORT_RECORD_VERSION,
        "window_started_at": str(window_started_at),
        "window_expires_at": str(window_expires_at),
        "replay_window_seconds": int(replay_window_seconds),
        "accepted_sequence_floor": int(sequence_floor),
        "accepted_sequence_ceiling": int(ceiling),
        "nonce_required": True,
        "replay_protection_mode": "metadata-only",
        "replay_safe_records": True,
        **TRUST_SAFETY_FLAGS,
    }


def validate_trusted_transport_session(session: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(session, dict):
        return _validation(False, ["transport session must be an object"], [], generated_at=timestamp)
    if not str(session.get("session_id") or "").strip():
        errors.append("session_id is required")
    if session.get("status") not in TRUSTED_TRANSPORT_STATUSES:
        errors.append("status must be a trusted transport status")
    if session.get("transport_mode") not in TRUSTED_TRANSPORT_MODES:
        errors.append("transport_mode is unsupported")
    if session.get("trust_scope_label") not in TRUST_SCOPE_LABELS:
        errors.append("trust_scope_label is unsupported")
    if not str(session.get("source_node_id") or "").strip():
        errors.append("source_node_id is required")
    if not str(session.get("destination_node_id") or "").strip():
        errors.append("destination_node_id is required")
    if session.get("source_node_id") == session.get("destination_node_id"):
        errors.append("source and destination nodes must differ")
    replay = session.get("replay_window")
    if not isinstance(replay, dict):
        errors.append("replay_window is required")
    elif not replay.get("replay_safe_records"):
        errors.append("replay_window must mark records as replay-safe")
    if _is_expired(session.get("expires_at"), generated_at=timestamp):
        warnings.append("transport session is expired")
    return _validation(not errors, errors, warnings, generated_at=timestamp)


def build_transport_session_summary(
    sessions: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = sorted((trusted_transport_session_to_dict(row) for row in sessions), key=lambda item: item["session_id"])
    by_status: dict[str, int] = {}
    by_mode: dict[str, int] = {}
    by_scope: dict[str, int] = {}
    expired_count = 0
    for row in rows:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
        by_mode[row["transport_mode"]] = by_mode.get(row["transport_mode"], 0) + 1
        by_scope[row["trust_scope_label"]] = by_scope.get(row["trust_scope_label"], 0) + 1
        if _is_expired(row.get("expires_at"), generated_at=timestamp):
            expired_count += 1
    return {
        "record_type": "trusted_transport_session_summary",
        "record_version": TRANSPORT_RECORD_VERSION,
        "summary_id": _stable_id("transport-summary", timestamp, rows),
        "generated_at": timestamp,
        "session_count": len(rows),
        "expired_session_count": expired_count,
        "by_status": dict(sorted(by_status.items())),
        "by_transport_mode": dict(sorted(by_mode.items())),
        "by_trust_scope": dict(sorted(by_scope.items())),
        "sessions": rows,
        **TRUST_SAFETY_FLAGS,
    }


def deterministic_transport_json(record: dict[str, Any]) -> str:
    return deterministic_trust_json(record)


def _peer_record(destination_node: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    if destination_node.get("record_type") == "approved_peer_record":
        return dict(destination_node)
    try:
        return build_approved_peer_record(destination_node, approved_at=generated_at)
    except TrustedNodeTrustError as exc:
        raise TrustedTransportError(str(exc)) from exc


def _validate_profile_source(profile: dict[str, Any], source_node_id: str) -> None:
    local_node = profile.get("local_node") if isinstance(profile, dict) else {}
    if not isinstance(local_node, dict) or str(local_node.get("node_id") or "") != source_node_id:
        raise TrustedTransportError("trust profile local_node does not match source_node")


def _transport_mode(value: Any) -> str:
    mode = str(value or "")
    if mode not in TRUSTED_TRANSPORT_MODES:
        raise TrustedTransportError(f"unsupported transport_mode: {mode}")
    return mode


def _session_status(value: Any) -> str:
    status = str(value or "")
    if status not in TRUSTED_TRANSPORT_STATUSES:
        raise TrustedTransportError(f"unsupported transport session status: {status}")
    return status


def _trust_scope(value: Any) -> str:
    scope = str(value or "")
    if scope not in TRUST_SCOPE_LABELS:
        raise TrustedTransportError(f"unsupported trust_scope_label: {scope}")
    return scope


def _add_seconds(timestamp: str, seconds: int) -> str:
    return (_parse_time(timestamp) + timedelta(seconds=seconds)).isoformat()


def _is_expired(value: Any, *, generated_at: str) -> bool:
    if not value:
        return False
    try:
        return _parse_time(str(value)) <= _parse_time(generated_at)
    except TrustedTransportError:
        return True


def _parse_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as exc:
        raise TrustedTransportError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


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


def _validation(ok: bool, errors: list[str], warnings: list[str], *, generated_at: str) -> dict[str, Any]:
    return {
        "ok": ok,
        "status": "valid" if ok else "invalid",
        "errors": sorted(errors),
        "warnings": sorted(warnings),
        "generated_at": generated_at,
        **TRUST_SAFETY_FLAGS,
    }


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
