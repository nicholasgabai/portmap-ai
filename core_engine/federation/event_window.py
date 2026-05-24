from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Iterable

from core_engine.federation.signing import SIGNING_SAFETY_FLAGS


EVENT_WINDOW_RECORD_VERSION = 1


class EventPropagationWindowError(ValueError):
    """Raised when an event propagation window is malformed."""


def build_event_propagation_window(
    *,
    window_id: str | None = None,
    trusted_node_ids: Iterable[str] | None = None,
    opened_at: str | None = None,
    closes_at: str | None = None,
    replay_window_seconds: int = 300,
    last_sequence_by_node: dict[str, int] | None = None,
    last_event_digest_by_node: dict[str, str] | None = None,
    seen_event_digests: Iterable[str] | None = None,
    seen_nonces: Iterable[str] | None = None,
    runtime_session_ref: dict[str, Any] | None = None,
    source_refs: Iterable[str] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    timestamp = opened_at or _now()
    if replay_window_seconds <= 0:
        raise EventPropagationWindowError("replay_window_seconds must be greater than zero")
    close_time = closes_at or (_parse_time(timestamp) + timedelta(seconds=replay_window_seconds)).isoformat()
    nodes = sorted(set(str(item) for item in trusted_node_ids or [] if str(item).strip()))
    payload = {
        "record_type": "distributed_event_propagation_window",
        "record_version": EVENT_WINDOW_RECORD_VERSION,
        "window_id": window_id or _stable_id("event-window", timestamp, nodes, runtime_session_ref or {}),
        "opened_at": timestamp,
        "closes_at": close_time,
        "replay_window_seconds": int(replay_window_seconds),
        "trusted_node_ids": nodes,
        "runtime_session_ref": dict(runtime_session_ref or {}),
        "last_sequence_by_node": _int_map(last_sequence_by_node),
        "last_event_digest_by_node": _str_map(last_event_digest_by_node),
        "last_seen_event_by_node": {},
        "seen_event_digests": sorted(set(str(item) for item in seen_event_digests or [] if str(item).strip())),
        "seen_nonces": sorted(set(str(item) for item in seen_nonces or [] if str(item).strip())),
        "accepted_event_ids": [],
        "rejected_event_ids": [],
        "source_refs": _source_refs(source_refs, fallback="event-window:local"),
        "metadata": _sorted_dict(metadata or {}),
        **SIGNING_SAFETY_FLAGS,
    }
    payload["summary"] = summarize_event_propagation_window(payload, generated_at=timestamp)
    return payload


def summarize_event_propagation_window(window: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "generated_at": timestamp,
        "window_id": str(window.get("window_id") or ""),
        "trusted_node_count": len(window.get("trusted_node_ids") or []),
        "last_sequence_node_count": len(window.get("last_sequence_by_node") or {}),
        "last_event_digest_node_count": len(window.get("last_event_digest_by_node") or {}),
        "seen_event_digest_count": len(window.get("seen_event_digests") or []),
        "seen_nonce_count": len(window.get("seen_nonces") or []),
        "accepted_event_count": len(window.get("accepted_event_ids") or []),
        "rejected_event_count": len(window.get("rejected_event_ids") or []),
        "closed": _parse_time(str(window.get("closes_at") or timestamp)) <= _parse_time(timestamp),
        **SIGNING_SAFETY_FLAGS,
    }


def copy_event_propagation_window(window: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(window, dict):
        raise EventPropagationWindowError("event propagation window must be an object")
    copied = {
        **dict(window),
        "last_sequence_by_node": _int_map(window.get("last_sequence_by_node")),
        "last_event_digest_by_node": _str_map(window.get("last_event_digest_by_node")),
        "last_seen_event_by_node": {
            str(key): dict(value)
            for key, value in dict(window.get("last_seen_event_by_node") or {}).items()
            if isinstance(value, dict)
        },
        "seen_event_digests": sorted(set(str(item) for item in window.get("seen_event_digests") or [] if str(item).strip())),
        "seen_nonces": sorted(set(str(item) for item in window.get("seen_nonces") or [] if str(item).strip())),
        "accepted_event_ids": sorted(set(str(item) for item in window.get("accepted_event_ids") or [] if str(item).strip())),
        "rejected_event_ids": sorted(set(str(item) for item in window.get("rejected_event_ids") or [] if str(item).strip())),
    }
    if not copied.get("window_id"):
        raise EventPropagationWindowError("window_id is required")
    return copied


def deterministic_event_window_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


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
        raise EventPropagationWindowError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
