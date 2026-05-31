from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.history.snapshots import (
    HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    build_malformed_snapshot_record,
    validate_historical_snapshot,
)


REPLAY_WINDOW_RECORD_VERSION = 1
DEFAULT_MAX_REPLAY_EVENTS = 200

REPLAY_WINDOW_SAFETY_FLAGS = {
    **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    "historical_replay_only": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "collectors_rerun": False,
    "payload_bytes_stored": 0,
    "packet_payloads_stored": False,
    "credentials_stored": False,
    "raw_browsing_history_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


def build_replay_window_record(
    *,
    window_label: str = "historical-review",
    start_at: str | None = None,
    end_at: str | None = None,
    max_events: int = DEFAULT_MAX_REPLAY_EVENTS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    window = {
        "record_type": "historical_replay_window",
        "record_version": REPLAY_WINDOW_RECORD_VERSION,
        "generated_at": timestamp,
        "window_label": _safe_label(window_label),
        "start_at": str(start_at or ""),
        "end_at": str(end_at or ""),
        "max_events": max(0, int(max_events)),
        "bounded_window": True,
        "replay_cursor": "",
        **REPLAY_WINDOW_SAFETY_FLAGS,
    }
    window["window_id"] = "historical-replay-window-" + _digest(
        {
            "label": window["window_label"],
            "start_at": window["start_at"],
            "end_at": window["end_at"],
            "max_events": window["max_events"],
        }
    )[:16]
    window["replay_cursor"] = "cursor-" + _digest({"window_id": window["window_id"], "generated_at": timestamp})[:16]
    return window


def build_snapshot_sequence_summary(
    snapshots: Iterable[dict[str, Any]] | None = None,
    *,
    replay_window: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    window = replay_window or infer_replay_window(snapshots or [], generated_at=timestamp)
    selected, malformed = select_snapshots_for_replay_window(snapshots or [], replay_window=window)
    return {
        "record_type": "historical_snapshot_sequence_summary",
        "record_version": REPLAY_WINDOW_RECORD_VERSION,
        "generated_at": timestamp,
        "window": dict(window),
        "snapshot_count": len(selected),
        "malformed_snapshot_count": len(malformed),
        "first_snapshot_at": selected[0]["snapshot_timestamp"] if selected else "",
        "last_snapshot_at": selected[-1]["snapshot_timestamp"] if selected else "",
        "snapshot_ids": [str(row.get("snapshot_id") or "") for row in selected],
        "snapshot_digests": [str(row.get("snapshot_digest") or "") for row in selected if row.get("snapshot_digest")],
        "malformed_snapshots": malformed,
        **REPLAY_WINDOW_SAFETY_FLAGS,
    }


def select_snapshots_for_replay_window(
    snapshots: Iterable[dict[str, Any]],
    *,
    replay_window: dict[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    selected: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    start = _parse_time(str(replay_window.get("start_at") or ""))
    end = _parse_time(str(replay_window.get("end_at") or ""))
    limit = max(0, int(replay_window.get("max_events") or DEFAULT_MAX_REPLAY_EVENTS))
    for row in snapshots or []:
        if not isinstance(row, dict):
            malformed.append(build_malformed_snapshot_record(errors=["snapshot entry must be an object"]))
            continue
        validation = validate_historical_snapshot(row)
        if not validation["valid"]:
            malformed.append(build_malformed_snapshot_record(raw_record=row, errors=validation["errors"]))
            continue
        when = _parse_time(str(row.get("snapshot_timestamp") or row.get("generated_at") or ""))
        if start and when and when < start:
            continue
        if end and when and when > end:
            continue
        selected.append(dict(row))
    selected = sorted(selected, key=lambda item: (str(item.get("snapshot_timestamp") or ""), str(item.get("snapshot_id") or "")))
    return selected[:limit], malformed


def infer_replay_window(
    snapshots: Iterable[dict[str, Any]] | None = None,
    *,
    max_events: int = DEFAULT_MAX_REPLAY_EVENTS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    valid_times = []
    for row in snapshots or []:
        if isinstance(row, dict) and validate_historical_snapshot(row)["valid"]:
            value = str(row.get("snapshot_timestamp") or row.get("generated_at") or "")
            if value:
                valid_times.append(value)
    return build_replay_window_record(
        start_at=min(valid_times) if valid_times else "",
        end_at=max(valid_times) if valid_times else "",
        max_events=max_events,
        generated_at=generated_at,
    )


def deterministic_replay_window_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _safe_label(value: str) -> str:
    text = str(value or "historical-review").strip().lower().replace(" ", "-")
    return "".join(ch for ch in text if ch.isalnum() or ch in {"-", "_", "."})[:80] or "historical-review"


def _parse_time(value: str) -> datetime | None:
    text = str(value or "")
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
