from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


BASELINE_WINDOW_RECORD_VERSION = 1

DEFAULT_BASELINE_WINDOWS = {
    "short": {"duration_seconds": 300, "max_records": 250},
    "medium": {"duration_seconds": 3600, "max_records": 750},
    "long": {"duration_seconds": 86400, "max_records": 2000},
}

BASELINE_WINDOW_SAFETY_FLAGS = {
    **TELEMETRY_SAFETY_FLAGS,
    "metadata_only": True,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "credentials_stored": False,
    "bounded_memory": True,
    "automatic_blocking": False,
    "firewall_changes": False,
    "external_learning": False,
}


class BaselineWindowError(ValueError):
    """Raised when baseline window input is malformed."""


def build_baseline_window_records(
    observations: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    window_config: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """Build bounded short, medium, and long baseline window records."""
    timestamp = generated_at or _now()
    configs = _normalize_window_config(window_config or DEFAULT_BASELINE_WINDOWS)
    rows = _rows(observations)
    windows = {
        name: build_baseline_window_record(
            rows,
            window_name=name,
            duration_seconds=int(config["duration_seconds"]),
            max_records=int(config["max_records"]),
            generated_at=timestamp,
        )
        for name, config in sorted(configs.items())
    }
    return {
        "record_type": "baseline_window_set",
        "record_version": BASELINE_WINDOW_RECORD_VERSION,
        "generated_at": timestamp,
        "window_count": len(windows),
        "input_observation_count": len(rows),
        "windows": windows,
        "summary": summarize_baseline_windows(windows, generated_at=timestamp),
        **BASELINE_WINDOW_SAFETY_FLAGS,
    }


def build_baseline_window_record(
    observations: Iterable[dict[str, Any]],
    *,
    window_name: str,
    duration_seconds: int,
    max_records: int,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if int(duration_seconds) <= 0:
        raise BaselineWindowError("duration_seconds must be positive")
    if int(max_records) <= 0:
        raise BaselineWindowError("max_records must be positive")
    cutoff = _parse_time(timestamp) - timedelta(seconds=int(duration_seconds))
    candidates = [
        row
        for row in _rows(observations)
        if _observation_time(row) is not None and _observation_time(row) >= cutoff
    ]
    candidates = sorted(candidates, key=lambda item: (_timestamp_string(item), str(item.get("category") or ""), str(item.get("key") or "")))
    retained = candidates[-int(max_records) :]
    dropped = max(0, len(candidates) - len(retained))
    category_counts = _count_by(retained, "category")
    key_counts = _key_counts(retained)
    return {
        "record_type": "baseline_window",
        "record_version": BASELINE_WINDOW_RECORD_VERSION,
        "window_name": str(window_name),
        "generated_at": timestamp,
        "duration_seconds": int(duration_seconds),
        "max_records": int(max_records),
        "retained_observation_count": len(retained),
        "dropped_observation_count": dropped,
        "earliest_seen": min((_timestamp_string(row) for row in retained), default=""),
        "latest_seen": max((_timestamp_string(row) for row in retained), default=""),
        "category_counts": category_counts,
        "key_counts": key_counts,
        "observation_refs": [str(row.get("observation_ref") or _digest(row)[:16]) for row in retained],
        **BASELINE_WINDOW_SAFETY_FLAGS,
    }


def summarize_baseline_windows(windows: dict[str, dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(value) for value in (windows or {}).values() if isinstance(value, dict)]
    return {
        "record_type": "baseline_window_summary",
        "record_version": BASELINE_WINDOW_RECORD_VERSION,
        "generated_at": timestamp,
        "window_count": len(rows),
        "retained_observation_count": sum(int(row.get("retained_observation_count") or 0) for row in rows),
        "dropped_observation_count": sum(int(row.get("dropped_observation_count") or 0) for row in rows),
        "windows": {
            str(row.get("window_name") or "unknown"): {
                "duration_seconds": int(row.get("duration_seconds") or 0),
                "retained_observation_count": int(row.get("retained_observation_count") or 0),
                "dropped_observation_count": int(row.get("dropped_observation_count") or 0),
                "earliest_seen": str(row.get("earliest_seen") or ""),
                "latest_seen": str(row.get("latest_seen") or ""),
            }
            for row in sorted(rows, key=lambda item: str(item.get("window_name") or ""))
        },
        **BASELINE_WINDOW_SAFETY_FLAGS,
    }


def deterministic_baseline_window_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _normalize_window_config(config: dict[str, dict[str, int]]) -> dict[str, dict[str, int]]:
    normalized: dict[str, dict[str, int]] = {}
    for name in ("short", "medium", "long"):
        values = dict((config or {}).get(name) or DEFAULT_BASELINE_WINDOWS[name])
        duration = int(values.get("duration_seconds") or 0)
        max_records = int(values.get("max_records") or 0)
        if duration <= 0 or max_records <= 0:
            raise BaselineWindowError(f"{name} window requires positive duration_seconds and max_records")
        normalized[name] = {"duration_seconds": duration, "max_records": max_records}
    return normalized


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _key_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        key = f"{row.get('category') or 'unknown'}:{row.get('key') or 'unknown'}"
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items()))


def _timestamp_string(row: dict[str, Any]) -> str:
    return str(row.get("observed_at") or row.get("last_seen") or row.get("first_seen") or row.get("timestamp") or row.get("generated_at") or "")


def _observation_time(row: dict[str, Any]) -> datetime | None:
    value = _timestamp_string(row)
    if not value:
        return None
    try:
        return _parse_time(value)
    except ValueError:
        return None


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
