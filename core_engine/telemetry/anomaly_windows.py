from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.telemetry.behavior_baselines import BEHAVIOR_BASELINE_SAFETY_FLAGS


ANOMALY_WINDOW_RECORD_VERSION = 1
DEFAULT_MAX_ANOMALY_WINDOW_KEYS = 100

ANOMALY_WINDOW_SAFETY_FLAGS = {
    **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    "advisory_only": True,
    "dry_run_safe": True,
    "raw_packet_payloads_stored": False,
    "credentials_stored": False,
    "external_reputation_calls": False,
    "automatic_remediation": False,
    "firewall_changes": False,
}


class AnomalyWindowError(ValueError):
    """Raised when anomaly window input is malformed."""


def build_anomaly_window_records(
    baseline_report: dict[str, Any] | None,
    *,
    generated_at: str | None = None,
    max_keys_per_window: int = DEFAULT_MAX_ANOMALY_WINDOW_KEYS,
) -> dict[str, Any]:
    """Build bounded anomaly-ready window records from a behavior baseline report."""
    timestamp = generated_at or _generated_at(baseline_report)
    if int(max_keys_per_window) <= 0:
        raise AnomalyWindowError("max_keys_per_window must be positive")
    if not isinstance(baseline_report, dict):
        return _empty_window_set(generated_at=timestamp)
    window_set = baseline_report.get("window_set") if isinstance(baseline_report.get("window_set"), dict) else {}
    windows = window_set.get("windows") if isinstance(window_set.get("windows"), dict) else {}
    records = {
        name: build_anomaly_window_record(
            window,
            baseline_entries=baseline_report.get("entries") if isinstance(baseline_report.get("entries"), list) else [],
            window_name=name,
            generated_at=timestamp,
            max_keys=int(max_keys_per_window),
        )
        for name, window in sorted(windows.items())
        if isinstance(window, dict)
    }
    return {
        "record_type": "temporal_anomaly_window_set",
        "record_version": ANOMALY_WINDOW_RECORD_VERSION,
        "generated_at": timestamp,
        "window_count": len(records),
        "windows": records,
        "summary": summarize_anomaly_windows(records, generated_at=timestamp),
        **ANOMALY_WINDOW_SAFETY_FLAGS,
    }


def build_anomaly_window_record(
    window: dict[str, Any],
    *,
    baseline_entries: list[dict[str, Any]],
    window_name: str,
    generated_at: str | None = None,
    max_keys: int = DEFAULT_MAX_ANOMALY_WINDOW_KEYS,
) -> dict[str, Any]:
    timestamp = generated_at or _generated_at(window)
    key_counts = {
        str(key): int(value)
        for key, value in (window.get("key_counts") or {}).items()
        if value is not None
    }
    retained = int(window.get("retained_observation_count") or 0)
    duration = int(window.get("duration_seconds") or 0)
    entry_index = _entry_index(baseline_entries)
    bounded_keys = sorted(key_counts.items(), key=lambda item: (-item[1], item[0]))[: int(max_keys)]
    dropped = max(0, len(key_counts) - len(bounded_keys))
    return {
        "record_type": "temporal_anomaly_window",
        "record_version": ANOMALY_WINDOW_RECORD_VERSION,
        "window_name": str(window_name),
        "generated_at": timestamp,
        "duration_seconds": duration,
        "retained_observation_count": retained,
        "dropped_key_count": dropped,
        "observation_rate_per_second": round(retained / duration, 6) if duration > 0 else 0.0,
        "category_counts": dict(sorted((window.get("category_counts") or {}).items())),
        "key_counts": dict(bounded_keys),
        "novel_key_count": sum(1 for key, _count in bounded_keys if _entry_state(entry_index.get(key)) == "new"),
        "stable_key_count": sum(1 for key, _count in bounded_keys if _entry_state(entry_index.get(key)) == "stable"),
        "rare_key_count": sum(1 for key, _count in bounded_keys if _entry_observation_count(entry_index.get(key)) <= 2),
        "window_id": "anomaly-window-" + _digest({"window_name": window_name, "generated_at": timestamp})[:16],
        **ANOMALY_WINDOW_SAFETY_FLAGS,
    }


def summarize_anomaly_windows(windows: dict[str, dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in (windows or {}).values() if isinstance(row, dict)]
    return {
        "record_type": "temporal_anomaly_window_summary",
        "record_version": ANOMALY_WINDOW_RECORD_VERSION,
        "generated_at": timestamp,
        "window_count": len(rows),
        "retained_observation_count": sum(int(row.get("retained_observation_count") or 0) for row in rows),
        "novel_key_count": sum(int(row.get("novel_key_count") or 0) for row in rows),
        "rare_key_count": sum(int(row.get("rare_key_count") or 0) for row in rows),
        "dropped_key_count": sum(int(row.get("dropped_key_count") or 0) for row in rows),
        "windows": {
            str(row.get("window_name") or "unknown"): {
                "retained_observation_count": int(row.get("retained_observation_count") or 0),
                "observation_rate_per_second": float(row.get("observation_rate_per_second") or 0.0),
                "novel_key_count": int(row.get("novel_key_count") or 0),
                "rare_key_count": int(row.get("rare_key_count") or 0),
            }
            for row in sorted(rows, key=lambda item: str(item.get("window_name") or ""))
        },
        **ANOMALY_WINDOW_SAFETY_FLAGS,
    }


def deterministic_anomaly_window_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _empty_window_set(*, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": "temporal_anomaly_window_set",
        "record_version": ANOMALY_WINDOW_RECORD_VERSION,
        "generated_at": generated_at,
        "window_count": 0,
        "windows": {},
        "summary": summarize_anomaly_windows({}, generated_at=generated_at),
        "malformed_input": True,
        **ANOMALY_WINDOW_SAFETY_FLAGS,
    }


def _entry_index(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in entries or []:
        if not isinstance(row, dict):
            continue
        category = str(row.get("category") or "")
        key = str(row.get("baseline_key") or "")
        if category and key:
            index[f"{category}:{key}"] = row
    return index


def _entry_state(entry: dict[str, Any] | None) -> str:
    return str((entry or {}).get("behavior_state") or "unknown")


def _entry_observation_count(entry: dict[str, Any] | None) -> int:
    return int((entry or {}).get("observation_count") or 0)


def _generated_at(record: dict[str, Any] | None) -> str:
    if isinstance(record, dict) and record.get("generated_at"):
        return str(record.get("generated_at"))
    return _now()


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
