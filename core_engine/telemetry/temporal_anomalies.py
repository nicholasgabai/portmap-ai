from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.telemetry.anomaly_windows import (
    ANOMALY_WINDOW_SAFETY_FLAGS,
    DEFAULT_MAX_ANOMALY_WINDOW_KEYS,
    build_anomaly_window_records,
)


TEMPORAL_ANOMALY_RECORD_VERSION = 1
DEFAULT_MAX_TEMPORAL_ANOMALIES = 200
DEFAULT_BURST_MULTIPLIER = 2.5
DEFAULT_MIN_BURST_COUNT = 4
DEFAULT_VOLUME_DRIFT_MULTIPLIER = 2.0

TEMPORAL_ANOMALY_SAFETY_FLAGS = {
    **ANOMALY_WINDOW_SAFETY_FLAGS,
    "baseline_aware": True,
    "operator_review_required": False,
}


class TemporalAnomalyError(ValueError):
    """Raised when temporal anomaly configuration is malformed."""


def build_temporal_anomaly_report(
    baseline_report: dict[str, Any] | None,
    *,
    generated_at: str | None = None,
    max_anomalies: int = DEFAULT_MAX_TEMPORAL_ANOMALIES,
    max_keys_per_window: int = DEFAULT_MAX_ANOMALY_WINDOW_KEYS,
    burst_multiplier: float = DEFAULT_BURST_MULTIPLIER,
    min_burst_count: int = DEFAULT_MIN_BURST_COUNT,
    volume_drift_multiplier: float = DEFAULT_VOLUME_DRIFT_MULTIPLIER,
) -> dict[str, Any]:
    """Build advisory temporal anomaly summaries from local behavior baselines."""
    timestamp = generated_at or _generated_at(baseline_report)
    if int(max_anomalies) <= 0:
        raise TemporalAnomalyError("max_anomalies must be positive")
    if float(burst_multiplier) <= 1:
        raise TemporalAnomalyError("burst_multiplier must be greater than 1")
    windows = build_anomaly_window_records(
        baseline_report,
        generated_at=timestamp,
        max_keys_per_window=max_keys_per_window,
    )
    if not isinstance(baseline_report, dict):
        anomalies = [
            _anomaly(
                label="malformed_baseline_input",
                window_name="none",
                category="input",
                baseline_key="malformed",
                display_label="Malformed baseline input",
                confidence=0.2,
                severity="low",
                explanation="Baseline input was missing or malformed, so temporal anomaly detection used an empty safe state.",
                generated_at=timestamp,
            )
        ]
    else:
        entries = [dict(row) for row in baseline_report.get("entries") or [] if isinstance(row, dict)]
        anomalies = []
        anomalies.extend(detect_burst_anomalies(windows, entries=entries, generated_at=timestamp, burst_multiplier=burst_multiplier, min_burst_count=min_burst_count))
        anomalies.extend(detect_rare_service_timing(windows, entries=entries, generated_at=timestamp))
        anomalies.extend(detect_volume_drift_hints(windows, generated_at=timestamp, volume_drift_multiplier=volume_drift_multiplier))
        anomalies.extend(detect_window_novelty(windows, entries=entries, generated_at=timestamp))
    anomalies = _dedupe_anomalies(anomalies)
    dropped = max(0, len(anomalies) - int(max_anomalies))
    selected = sorted(anomalies, key=lambda item: (-float(item.get("confidence") or 0.0), str(item.get("label") or ""), str(item.get("baseline_key") or "")))[: int(max_anomalies)]
    for row in selected:
        row["bounded_retention_applied"] = dropped > 0
        row["dropped_anomaly_count"] = dropped
    summary = summarize_temporal_anomalies(selected, anomaly_windows=windows, dropped_anomaly_count=dropped, generated_at=timestamp)
    dashboard = build_temporal_anomaly_dashboard_record(summary=summary, anomalies=selected, generated_at=timestamp)
    api = build_temporal_anomaly_api_response(summary=summary, anomaly_windows=windows, anomalies=selected, dashboard=dashboard, generated_at=timestamp)
    export = build_temporal_anomaly_export_record(summary=summary, anomalies=selected, generated_at=timestamp)
    return {
        "record_type": "temporal_anomaly_report",
        "record_version": TEMPORAL_ANOMALY_RECORD_VERSION,
        "report_id": "temporal-anomaly-report-" + _digest({"generated_at": timestamp, "anomalies": [row.get("anomaly_id") for row in selected]})[:16],
        "generated_at": timestamp,
        "max_anomalies": int(max_anomalies),
        "dropped_anomaly_count": dropped,
        "anomaly_windows": windows,
        "anomalies": selected,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **TEMPORAL_ANOMALY_SAFETY_FLAGS,
    }


def detect_burst_anomalies(
    anomaly_windows: dict[str, Any],
    *,
    entries: list[dict[str, Any]],
    generated_at: str,
    burst_multiplier: float = DEFAULT_BURST_MULTIPLIER,
    min_burst_count: int = DEFAULT_MIN_BURST_COUNT,
) -> list[dict[str, Any]]:
    windows = _windows(anomaly_windows)
    short = windows.get("short") or {}
    medium = windows.get("medium") or {}
    long = windows.get("long") or {}
    entry_index = _entry_index(entries)
    rows = []
    for key, short_count in (short.get("key_counts") or {}).items():
        medium_count = int((medium.get("key_counts") or {}).get(key) or 0)
        long_count = int((long.get("key_counts") or {}).get(key) or 0)
        baseline_count = max(medium_count, long_count, 1)
        expected_short = max(1.0, baseline_count * _window_ratio(short, medium if medium_count else long))
        if int(short_count) >= int(min_burst_count) and float(short_count) >= expected_short * float(burst_multiplier):
            entry = entry_index.get(str(key))
            rows.append(
                _anomaly(
                    label="burst_detected",
                    window_name="short",
                    category=_category_from_key(str(key)),
                    baseline_key=_baseline_from_key(str(key)),
                    display_label=_display_label(entry, str(key)),
                    confidence=score_anomaly_confidence(label="burst_detected", baseline_entry=entry, ratio=float(short_count) / max(1.0, expected_short)),
                    severity="medium",
                    explanation=f"Short-window observations for {_display_label(entry, str(key))} exceeded the local baseline expectation.",
                    generated_at=generated_at,
                    evidence={"short_count": int(short_count), "expected_short_count": round(expected_short, 3), "baseline_count": baseline_count},
                )
            )
    return rows


def detect_rare_service_timing(anomaly_windows: dict[str, Any], *, entries: list[dict[str, Any]], generated_at: str) -> list[dict[str, Any]]:
    short_keys = set(((_windows(anomaly_windows).get("short") or {}).get("key_counts") or {}).keys())
    rows = []
    for entry in entries:
        key = f"{entry.get('category')}:{entry.get('baseline_key')}"
        if key not in short_keys:
            continue
        if str(entry.get("category")) == "service" and int(entry.get("observation_count") or 0) <= 2:
            rows.append(
                _anomaly(
                    label="rare_service_timing",
                    window_name="short",
                    category="service",
                    baseline_key=str(entry.get("baseline_key") or ""),
                    display_label=_display_label(entry, key),
                    confidence=score_anomaly_confidence(label="rare_service_timing", baseline_entry=entry, ratio=1.5),
                    severity="low",
                    explanation=f"Rare service behavior for {_display_label(entry, key)} appeared in the short window.",
                    generated_at=generated_at,
                    evidence={"observation_count": int(entry.get("observation_count") or 0), "behavior_state": str(entry.get("behavior_state") or "unknown")},
                )
            )
    return rows


def detect_volume_drift_hints(
    anomaly_windows: dict[str, Any],
    *,
    generated_at: str,
    volume_drift_multiplier: float = DEFAULT_VOLUME_DRIFT_MULTIPLIER,
) -> list[dict[str, Any]]:
    windows = _windows(anomaly_windows)
    short = windows.get("short") or {}
    medium = windows.get("medium") or {}
    long = windows.get("long") or {}
    short_count = int(short.get("retained_observation_count") or 0)
    baseline_window = medium if int(medium.get("retained_observation_count") or 0) else long
    expected = max(1.0, int(baseline_window.get("retained_observation_count") or 0) * _window_ratio(short, baseline_window))
    if short_count <= 0 or short_count < expected * float(volume_drift_multiplier):
        return []
    return [
        _anomaly(
            label="volume_drift_hint",
            window_name="short",
            category="window",
            baseline_key="all-observations",
            display_label="All observations",
            confidence=score_anomaly_confidence(label="volume_drift_hint", baseline_entry=None, ratio=short_count / expected),
            severity="medium",
            explanation="Short-window observation volume exceeded local historical window expectations.",
            generated_at=generated_at,
            evidence={"short_count": short_count, "expected_short_count": round(expected, 3)},
        )
    ]


def detect_window_novelty(anomaly_windows: dict[str, Any], *, entries: list[dict[str, Any]], generated_at: str) -> list[dict[str, Any]]:
    short_keys = set(((_windows(anomaly_windows).get("short") or {}).get("key_counts") or {}).keys())
    rows = []
    for entry in entries:
        key = f"{entry.get('category')}:{entry.get('baseline_key')}"
        if key in short_keys and bool(entry.get("novelty")):
            rows.append(
                _anomaly(
                    label="new_behavior_in_window",
                    window_name="short",
                    category=str(entry.get("category") or "unknown"),
                    baseline_key=str(entry.get("baseline_key") or ""),
                    display_label=_display_label(entry, key),
                    confidence=score_anomaly_confidence(label="new_behavior_in_window", baseline_entry=entry, ratio=1.0),
                    severity="low",
                    explanation=f"New behavior for {_display_label(entry, key)} appeared in the short anomaly window.",
                    generated_at=generated_at,
                    evidence={"behavior_state": str(entry.get("behavior_state") or "unknown"), "observation_count": int(entry.get("observation_count") or 0)},
                )
            )
    return rows


def score_anomaly_confidence(*, label: str, baseline_entry: dict[str, Any] | None, ratio: float = 1.0) -> float:
    base = {
        "burst_detected": 0.45,
        "rare_service_timing": 0.35,
        "volume_drift_hint": 0.4,
        "new_behavior_in_window": 0.3,
        "malformed_baseline_input": 0.2,
    }.get(label, 0.25)
    baseline_confidence = float((baseline_entry or {}).get("confidence") or 0.4)
    ratio_score = min(0.25, max(0.0, (float(ratio) - 1.0) * 0.08))
    return round(min(1.0, base + baseline_confidence * 0.35 + ratio_score), 3)


def summarize_temporal_anomalies(
    anomalies: list[dict[str, Any]],
    *,
    anomaly_windows: dict[str, Any],
    dropped_anomaly_count: int = 0,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _generated_at(anomaly_windows)
    rows = [dict(row) for row in anomalies or [] if isinstance(row, dict)]
    return {
        "record_type": "temporal_anomaly_summary",
        "record_version": TEMPORAL_ANOMALY_RECORD_VERSION,
        "generated_at": timestamp,
        "anomaly_count": len(rows),
        "dropped_anomaly_count": int(dropped_anomaly_count),
        "burst_count": sum(1 for row in rows if row.get("label") == "burst_detected"),
        "rare_service_timing_count": sum(1 for row in rows if row.get("label") == "rare_service_timing"),
        "volume_drift_count": sum(1 for row in rows if row.get("label") == "volume_drift_hint"),
        "novel_behavior_count": sum(1 for row in rows if row.get("label") == "new_behavior_in_window"),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "by_label": _count_by(rows, "label"),
        "by_window": _count_by(rows, "window_name"),
        "window_summary": dict((anomaly_windows or {}).get("summary") or {}),
        **TEMPORAL_ANOMALY_SAFETY_FLAGS,
    }


def build_temporal_anomaly_dashboard_record(
    *,
    summary: dict[str, Any],
    anomalies: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in anomalies or [] if isinstance(row, dict)]
    status = "review_required" if rows else "ok"
    return {
        "record_type": "temporal_anomaly_dashboard",
        "panel": "temporal_anomalies",
        "status": status,
        "generated_at": generated_at or _generated_at(summary),
        "metrics": {
            "anomaly_count": int(summary.get("anomaly_count") or 0),
            "burst_count": int(summary.get("burst_count") or 0),
            "rare_service_timing_count": int(summary.get("rare_service_timing_count") or 0),
            "volume_drift_count": int(summary.get("volume_drift_count") or 0),
            "novel_behavior_count": int(summary.get("novel_behavior_count") or 0),
            "average_confidence": float(summary.get("average_confidence") or 0.0),
        },
        "rows": [
            {
                "label": row.get("label"),
                "window_name": row.get("window_name"),
                "display_label": row.get("display_label"),
                "confidence": row.get("confidence"),
                "severity": row.get("severity"),
                "explanation": row.get("explanation"),
            }
            for row in rows[:50]
        ],
        "recommended_review": bool(rows),
        **TEMPORAL_ANOMALY_SAFETY_FLAGS,
    }


def build_temporal_anomaly_api_response(
    *,
    summary: dict[str, Any],
    anomaly_windows: dict[str, Any],
    anomalies: list[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "temporal_anomaly_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _generated_at(summary),
        "summary": dict(summary),
        "anomaly_windows": dict(anomaly_windows),
        "anomalies": [dict(row) for row in anomalies],
        "dashboard": dict(dashboard),
        **TEMPORAL_ANOMALY_SAFETY_FLAGS,
    }


def build_temporal_anomaly_export_record(
    *,
    summary: dict[str, Any],
    anomalies: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    payload = {
        "record_type": "temporal_anomaly_export_summary",
        "record_version": TEMPORAL_ANOMALY_RECORD_VERSION,
        "generated_at": generated_at or _generated_at(summary),
        "record_counts": {
            "anomalies": len(anomalies),
            "bursts": int(summary.get("burst_count") or 0),
            "rare_service_timing": int(summary.get("rare_service_timing_count") or 0),
            "volume_drift": int(summary.get("volume_drift_count") or 0),
            "new_behavior": int(summary.get("novel_behavior_count") or 0),
        },
        "anomaly_ids": [str(row.get("anomaly_id") or "") for row in anomalies],
        "digest": "",
        **TEMPORAL_ANOMALY_SAFETY_FLAGS,
    }
    payload["digest"] = "sha256:" + _digest({"record_counts": payload["record_counts"], "anomaly_ids": payload["anomaly_ids"]})
    return payload


def deterministic_temporal_anomaly_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _anomaly(
    *,
    label: str,
    window_name: str,
    category: str,
    baseline_key: str,
    display_label: str,
    confidence: float,
    severity: str,
    explanation: str,
    generated_at: str,
    evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    row = {
        "record_type": "temporal_anomaly_record",
        "record_version": TEMPORAL_ANOMALY_RECORD_VERSION,
        "generated_at": generated_at,
        "label": str(label),
        "window_name": str(window_name),
        "category": str(category),
        "baseline_key": str(baseline_key),
        "display_label": str(display_label),
        "confidence": round(max(0.0, min(1.0, float(confidence))), 3),
        "severity": str(severity),
        "explanation": str(explanation),
        "evidence": dict(evidence or {}),
        "bounded_retention_applied": False,
        "dropped_anomaly_count": 0,
        **TEMPORAL_ANOMALY_SAFETY_FLAGS,
    }
    row["anomaly_id"] = "temporal-anomaly-" + _digest({"label": label, "window_name": window_name, "category": category, "baseline_key": baseline_key, "generated_at": generated_at})[:16]
    return row


def _dedupe_anomalies(anomalies: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for row in anomalies:
        key = f"{row.get('label')}:{row.get('window_name')}:{row.get('category')}:{row.get('baseline_key')}"
        current = by_key.get(key)
        if current is None or float(row.get("confidence") or 0.0) > float(current.get("confidence") or 0.0):
            by_key[key] = row
    return [by_key[key] for key in sorted(by_key)]


def _windows(anomaly_windows: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return anomaly_windows.get("windows") if isinstance((anomaly_windows or {}).get("windows"), dict) else {}


def _entry_index(entries: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        category = str(entry.get("category") or "")
        key = str(entry.get("baseline_key") or "")
        if category and key:
            index[f"{category}:{key}"] = entry
    return index


def _category_from_key(key: str) -> str:
    return key.split(":", 1)[0] if ":" in key else "unknown"


def _baseline_from_key(key: str) -> str:
    return key.split(":", 1)[1] if ":" in key else key


def _display_label(entry: dict[str, Any] | None, fallback: str) -> str:
    return str((entry or {}).get("display_label") or fallback)


def _window_ratio(short: dict[str, Any], baseline: dict[str, Any]) -> float:
    short_duration = max(1, int(short.get("duration_seconds") or 1))
    baseline_duration = max(short_duration, int(baseline.get("duration_seconds") or short_duration))
    return min(1.0, short_duration / baseline_duration)


def _count_by(rows: list[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _generated_at(record: dict[str, Any] | None) -> str:
    if isinstance(record, dict) and record.get("generated_at"):
        return str(record.get("generated_at"))
    return _now()


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
