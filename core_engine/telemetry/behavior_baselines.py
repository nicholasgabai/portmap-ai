from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.baseline_windows import (
    BASELINE_WINDOW_SAFETY_FLAGS,
    DEFAULT_BASELINE_WINDOWS,
    build_baseline_window_records,
)
from core_engine.telemetry.dns_visibility import sanitize_domain_name
from core_engine.telemetry.flow_observations import FLOW_OBSERVATION_SAFETY_FLAGS


BEHAVIOR_BASELINE_RECORD_VERSION = 1
DEFAULT_BASELINE_MATURITY_THRESHOLD = 3
DEFAULT_MAX_BASELINE_ENTRIES = 500

BASELINE_CATEGORIES = (
    "port",
    "protocol",
    "service",
    "process_service_fingerprint",
    "flow_tuple",
    "dns_domain",
)

BEHAVIOR_BASELINE_SAFETY_FLAGS = {
    **FLOW_OBSERVATION_SAFETY_FLAGS,
    **BASELINE_WINDOW_SAFETY_FLAGS,
    "privacy_preserving": True,
    "credentials_stored": False,
    "dns_query_contents_stored": False,
    "packet_capture_stored": False,
    "enforcement_actions_created": False,
    "firewall_changes": False,
    "ml_model_used": False,
    "remote_learning": False,
    "external_services_called": False,
}


class BehaviorBaselineError(ValueError):
    """Raised when behavioral baseline input is malformed."""


def build_behavior_baseline_report(
    *,
    flow_observations: Iterable[dict[str, Any]] | None = None,
    dns_records: Iterable[dict[str, Any]] | None = None,
    service_attributions: Iterable[dict[str, Any]] | None = None,
    previous_baselines: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_entries: int = DEFAULT_MAX_BASELINE_ENTRIES,
    maturity_threshold: int = DEFAULT_BASELINE_MATURITY_THRESHOLD,
    window_config: dict[str, dict[str, int]] | None = None,
) -> dict[str, Any]:
    """Build deterministic metadata-only behavior baselines from telemetry summaries."""
    timestamp = generated_at or _now()
    if int(max_entries) <= 0:
        raise BehaviorBaselineError("max_entries must be positive")
    if int(maturity_threshold) <= 0:
        raise BehaviorBaselineError("maturity_threshold must be positive")
    observations = build_baseline_observations(
        flow_observations=flow_observations,
        dns_records=dns_records,
        service_attributions=service_attributions,
    )
    windows = build_baseline_window_records(observations, generated_at=timestamp, window_config=window_config or DEFAULT_BASELINE_WINDOWS)
    entries = build_baseline_entries(
        observations=observations,
        windows=windows,
        previous_baselines=previous_baselines,
        generated_at=timestamp,
        max_entries=int(max_entries),
        maturity_threshold=int(maturity_threshold),
    )
    summary = summarize_behavior_baselines(
        entries,
        windows=windows,
        input_observation_count=len(observations),
        generated_at=timestamp,
    )
    dashboard = build_behavior_baseline_dashboard_record(summary=summary, entries=entries, generated_at=timestamp)
    api = build_behavior_baseline_api_response(summary=summary, windows=windows, entries=entries, dashboard=dashboard, generated_at=timestamp)
    export = build_behavior_baseline_export_record(summary=summary, entries=entries, generated_at=timestamp)
    return {
        "record_type": "behavior_baseline_report",
        "record_version": BEHAVIOR_BASELINE_RECORD_VERSION,
        "report_id": "behavior-baseline-report-" + _digest({"generated_at": timestamp, "entries": [row.get("baseline_id") for row in entries]})[:16],
        "generated_at": timestamp,
        "max_entries": int(max_entries),
        "maturity_threshold": int(maturity_threshold),
        "input_observation_count": len(observations),
        "window_set": windows,
        "entries": entries,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }


def build_baseline_observations(
    *,
    flow_observations: Iterable[dict[str, Any]] | None = None,
    dns_records: Iterable[dict[str, Any]] | None = None,
    service_attributions: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    observations: list[dict[str, Any]] = []
    for row in _rows(flow_observations):
        observations.extend(_observations_from_flow(row))
    for row in _rows(dns_records):
        observations.extend(_observations_from_dns(row))
    for row in _rows(service_attributions):
        observations.extend(_observations_from_service_attribution(row))
    return sorted(observations, key=lambda item: (str(item.get("observed_at") or ""), str(item.get("category") or ""), str(item.get("key") or "")))


def build_baseline_entries(
    *,
    observations: Iterable[dict[str, Any]],
    windows: dict[str, Any],
    previous_baselines: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_entries: int = DEFAULT_MAX_BASELINE_ENTRIES,
    maturity_threshold: int = DEFAULT_BASELINE_MATURITY_THRESHOLD,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    grouped = _group_observations(observations)
    previous = _previous_index(previous_baselines)
    entries = [
        _build_entry(
            category=category,
            key=key,
            observations=rows,
            windows=windows,
            previous=previous.get((category, key)),
            generated_at=timestamp,
            maturity_threshold=int(maturity_threshold),
        )
        for (category, key), rows in grouped.items()
    ]
    for (category, key), previous_entry in previous.items():
        if (category, key) not in grouped:
            entries.append(_build_inactive_entry(category=category, key=key, previous=previous_entry, generated_at=timestamp))
    entries = sorted(entries, key=lambda item: (str(item.get("category") or ""), str(item.get("baseline_key") or "")))
    dropped_count = max(0, len(entries) - int(max_entries))
    selected = entries[-int(max_entries) :]
    if dropped_count:
        for row in selected:
            row["bounded_retention_applied"] = True
            row["dropped_entry_count"] = dropped_count
    return selected


def classify_baseline_behavior(
    *,
    observation_count: int,
    first_seen: str,
    last_seen: str,
    previous_entry: dict[str, Any] | None = None,
    window_presence: dict[str, bool] | None = None,
    maturity_threshold: int = DEFAULT_BASELINE_MATURITY_THRESHOLD,
) -> dict[str, Any]:
    presence = dict(window_presence or {})
    mature = int(observation_count) >= int(maturity_threshold)
    recurring = bool(presence.get("medium") or presence.get("long")) and int(observation_count) >= 2
    previously_seen = bool(previous_entry)
    if int(observation_count) <= 0 and previously_seen:
        state = "decaying_inactive"
    elif not previously_seen and int(observation_count) < int(maturity_threshold):
        state = "new"
    elif mature and recurring:
        state = "stable"
    elif recurring:
        state = "recurring"
    else:
        state = "insufficient_history"
    return {
        "record_type": "baseline_behavior_classification",
        "behavior_state": state,
        "stable_behavior": state == "stable",
        "novelty": state == "new",
        "recurring_behavior": state in {"recurring", "stable"},
        "decaying_inactive": state == "decaying_inactive",
        "maturity_threshold": int(maturity_threshold),
        "first_seen": first_seen,
        "last_seen": last_seen,
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }


def score_baseline_confidence(
    *,
    observation_count: int,
    rolling_average_score: float,
    window_presence: dict[str, bool],
    category: str,
    maturity_threshold: int = DEFAULT_BASELINE_MATURITY_THRESHOLD,
) -> float:
    frequency_score = min(0.35, (int(observation_count) / max(1, int(maturity_threshold))) * 0.35)
    consistency_score = min(0.25, sum(1 for value in window_presence.values() if value) * 0.085)
    recurrence_score = 0.2 if window_presence.get("medium") or window_presence.get("long") else 0.05
    service_score = 0.15 if category in {"service", "process_service_fingerprint"} else 0.08
    average_score = max(0.0, min(0.2, float(rolling_average_score) * 0.2))
    return round(min(1.0, 0.05 + frequency_score + consistency_score + recurrence_score + service_score + average_score), 3)


def summarize_behavior_baselines(
    entries: Iterable[dict[str, Any]],
    *,
    windows: dict[str, Any] | None = None,
    input_observation_count: int = 0,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = _rows(entries)
    return {
        "record_type": "behavior_baseline_summary",
        "record_version": BEHAVIOR_BASELINE_RECORD_VERSION,
        "generated_at": timestamp,
        "input_observation_count": int(input_observation_count),
        "baseline_entry_count": len(rows),
        "stable_behavior_count": sum(1 for row in rows if row.get("stable_behavior")),
        "novel_behavior_count": sum(1 for row in rows if row.get("novelty")),
        "recurring_behavior_count": sum(1 for row in rows if row.get("behavior_state") == "recurring"),
        "decaying_inactive_count": sum(1 for row in rows if row.get("behavior_state") == "decaying_inactive"),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "by_category": _count_by(rows, "category"),
        "by_behavior_state": _count_by(rows, "behavior_state"),
        "window_summary": dict((windows or {}).get("summary") or {}),
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }


def build_behavior_baseline_dashboard_record(
    *,
    summary: dict[str, Any],
    entries: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(entries)
    status = "review_required" if int(summary.get("novel_behavior_count") or 0) or int(summary.get("decaying_inactive_count") or 0) else "ok"
    return {
        "record_type": "behavior_baseline_dashboard",
        "panel": "behavior_baselines",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "baseline_entry_count": int(summary.get("baseline_entry_count") or 0),
            "stable_behavior_count": int(summary.get("stable_behavior_count") or 0),
            "novel_behavior_count": int(summary.get("novel_behavior_count") or 0),
            "decaying_inactive_count": int(summary.get("decaying_inactive_count") or 0),
            "average_confidence": float(summary.get("average_confidence") or 0.0),
        },
        "by_category": dict(summary.get("by_category") or {}),
        "by_behavior_state": dict(summary.get("by_behavior_state") or {}),
        "rows": [
            {
                "category": row.get("category"),
                "display_label": row.get("display_label"),
                "behavior_state": row.get("behavior_state"),
                "observation_count": row.get("observation_count"),
                "rolling_frequency": row.get("rolling_frequency"),
                "confidence": row.get("confidence"),
                "stable_behavior": row.get("stable_behavior"),
                "novelty": row.get("novelty"),
            }
            for row in sorted(rows, key=lambda item: (str(item.get("category") or ""), str(item.get("display_label") or "")))[:50]
        ],
        "recommended_review": status == "review_required",
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }


def build_behavior_baseline_api_response(
    *,
    summary: dict[str, Any],
    windows: dict[str, Any],
    entries: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(entries)
    return {
        "record_type": "behavior_baseline_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "window_set": dict(windows),
        "entries": rows,
        "dashboard": dict(dashboard),
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }


def build_behavior_baseline_export_record(
    *,
    summary: dict[str, Any],
    entries: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(entries)
    payload = {
        "record_type": "behavior_baseline_export_summary",
        "record_version": BEHAVIOR_BASELINE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "baseline_entries": len(rows),
            "stable_behavior": int(summary.get("stable_behavior_count") or 0),
            "novel_behavior": int(summary.get("novel_behavior_count") or 0),
            "decaying_inactive": int(summary.get("decaying_inactive_count") or 0),
        },
        "baseline_ids": [str(row.get("baseline_id") or "") for row in rows],
        "digest": "",
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }
    payload["digest"] = "sha256:" + _digest({"record_counts": payload["record_counts"], "baseline_ids": payload["baseline_ids"]})
    return payload


def deterministic_behavior_baseline_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _build_entry(
    *,
    category: str,
    key: str,
    observations: list[dict[str, Any]],
    windows: dict[str, Any],
    previous: dict[str, Any] | None,
    generated_at: str,
    maturity_threshold: int,
) -> dict[str, Any]:
    rows = sorted(observations, key=lambda item: str(item.get("observed_at") or ""))
    first_seen = min((str(row.get("observed_at") or "") for row in rows), default="")
    last_seen = max((str(row.get("observed_at") or "") for row in rows), default="")
    window_presence = _window_presence(category, key, windows)
    observation_count = len(rows)
    rolling_frequency = _rolling_frequency(observation_count, windows)
    average_score = round(sum(float(row.get("score") or 0.0) for row in rows) / observation_count, 3) if rows else 0.0
    classification = classify_baseline_behavior(
        observation_count=observation_count,
        first_seen=first_seen,
        last_seen=last_seen,
        previous_entry=previous,
        window_presence=window_presence,
        maturity_threshold=maturity_threshold,
    )
    confidence = score_baseline_confidence(
        observation_count=observation_count,
        rolling_average_score=average_score,
        window_presence=window_presence,
        category=category,
        maturity_threshold=maturity_threshold,
    )
    display_label = _display_label(rows, category, key)
    entry = {
        "record_type": "behavior_baseline_entry",
        "record_version": BEHAVIOR_BASELINE_RECORD_VERSION,
        "generated_at": generated_at,
        "category": category,
        "baseline_key": key,
        "display_label": display_label,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observation_count": observation_count,
        "rolling_frequency": rolling_frequency,
        "rolling_average_score": average_score,
        "confidence": confidence,
        "window_presence": window_presence,
        "source_refs": sorted({str(ref) for row in rows for ref in row.get("source_refs", []) if ref}),
        "bounded_retention_applied": False,
        "dropped_entry_count": 0,
        **classification,
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }
    entry["baseline_id"] = "behavior-baseline-" + _digest({"category": category, "key": key})[:16]
    return entry


def _build_inactive_entry(*, category: str, key: str, previous: dict[str, Any], generated_at: str) -> dict[str, Any]:
    count = int(previous.get("observation_count") or 0)
    entry = {
        "record_type": "behavior_baseline_entry",
        "record_version": BEHAVIOR_BASELINE_RECORD_VERSION,
        "generated_at": generated_at,
        "category": category,
        "baseline_key": key,
        "display_label": str(previous.get("display_label") or key),
        "first_seen": str(previous.get("first_seen") or ""),
        "last_seen": str(previous.get("last_seen") or ""),
        "observation_count": count,
        "rolling_frequency": round(float(previous.get("rolling_frequency") or 0.0) * 0.5, 6),
        "rolling_average_score": float(previous.get("rolling_average_score") or 0.0),
        "stable_behavior": False,
        "novelty": False,
        "recurring_behavior": False,
        "decaying_inactive": True,
        "behavior_state": "decaying_inactive",
        "confidence": round(max(0.1, float(previous.get("confidence") or 0.2) * 0.5), 3),
        "window_presence": {"short": False, "medium": False, "long": False},
        "source_refs": sorted(str(ref) for ref in previous.get("source_refs") or []),
        "bounded_retention_applied": False,
        "dropped_entry_count": 0,
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }
    entry["baseline_id"] = str(previous.get("baseline_id") or "behavior-baseline-" + _digest({"category": category, "key": key})[:16])
    return entry


def _observations_from_flow(row: dict[str, Any]) -> list[dict[str, Any]]:
    observed_at = str(row.get("last_seen") or row.get("first_seen") or row.get("generated_at") or "")
    source_refs = sorted(str(ref) for ref in row.get("source_refs") or [] if ref)
    protocol = str(row.get("transport_protocol") or "unknown").lower()
    service_hint = row.get("service_port_hint") if isinstance(row.get("service_port_hint"), dict) else {}
    service_name = str(service_hint.get("service_name") or "unknown")
    service_port = service_hint.get("service_port")
    confidence = float(row.get("confidence") or service_hint.get("confidence") or 0.0)
    flow_tuple = _flow_tuple_digest(row)
    observations = [
        _observation("protocol", protocol, protocol, observed_at, confidence, source_refs),
        _observation("flow_tuple", flow_tuple, f"{protocol}:flow:{flow_tuple[:12]}", observed_at, confidence, source_refs),
    ]
    if service_port is not None:
        observations.append(_observation("port", str(service_port), f"port:{service_port}", observed_at, confidence, source_refs))
    if service_name and service_name != "unknown":
        observations.append(_observation("service", service_name, service_name, observed_at, confidence, source_refs))
    return observations


def _observations_from_dns(row: dict[str, Any]) -> list[dict[str, Any]]:
    observed_at = str(row.get("observed_at") or row.get("response_time") or row.get("query_time") or row.get("generated_at") or "")
    domain = str(row.get("safe_domain") or row.get("domain") or row.get("query_name") or row.get("name") or "")
    safe_domain, _governance = sanitize_domain_name(domain) if domain else ("", {})
    if not safe_domain:
        return []
    return [_observation("dns_domain", safe_domain, safe_domain, observed_at, float(row.get("confidence") or 0.6), sorted(str(ref) for ref in row.get("source_refs") or [] if ref))]


def _observations_from_service_attribution(row: dict[str, Any]) -> list[dict[str, Any]]:
    observed_at = str(row.get("last_seen") or row.get("observed_at") or row.get("generated_at") or "")
    service_name = str(row.get("service_name") or row.get("detected_service") or "unknown")
    protocol = str(row.get("transport_protocol") or row.get("protocol") or "unknown").lower()
    port = row.get("service_port") or row.get("port")
    process = str((row.get("process") or {}).get("process_name") if isinstance(row.get("process"), dict) else row.get("process_name") or "unknown")
    fingerprint_key = _digest({"service": service_name, "protocol": protocol, "port": port, "process": process})[:24]
    display = f"{service_name}/{protocol}/{port or 'unknown'}"
    source_refs = sorted(str(ref) for ref in row.get("source_refs") or [] if ref)
    observations = [_observation("process_service_fingerprint", fingerprint_key, display, observed_at, float(row.get("confidence") or 0.5), source_refs)]
    if port is not None:
        observations.append(_observation("port", str(port), f"port:{port}", observed_at, float(row.get("confidence") or 0.5), source_refs))
    if service_name and service_name != "unknown":
        observations.append(_observation("service", service_name, service_name, observed_at, float(row.get("confidence") or 0.5), source_refs))
    return observations


def _observation(category: str, key: str, display_label: str, observed_at: str, score: float, source_refs: list[str]) -> dict[str, Any]:
    payload = {
        "record_type": "baseline_observation",
        "category": str(category),
        "key": str(key),
        "display_label": str(display_label),
        "observed_at": str(observed_at),
        "score": round(max(0.0, min(1.0, float(score or 0.0))), 3),
        "source_refs": source_refs,
        **BEHAVIOR_BASELINE_SAFETY_FLAGS,
    }
    payload["observation_ref"] = "baseline-observation-" + _digest({k: payload[k] for k in ("category", "key", "observed_at")})[:16]
    return payload


def _flow_tuple_digest(row: dict[str, Any]) -> str:
    initiator = row.get("initiator") if isinstance(row.get("initiator"), dict) else {}
    responder = row.get("responder") if isinstance(row.get("responder"), dict) else {}
    payload = {
        "initiator_port": initiator.get("port"),
        "responder_port": responder.get("port"),
        "transport": row.get("transport_protocol"),
        "direction": (row.get("direction") or {}).get("direction") if isinstance(row.get("direction"), dict) else row.get("direction"),
        "service": (row.get("service_port_hint") or {}).get("service_name") if isinstance(row.get("service_port_hint"), dict) else "",
    }
    return _digest(payload)[:32]


def _group_observations(observations: Iterable[dict[str, Any]]) -> dict[tuple[str, str], list[dict[str, Any]]]:
    grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for row in _rows(observations):
        category = str(row.get("category") or "unknown")
        key = str(row.get("key") or "unknown")
        grouped.setdefault((category, key), []).append(row)
    return grouped


def _previous_index(previous_baselines: Iterable[dict[str, Any]] | None) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for row in _rows(previous_baselines):
        category = str(row.get("category") or "")
        key = str(row.get("baseline_key") or "")
        if category and key:
            index[(category, key)] = row
    return index


def _window_presence(category: str, key: str, windows: dict[str, Any]) -> dict[str, bool]:
    key_name = f"{category}:{key}"
    window_records = (windows or {}).get("windows") if isinstance((windows or {}).get("windows"), dict) else {}
    return {
        name: key_name in ((record or {}).get("key_counts") or {})
        for name, record in sorted(window_records.items())
    } or {"short": False, "medium": False, "long": False}


def _rolling_frequency(observation_count: int, windows: dict[str, Any]) -> float:
    long_window = (((windows or {}).get("windows") or {}).get("long") or {}) if isinstance((windows or {}).get("windows"), dict) else {}
    duration = int(long_window.get("duration_seconds") or 1)
    return round(float(observation_count) / max(1, duration), 6)


def _display_label(rows: list[dict[str, Any]], category: str, key: str) -> str:
    for row in rows:
        label = str(row.get("display_label") or "")
        if label:
            return label
    return f"{category}:{key}"


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
