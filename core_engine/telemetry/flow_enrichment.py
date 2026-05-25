from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.flow_observations import (
    FLOW_OBSERVATION_RECORD_VERSION,
    FLOW_OBSERVATION_SAFETY_FLAGS,
    build_enriched_flow_observation,
    deterministic_flow_observation_json,
)


FLOW_ENRICHMENT_RECORD_VERSION = 1
DEFAULT_MAX_ENRICHED_FLOW_OBSERVATIONS = 1000


class FlowEnrichmentError(ValueError):
    """Raised when flow enrichment input is malformed."""


def enrich_flow_records(
    flows: Iterable[dict[str, Any]],
    *,
    previous_observations: Iterable[dict[str, Any]] | None = None,
    local_cidrs: Iterable[str] | None = None,
    max_observations: int = DEFAULT_MAX_ENRICHED_FLOW_OBSERVATIONS,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build bounded metadata-only enrichment records for reconstructed flows."""
    timestamp = generated_at or _now()
    if int(max_observations) <= 0:
        raise FlowEnrichmentError("max_observations must be positive")
    rows = sorted(
        [dict(row) for row in flows or [] if isinstance(row, dict)],
        key=lambda item: (str(item.get("last_seen") or ""), str(item.get("flow_id") or "")),
    )
    previous_index = _previous_observation_index(previous_observations)
    selected = rows[-int(max_observations) :]
    dropped_count = max(0, len(rows) - len(selected))
    observations = [
        build_enriched_flow_observation(
            flow=row,
            previous_observation=previous_index.get(str(row.get("flow_id") or "")),
            local_cidrs=local_cidrs,
            generated_at=timestamp,
        )
        for row in selected
    ]
    observations = sorted(observations, key=lambda item: str(item.get("flow_ref") or ""))
    summary = summarize_enriched_flow_observations(observations, dropped_count=dropped_count, generated_at=timestamp)
    rolling = build_rolling_flow_statistics(observations, generated_at=timestamp)
    dashboard = build_flow_enrichment_dashboard_record(summary=summary, rolling_statistics=rolling, observations=observations, generated_at=timestamp)
    api = build_flow_enrichment_api_response(summary=summary, rolling_statistics=rolling, observations=observations, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "flow_enrichment_report",
        "record_version": FLOW_ENRICHMENT_RECORD_VERSION,
        "report_id": "flow-enrichment-report-" + _digest({"generated_at": timestamp, "observations": [row.get("observation_id") for row in observations]})[:16],
        "generated_at": timestamp,
        "input_flow_count": len(rows),
        "max_observations": int(max_observations),
        "dropped_observation_count": dropped_count,
        "observations": observations,
        "summary": summary,
        "rolling_statistics": rolling,
        "dashboard_status": dashboard,
        "api_status": api,
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def summarize_enriched_flow_observations(
    observations: Iterable[dict[str, Any]],
    *,
    dropped_count: int = 0,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in observations or [] if isinstance(row, dict)]
    return {
        "record_type": "enriched_flow_summary",
        "record_version": FLOW_OBSERVATION_RECORD_VERSION,
        "generated_at": timestamp,
        "observation_count": len(rows),
        "dropped_observation_count": int(dropped_count),
        "packet_count": sum(int((row.get("counters") or {}).get("packet_count") or 0) for row in rows),
        "byte_count": sum(int((row.get("counters") or {}).get("byte_count") or 0) for row in rows),
        "complete_flow_count": sum(1 for row in rows if row.get("classification") == "complete"),
        "partial_flow_count": sum(1 for row in rows if row.get("classification") == "partial"),
        "malformed_flow_count": sum(1 for row in rows if row.get("classification") == "malformed"),
        "high_quality_count": sum(1 for row in rows if (row.get("telemetry_quality_flags") or {}).get("quality_level") == "high"),
        "medium_quality_count": sum(1 for row in rows if (row.get("telemetry_quality_flags") or {}).get("quality_level") == "medium"),
        "poor_quality_count": sum(1 for row in rows if (row.get("telemetry_quality_flags") or {}).get("quality_level") == "poor"),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "by_direction": _count_nested(rows, "direction", "direction"),
        "by_service": _count_nested(rows, "service_port_hint", "service_name"),
        "by_transport": _count_by(rows, "transport_protocol"),
        "transition_counts": _count_nested(rows, "state_transition", "state"),
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def build_rolling_flow_statistics(
    observations: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = sorted([dict(row) for row in observations or [] if isinstance(row, dict)], key=lambda item: (str(item.get("first_seen") or ""), str(item.get("flow_ref") or "")))
    first_seen = min((str(row.get("first_seen") or "") for row in rows if row.get("first_seen")), default="")
    last_seen = max((str(row.get("last_seen") or "") for row in rows if row.get("last_seen")), default="")
    packet_total = sum(int((row.get("counters") or {}).get("packet_count") or 0) for row in rows)
    byte_total = sum(int((row.get("counters") or {}).get("byte_count") or 0) for row in rows)
    duration = _duration_seconds(first_seen, last_seen)
    return {
        "record_type": "rolling_flow_statistics",
        "record_version": FLOW_ENRICHMENT_RECORD_VERSION,
        "generated_at": timestamp,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "duration_seconds": duration,
        "observation_count": len(rows),
        "packet_count": packet_total,
        "byte_count": byte_total,
        "packets_per_second": round(packet_total / duration, 3) if duration > 0 else 0.0,
        "bytes_per_second": round(byte_total / duration, 3) if duration > 0 else 0.0,
        "average_packets_per_flow": round(packet_total / len(rows), 3) if rows else 0.0,
        "average_bytes_per_flow": round(byte_total / len(rows), 3) if rows else 0.0,
        "direction_counts": _count_nested(rows, "direction", "direction"),
        "quality_counts": _count_nested(rows, "telemetry_quality_flags", "quality_level"),
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def build_flow_enrichment_dashboard_record(
    *,
    summary: dict[str, Any],
    rolling_statistics: dict[str, Any],
    observations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in observations or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("malformed_flow_count") or 0) or int(summary.get("poor_quality_count") or 0) else "ok"
    return {
        "record_type": "flow_enrichment_dashboard",
        "panel": "flow_enrichment",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "observation_count": int(summary.get("observation_count") or 0),
            "packet_count": int(summary.get("packet_count") or 0),
            "byte_count": int(summary.get("byte_count") or 0),
            "average_confidence": float(summary.get("average_confidence") or 0.0),
            "dropped_observation_count": int(summary.get("dropped_observation_count") or 0),
            "packets_per_second": float(rolling_statistics.get("packets_per_second") or 0.0),
            "bytes_per_second": float(rolling_statistics.get("bytes_per_second") or 0.0),
        },
        "by_direction": dict(summary.get("by_direction") or {}),
        "by_service": dict(summary.get("by_service") or {}),
        "rows": [
            {
                "flow_ref": row.get("flow_ref"),
                "direction": (row.get("direction") or {}).get("direction") if isinstance(row.get("direction"), dict) else "unknown",
                "service_name": (row.get("service_port_hint") or {}).get("service_name") if isinstance(row.get("service_port_hint"), dict) else "unknown",
                "packet_count": (row.get("counters") or {}).get("packet_count") if isinstance(row.get("counters"), dict) else 0,
                "byte_count": (row.get("counters") or {}).get("byte_count") if isinstance(row.get("counters"), dict) else 0,
                "confidence": row.get("confidence"),
                "quality_level": (row.get("telemetry_quality_flags") or {}).get("quality_level") if isinstance(row.get("telemetry_quality_flags"), dict) else "unknown",
            }
            for row in sorted(rows, key=lambda item: str(item.get("flow_ref") or ""))
        ],
        "recommended_review": status == "review_required",
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def build_flow_enrichment_api_response(
    *,
    summary: dict[str, Any],
    rolling_statistics: dict[str, Any],
    observations: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in observations or [] if isinstance(row, dict)]
    return {
        "record_type": "flow_enrichment_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "rolling_statistics": dict(rolling_statistics),
        "observations": rows,
        "dashboard": dict(dashboard),
        **FLOW_OBSERVATION_SAFETY_FLAGS,
    }


def deterministic_flow_enrichment_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _previous_observation_index(previous_observations: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for row in previous_observations or []:
        if isinstance(row, dict):
            flow_ref = str(row.get("flow_ref") or "")
            if flow_ref:
                index[flow_ref] = dict(row)
    return index


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _count_nested(rows: Iterable[dict[str, Any]], object_name: str, field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        nested = row.get(object_name) if isinstance(row.get(object_name), dict) else {}
        value = str(nested.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _duration_seconds(first_seen: str, last_seen: str) -> int:
    if not first_seen or not last_seen:
        return 0
    try:
        first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((last - first).total_seconds()))


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
