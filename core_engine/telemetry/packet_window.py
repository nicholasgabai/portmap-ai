from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.ingestion import (
    PACKET_METADATA_RECORD_VERSION,
    normalize_packet_metadata,
    summarize_packet_metadata_records,
)
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


PACKET_WINDOW_RECORD_VERSION = 1
DEFAULT_MAX_WINDOW_PACKETS = 1024
DEFAULT_MAX_WINDOW_BYTES = 1024 * 1024
EDGE_MAX_WINDOW_PACKETS = 256
EDGE_MAX_WINDOW_BYTES = 256 * 1024


class PacketWindowError(ValueError):
    """Raised when a bounded packet ingestion window is invalid."""


def build_packet_ingestion_window(
    *,
    packets: Iterable[dict[str, Any]],
    capture_plan: dict[str, Any] | None = None,
    previous_packet_digests: Iterable[str] | None = None,
    replay_window_started_at: str | None = None,
    max_packets: int | None = None,
    max_window_bytes: int | None = None,
    duration_seconds: int = 1,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a bounded metadata-only ingestion window from provided packet records."""
    timestamp = generated_at or _now()
    packet_rows = list(packets or [])
    packet_limit = int(max_packets if max_packets is not None else (EDGE_MAX_WINDOW_PACKETS if edge_device else DEFAULT_MAX_WINDOW_PACKETS))
    byte_limit = int(max_window_bytes if max_window_bytes is not None else (EDGE_MAX_WINDOW_BYTES if edge_device else DEFAULT_MAX_WINDOW_BYTES))
    if packet_limit < 0:
        raise PacketWindowError("max_packets cannot be negative")
    if byte_limit < 0:
        raise PacketWindowError("max_window_bytes cannot be negative")
    if int(duration_seconds) < 0:
        raise PacketWindowError("duration_seconds cannot be negative")
    default_interface = _default_interface(capture_plan)
    seen = set(str(item) for item in previous_packet_digests or [] if str(item).strip())
    records = []
    total_bytes = 0
    truncated_count = 0
    for index, packet in enumerate(packet_rows):
        if len(records) >= packet_limit:
            truncated_count += 1
            continue
        metadata = normalize_packet_metadata(packet, default_interface=default_interface, generated_at=timestamp)
        digest = str(metadata.get("packet_digest") or "")
        size = int(metadata.get("size_bytes") or 0)
        if total_bytes + size > byte_limit:
            truncated_count += 1
            continue
        classification = classify_window_packet(metadata, seen_digests=seen, replay_window_started_at=replay_window_started_at)
        metadata["window_sequence"] = index + 1
        metadata["window_classification"] = classification
        metadata["replay_checked"] = True
        if digest:
            seen.add(digest)
        total_bytes += size
        records.append(metadata)
    summary = summarize_packet_ingestion_window(
        records=records,
        packet_limit=packet_limit,
        byte_limit=byte_limit,
        duration_seconds=duration_seconds,
        truncated_count=truncated_count,
        total_input_count=len(packet_rows),
        generated_at=timestamp,
    )
    dashboard = build_packet_ingestion_dashboard_record(summary=summary, records=records, generated_at=timestamp)
    api = build_packet_ingestion_api_response(summary=summary, records=records, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "packet_ingestion_window",
        "record_version": PACKET_WINDOW_RECORD_VERSION,
        "window_id": _stable_id("packet-window", timestamp, summary, [row.get("packet_digest") for row in records]),
        "generated_at": timestamp,
        "capture_plan_ref": str((capture_plan or {}).get("session_plan_id") or ""),
        "dry_run": True,
        "metadata_only": True,
        "packet_records": records,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "seen_packet_digests": sorted(seen),
        **TELEMETRY_SAFETY_FLAGS,
    }


def classify_window_packet(
    packet: dict[str, Any],
    *,
    seen_digests: set[str] | None = None,
    replay_window_started_at: str | None = None,
) -> str:
    digest = str(packet.get("packet_digest") or "")
    if digest and digest in (seen_digests or set()):
        return "duplicate"
    if replay_window_started_at and str(packet.get("timestamp") or "") < replay_window_started_at:
        return "stale"
    classification = str(packet.get("classification") or "unknown")
    if classification == "accepted":
        return "accepted"
    if classification == "unsupported":
        return "unsupported"
    if classification == "malformed":
        return "malformed"
    return "rejected"


def summarize_packet_ingestion_window(
    *,
    records: Iterable[dict[str, Any]],
    packet_limit: int,
    byte_limit: int,
    duration_seconds: int,
    truncated_count: int = 0,
    total_input_count: int | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    metadata_summary = summarize_packet_metadata_records(rows, generated_at=timestamp)
    accepted_count = sum(1 for row in rows if row.get("window_classification") == "accepted")
    duplicate_count = sum(1 for row in rows if row.get("window_classification") == "duplicate")
    stale_count = sum(1 for row in rows if row.get("window_classification") == "stale")
    malformed_count = sum(1 for row in rows if row.get("window_classification") == "malformed")
    unsupported_count = sum(1 for row in rows if row.get("window_classification") == "unsupported")
    rejected_count = sum(1 for row in rows if row.get("window_classification") == "rejected")
    observed_count = len(rows)
    seconds = int(duration_seconds)
    return {
        "record_type": "packet_ingestion_window_summary",
        "record_version": PACKET_WINDOW_RECORD_VERSION,
        "generated_at": timestamp,
        "dry_run": True,
        "metadata_only": True,
        "total_input_count": int(total_input_count if total_input_count is not None else observed_count),
        "metadata_record_count": observed_count,
        "accepted_count": accepted_count,
        "duplicate_count": duplicate_count,
        "stale_count": stale_count,
        "malformed_count": malformed_count,
        "unsupported_count": unsupported_count,
        "rejected_count": rejected_count,
        "truncated_count": int(truncated_count),
        "packet_limit": int(packet_limit),
        "byte_limit": int(byte_limit),
        "duration_seconds": seconds,
        "packet_rate_summary": {
            "record_type": "packet_rate_summary",
            "duration_seconds": seconds,
            "observed_packet_count": observed_count,
            "accepted_packet_count": accepted_count,
            "packets_per_second": round(observed_count / seconds, 2) if seconds > 0 else 0.0,
            "accepted_packets_per_second": round(accepted_count / seconds, 2) if seconds > 0 else 0.0,
            **TELEMETRY_SAFETY_FLAGS,
        },
        "packet_metadata_summary": metadata_summary,
        "transport_summary": dict(metadata_summary.get("by_transport") or {}),
        "address_family_summary": dict(metadata_summary.get("by_address_family") or {}),
        "interface_summary": dict(metadata_summary.get("by_interface") or {}),
        "packet_size_summary": dict(metadata_summary.get("packet_size_summary") or {}),
        "replay_safe_counters": {
            "accepted_count": accepted_count,
            "duplicate_count": duplicate_count,
            "stale_count": stale_count,
            "rejected_count": rejected_count + malformed_count + unsupported_count,
            "truncated_count": int(truncated_count),
            **TELEMETRY_SAFETY_FLAGS,
        },
        "raw_payload_stored": False,
        "payload_bytes_stored": 0,
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_packet_ingestion_dashboard_record(
    *,
    summary: dict[str, Any],
    records: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "packet_ingestion_dashboard",
        "panel": "packet_ingestion",
        "status": "ok" if int(summary.get("rejected_count") or 0) == 0 and int(summary.get("malformed_count") or 0) == 0 else "review_required",
        "generated_at": timestamp,
        "metrics": {
            "metadata_record_count": int(summary.get("metadata_record_count") or 0),
            "accepted_count": int(summary.get("accepted_count") or 0),
            "duplicate_count": int(summary.get("duplicate_count") or 0),
            "stale_count": int(summary.get("stale_count") or 0),
            "malformed_count": int(summary.get("malformed_count") or 0),
            "unsupported_count": int(summary.get("unsupported_count") or 0),
            "truncated_count": int(summary.get("truncated_count") or 0),
            "packets_per_second": (summary.get("packet_rate_summary") or {}).get("packets_per_second", 0.0),
        },
        "rows": [
            {
                "packet_id": row.get("packet_id"),
                "interface_name": row.get("interface_name"),
                "address_family": row.get("address_family"),
                "transport_protocol": row.get("transport_protocol"),
                "window_classification": row.get("window_classification"),
                "size_bytes": row.get("size_bytes"),
            }
            for row in sorted([dict(record) for record in records or [] if isinstance(record, dict)], key=lambda item: int(item.get("window_sequence") or 0))
        ],
        "recommended_review": bool(int(summary.get("malformed_count") or 0) or int(summary.get("unsupported_count") or 0)),
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_packet_ingestion_api_response(
    *,
    summary: dict[str, Any],
    records: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    return {
        "record_type": "packet_ingestion_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "packets": rows,
        "dashboard": dict(dashboard),
        **TELEMETRY_SAFETY_FLAGS,
    }


def deterministic_packet_window_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _default_interface(capture_plan: dict[str, Any] | None) -> str:
    selected = list((capture_plan or {}).get("selected_interfaces") or [])
    if selected:
        return str(selected[0])
    targets = list((capture_plan or {}).get("capture_targets") or [])
    if targets:
        return str((targets[0] or {}).get("interface_name") or "")
    return ""


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
