from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.events import create_event, event_to_dict


GATEWAY_LOG_RECORD_VERSION = 1

GATEWAY_LOG_SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "administrator_controlled": True,
    "advisory_only": True,
    "dry_run": True,
    "metadata_only": True,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "external_listener_started": False,
    "router_settings_modified": False,
    "automatic_blocking": False,
    "external_transmission_enabled": False,
}


def normalize_gateway_log_record(
    parsed: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    row = dict(parsed or {})
    event_action = normalize_gateway_action(row.get("action"))
    source = normalize_gateway_endpoint(ip=row.get("source_ip"), port=row.get("source_port"), role="source")
    destination = normalize_gateway_endpoint(ip=row.get("destination_ip"), port=row.get("destination_port"), role="destination")
    event = {
        "record_type": "gateway_log_record",
        "record_version": GATEWAY_LOG_RECORD_VERSION,
        "generated_at": timestamp,
        "timestamp": normalize_gateway_timestamp(row.get("timestamp"), fallback=timestamp),
        "source_device_ref": str(row.get("source_device_ref") or row.get("device") or "gateway-placeholder"),
        "action": event_action,
        "event_category": classify_gateway_event_category(row),
        "severity": gateway_event_severity(action=event_action, event_type=row.get("event_type"), malformed=False),
        "event_type": str(row.get("event_type") or "traffic").lower(),
        "protocol": str(row.get("protocol") or "unknown").lower(),
        "source": source,
        "destination": destination,
        "translated_source": normalize_gateway_endpoint(ip=row.get("translated_source_ip"), port=row.get("translated_source_port"), role="translated_source"),
        "translated_destination": normalize_gateway_endpoint(ip=row.get("translated_destination_ip"), port=row.get("translated_destination_port"), role="translated_destination"),
        "nat_event": bool(row.get("nat_event") or row.get("translated_source_ip") or row.get("translated_destination_ip")),
        "source_refs": sorted(str(item) for item in row.get("source_refs") or []),
        "parse_warnings": sorted(str(item) for item in row.get("parse_warnings") or []),
        "malformed": False,
        **GATEWAY_LOG_SAFETY_FLAGS,
    }
    event["gateway_event_id"] = "gateway-event-" + _digest(
        {
            "timestamp": event["timestamp"],
            "action": event["action"],
            "source": event["source"],
            "destination": event["destination"],
            "protocol": event["protocol"],
        }
    )[:16]
    event["runtime_event"] = gateway_log_to_runtime_event(event)
    event["topology_edge"] = gateway_log_to_topology_edge(event)
    return event


def malformed_gateway_log_record(
    *,
    line_ref: str,
    reason: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    record = {
        "record_type": "gateway_log_record",
        "record_version": GATEWAY_LOG_RECORD_VERSION,
        "generated_at": timestamp,
        "timestamp": timestamp,
        "source_device_ref": "gateway-placeholder",
        "action": "unknown",
        "event_category": "malformed",
        "severity": "low",
        "event_type": "malformed",
        "protocol": "unknown",
        "source": normalize_gateway_endpoint(ip="", port=None, role="source"),
        "destination": normalize_gateway_endpoint(ip="", port=None, role="destination"),
        "translated_source": normalize_gateway_endpoint(ip="", port=None, role="translated_source"),
        "translated_destination": normalize_gateway_endpoint(ip="", port=None, role="translated_destination"),
        "nat_event": False,
        "source_refs": [str(line_ref)],
        "parse_warnings": [str(reason)],
        "malformed": True,
        **GATEWAY_LOG_SAFETY_FLAGS,
    }
    record["gateway_event_id"] = "gateway-event-" + _digest({"line_ref": line_ref, "reason": reason, "generated_at": timestamp})[:16]
    record["runtime_event"] = gateway_log_to_runtime_event(record)
    record["topology_edge"] = None
    return record


def summarize_gateway_logs(records: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    return {
        "record_type": "gateway_log_summary",
        "record_version": GATEWAY_LOG_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_count": len(rows),
        "allow_count": sum(1 for row in rows if row.get("action") == "allow"),
        "deny_count": sum(1 for row in rows if row.get("action") == "deny"),
        "nat_event_count": sum(1 for row in rows if row.get("nat_event")),
        "malformed_count": sum(1 for row in rows if row.get("malformed")),
        "runtime_event_count": sum(1 for row in rows if isinstance(row.get("runtime_event"), dict)),
        "topology_edge_count": sum(1 for row in rows if isinstance(row.get("topology_edge"), dict)),
        "by_action": _count_by(rows, "action"),
        "by_protocol": _count_by(rows, "protocol"),
        "by_severity": _count_by(rows, "severity"),
        "by_category": _count_by(rows, "event_category"),
        **GATEWAY_LOG_SAFETY_FLAGS,
    }


def build_gateway_log_ingestion_report(
    records: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = sorted([dict(row) for row in records or [] if isinstance(row, dict)], key=lambda item: (str(item.get("timestamp") or ""), str(item.get("gateway_event_id") or "")))
    summary = summarize_gateway_logs(rows, generated_at=timestamp)
    export = build_gateway_log_export_summary(records=rows, summary=summary, generated_at=timestamp)
    dashboard = build_gateway_log_dashboard_record(records=rows, summary=summary, generated_at=timestamp)
    api = build_gateway_log_api_response(records=rows, summary=summary, export_summary=export, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "gateway_log_ingestion_report",
        "record_version": GATEWAY_LOG_RECORD_VERSION,
        "report_id": "gateway-log-report-" + _digest({"generated_at": timestamp, "records": [row.get("gateway_event_id") for row in rows]})[:16],
        "generated_at": timestamp,
        "records": rows,
        "summary": summary,
        "runtime_events": [dict(row["runtime_event"]) for row in rows if isinstance(row.get("runtime_event"), dict)],
        "topology_edges": [dict(row["topology_edge"]) for row in rows if isinstance(row.get("topology_edge"), dict)],
        "export_summary": export,
        "dashboard_status": dashboard,
        "api_status": api,
        **GATEWAY_LOG_SAFETY_FLAGS,
    }


def build_gateway_log_export_summary(
    *,
    records: Iterable[dict[str, Any]],
    summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    return {
        "record_type": "gateway_log_export_summary",
        "record_version": GATEWAY_LOG_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "export_ready": True,
        "record_count": len(rows),
        "digest": "sha256:" + sha256(deterministic_gateway_log_json({"summary": summary, "record_ids": [row.get("gateway_event_id") for row in rows]}).encode("utf-8")).hexdigest(),
        "record_counts": {
            "gateway_logs": len(rows),
            "runtime_events": sum(1 for row in rows if isinstance(row.get("runtime_event"), dict)),
            "topology_edges": sum(1 for row in rows if isinstance(row.get("topology_edge"), dict)),
        },
        **GATEWAY_LOG_SAFETY_FLAGS,
    }


def build_gateway_log_dashboard_record(
    *,
    records: Iterable[dict[str, Any]],
    summary: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in records or [] if isinstance(row, dict)]
    status = "review_required" if int(summary.get("deny_count") or 0) or int(summary.get("malformed_count") or 0) else "ok"
    return {
        "record_type": "gateway_log_dashboard",
        "panel": "gateway_logs",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "record_count": int(summary.get("record_count") or 0),
            "allow_count": int(summary.get("allow_count") or 0),
            "deny_count": int(summary.get("deny_count") or 0),
            "nat_event_count": int(summary.get("nat_event_count") or 0),
            "malformed_count": int(summary.get("malformed_count") or 0),
        },
        "rows": [
            {
                "gateway_event_id": row.get("gateway_event_id"),
                "timestamp": row.get("timestamp"),
                "action": row.get("action"),
                "event_category": row.get("event_category"),
                "severity": row.get("severity"),
                "protocol": row.get("protocol"),
                "source_ref": (row.get("source") or {}).get("endpoint_ref") if isinstance(row.get("source"), dict) else "",
                "destination_ref": (row.get("destination") or {}).get("endpoint_ref") if isinstance(row.get("destination"), dict) else "",
            }
            for row in rows
        ],
        "recommended_review": status == "review_required",
        **GATEWAY_LOG_SAFETY_FLAGS,
    }


def build_gateway_log_api_response(
    *,
    records: Iterable[dict[str, Any]],
    summary: dict[str, Any],
    export_summary: dict[str, Any],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "gateway_log_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "records": [dict(row) for row in records or [] if isinstance(row, dict)],
        "export_summary": dict(export_summary),
        "dashboard": dict(dashboard),
        **GATEWAY_LOG_SAFETY_FLAGS,
    }


def gateway_log_to_runtime_event(record: dict[str, Any]) -> dict[str, Any]:
    severity = str(record.get("severity") or "info")
    if severity not in {"info", "low", "medium", "high", "critical"}:
        severity = "info"
    event = create_event(
        "system_notice",
        severity=severity,
        source="gateway_router_log",
        message=f"Gateway log {record.get('action')} {record.get('event_category')}",
        metadata={
            "gateway_event_id": record.get("gateway_event_id"),
            "action": record.get("action"),
            "event_category": record.get("event_category"),
            "nat_event": record.get("nat_event"),
            "malformed": record.get("malformed"),
        },
    )
    return event_to_dict(event)


def gateway_log_to_topology_edge(record: dict[str, Any]) -> dict[str, Any] | None:
    if record.get("malformed"):
        return None
    source = record.get("source") if isinstance(record.get("source"), dict) else {}
    destination = record.get("destination") if isinstance(record.get("destination"), dict) else {}
    if not source.get("ip") or not destination.get("ip"):
        return None
    return {
        "record_type": "topology_edge",
        "record_version": GATEWAY_LOG_RECORD_VERSION,
        "edge_id": "gateway-edge-" + _digest({"src": source.get("ip"), "dst": destination.get("ip"), "protocol": record.get("protocol")})[:16],
        "source_asset": source.get("ip"),
        "target_asset": destination.get("ip"),
        "src": source.get("ip"),
        "dst": destination.get("ip"),
        "relationship_type": "gateway_observed",
        "protocol": str(record.get("protocol") or "unknown"),
        "observation_count": 1,
        "gateway_event_ref": str(record.get("gateway_event_id") or ""),
        "source_ref": str(record.get("gateway_event_id") or ""),
        "confidence": 0.8 if record.get("action") in {"allow", "deny"} else 0.5,
        **GATEWAY_LOG_SAFETY_FLAGS,
    }


def normalize_gateway_endpoint(*, ip: Any, port: Any, role: str) -> dict[str, Any]:
    ip_text = str(ip or "")
    port_value = _safe_port(port)
    return {
        "record_type": "gateway_endpoint",
        "role": role,
        "ip": ip_text,
        "port": port_value,
        "endpoint_ref": "endpoint-" + _digest({"ip": ip_text, "port": port_value, "role": role})[:12] if ip_text or port_value is not None else "",
        **GATEWAY_LOG_SAFETY_FLAGS,
    }


def normalize_gateway_timestamp(value: Any, *, fallback: str) -> str:
    text = str(value or "").strip()
    if not text:
        return fallback
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        return fallback


def normalize_gateway_action(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in {"allow", "accept", "accepted", "pass", "permit"}:
        return "allow"
    if text in {"deny", "denied", "drop", "reject", "block", "blocked"}:
        return "deny"
    if text in {"nat", "snat", "dnat"}:
        return "nat"
    return "unknown"


def classify_gateway_event_category(record: dict[str, Any]) -> str:
    if record.get("nat_event") or record.get("translated_source_ip") or record.get("translated_destination_ip"):
        return "nat"
    action = normalize_gateway_action(record.get("action"))
    if action in {"allow", "deny"}:
        return "policy"
    return str(record.get("event_type") or "traffic").lower()


def gateway_event_severity(*, action: str, event_type: Any, malformed: bool) -> str:
    if malformed:
        return "low"
    if action == "deny":
        return "medium"
    if action == "nat":
        return "low"
    if str(event_type or "").lower() in {"error", "alert"}:
        return "high"
    return "info"


def deterministic_gateway_log_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _safe_port(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if 0 <= port <= 65535:
        return port
    return None


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
