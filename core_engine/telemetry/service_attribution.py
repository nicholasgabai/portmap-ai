from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.flow_observations import FLOW_OBSERVATION_SAFETY_FLAGS
from core_engine.telemetry.process_attribution import (
    PROCESS_ATTRIBUTION_RECORD_VERSION,
    attribute_process_to_flow,
    build_process_socket_inventory,
)


SERVICE_ATTRIBUTION_RECORD_VERSION = 1

SERVICE_ATTRIBUTION_SAFETY_FLAGS = {
    **FLOW_OBSERVATION_SAFETY_FLAGS,
    "process_metadata_minimized": True,
    "command_line_stored": False,
    "username_stored": False,
    "privilege_escalation_attempted": False,
}


def build_process_service_attribution_report(
    *,
    enriched_flows: Iterable[dict[str, Any]],
    socket_records: Iterable[dict[str, Any]] | None = None,
    process_records: Iterable[dict[str, Any]] | None = None,
    protocol_records: Iterable[dict[str, Any]] | None = None,
    platform_status: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    flow_rows = sorted([dict(row) for row in enriched_flows or [] if isinstance(row, dict)], key=lambda item: str(item.get("flow_ref") or ""))
    inventory = build_process_socket_inventory(
        socket_records=socket_records,
        process_records=process_records,
        platform_status=platform_status,
        generated_at=timestamp,
    )
    protocol_index = _protocol_index(protocol_records)
    attributions = [
        build_service_attribution_record(
            flow_observation=flow,
            process_attribution=attribute_process_to_flow(flow, inventory, generated_at=timestamp),
            protocol_record=protocol_index.get(str(flow.get("flow_ref") or "")),
            generated_at=timestamp,
        )
        for flow in flow_rows
    ]
    summary = summarize_service_attributions(attributions, inventory=inventory, generated_at=timestamp)
    dashboard = build_service_attribution_dashboard_record(summary=summary, attributions=attributions, generated_at=timestamp)
    api = build_service_attribution_api_response(summary=summary, inventory=inventory, attributions=attributions, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "process_service_attribution_report",
        "record_version": SERVICE_ATTRIBUTION_RECORD_VERSION,
        "report_id": "process-service-attribution-" + _digest({"generated_at": timestamp, "flows": [row.get("flow_ref") for row in flow_rows]})[:16],
        "generated_at": timestamp,
        "inventory": inventory,
        "attributions": attributions,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **SERVICE_ATTRIBUTION_SAFETY_FLAGS,
    }


def build_service_attribution_record(
    *,
    flow_observation: dict[str, Any],
    process_attribution: dict[str, Any],
    protocol_record: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    flow = dict(flow_observation or {})
    process = dict(process_attribution or {})
    protocol = dict(protocol_record or {})
    service_hint = flow.get("service_port_hint") if isinstance(flow.get("service_port_hint"), dict) else {}
    service_name = _service_name(service_hint=service_hint, protocol_record=protocol)
    confidence = score_service_attribution_confidence(
        service_hint=service_hint,
        process_attribution=process,
        protocol_record=protocol,
    )
    return {
        "record_type": "service_attribution_record",
        "record_version": SERVICE_ATTRIBUTION_RECORD_VERSION,
        "attribution_id": "service-attribution-" + _digest({"flow": flow.get("flow_ref"), "service": service_name, "process": process.get("process_ref")})[:16],
        "generated_at": timestamp,
        "flow_ref": str(flow.get("flow_ref") or ""),
        "service_name": service_name,
        "service_port": service_hint.get("service_port"),
        "transport_protocol": str(flow.get("transport_protocol") or "unknown"),
        "process_attribution": process,
        "protocol_ref": str(protocol.get("protocol_metadata_id") or ""),
        "protocol_hint": str(protocol.get("protocol") or "unknown"),
        "confidence": confidence,
        "confidence_level": _confidence_level(confidence),
        "match_reasons": _service_match_reasons(service_hint=service_hint, process_attribution=process, protocol_record=protocol),
        "operator_display": build_sanitized_attribution_display(service_name=service_name, process_attribution=process, service_hint=service_hint),
        **SERVICE_ATTRIBUTION_SAFETY_FLAGS,
    }


def score_service_attribution_confidence(
    *,
    service_hint: dict[str, Any],
    process_attribution: dict[str, Any],
    protocol_record: dict[str, Any] | None = None,
) -> float:
    score = 0.15
    if str(service_hint.get("service_name") or "unknown") != "unknown":
        score += min(0.3, float(service_hint.get("confidence") or 0.0) * 0.3)
    process_confidence = float(process_attribution.get("confidence") or 0.0)
    score += min(0.35, process_confidence * 0.35)
    if protocol_record and str(protocol_record.get("protocol") or "unknown") != "unknown":
        score += min(0.15, float(protocol_record.get("confidence") or 0.0) * 0.15)
    if process_attribution.get("status") in {"unsupported", "permission_denied"}:
        score = min(score, 0.35)
    return round(max(0.0, min(1.0, score)), 3)


def summarize_service_attributions(
    attributions: Iterable[dict[str, Any]],
    *,
    inventory: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    process_rows = [row.get("process_attribution") for row in rows if isinstance(row.get("process_attribution"), dict)]
    inventory_summary = inventory.get("summary") if isinstance(inventory.get("summary"), dict) else {}
    return {
        "record_type": "process_service_attribution_summary",
        "record_version": SERVICE_ATTRIBUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "attribution_count": len(rows),
        "matched_process_count": sum(1 for row in process_rows if row.get("status") == "matched"),
        "unmatched_process_count": sum(1 for row in process_rows if row.get("status") == "unmatched"),
        "permission_denied_count": sum(1 for row in process_rows if row.get("permission_denied")),
        "unsupported_platform_count": sum(1 for row in process_rows if row.get("unsupported_platform")),
        "high_confidence_count": sum(1 for row in rows if row.get("confidence_level") == "high"),
        "medium_confidence_count": sum(1 for row in rows if row.get("confidence_level") == "medium"),
        "low_confidence_count": sum(1 for row in rows if row.get("confidence_level") == "low"),
        "average_confidence": round(sum(float(row.get("confidence") or 0.0) for row in rows) / len(rows), 3) if rows else 0.0,
        "listening_socket_count": int(inventory_summary.get("listening_socket_count") or 0),
        "by_service": _count_by(rows, "service_name"),
        "by_process_status": _count_by(process_rows, "status"),
        **SERVICE_ATTRIBUTION_SAFETY_FLAGS,
    }


def build_sanitized_attribution_display(
    *,
    service_name: str,
    process_attribution: dict[str, Any],
    service_hint: dict[str, Any],
) -> dict[str, Any]:
    process_display = process_attribution.get("process_display") if isinstance(process_attribution.get("process_display"), dict) else {}
    return {
        "service_name": service_name,
        "service_port": service_hint.get("service_port"),
        "process_ref": process_attribution.get("process_ref"),
        "process_display_name": process_display.get("display_name") or "unknown",
        "confidence_level": process_attribution.get("confidence_level"),
        "metadata_minimized": True,
        "command_line_stored": False,
        "username_stored": False,
    }


def build_service_attribution_dashboard_record(
    *,
    summary: dict[str, Any],
    attributions: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in attributions or [] if isinstance(row, dict)]
    degraded = bool(int(summary.get("permission_denied_count") or 0) or int(summary.get("unsupported_platform_count") or 0))
    status = "degraded" if degraded else "ok"
    return {
        "record_type": "process_service_attribution_dashboard",
        "panel": "process_service_attribution",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "attribution_count": int(summary.get("attribution_count") or 0),
            "matched_process_count": int(summary.get("matched_process_count") or 0),
            "unmatched_process_count": int(summary.get("unmatched_process_count") or 0),
            "listening_socket_count": int(summary.get("listening_socket_count") or 0),
            "average_confidence": float(summary.get("average_confidence") or 0.0),
        },
        "by_service": dict(summary.get("by_service") or {}),
        "rows": [
            {
                "flow_ref": row.get("flow_ref"),
                "service_name": row.get("service_name"),
                "service_port": row.get("service_port"),
                "process_ref": (row.get("process_attribution") or {}).get("process_ref") if isinstance(row.get("process_attribution"), dict) else "",
                "process_status": (row.get("process_attribution") or {}).get("status") if isinstance(row.get("process_attribution"), dict) else "unknown",
                "confidence_level": row.get("confidence_level"),
            }
            for row in sorted(rows, key=lambda item: str(item.get("flow_ref") or ""))
        ],
        "recommended_review": degraded or int(summary.get("unmatched_process_count") or 0) > 0,
        **SERVICE_ATTRIBUTION_SAFETY_FLAGS,
    }


def build_service_attribution_api_response(
    *,
    summary: dict[str, Any],
    inventory: dict[str, Any],
    attributions: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "process_service_attribution_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "inventory_summary": dict(inventory.get("summary") or {}),
        "attributions": [dict(row) for row in attributions or [] if isinstance(row, dict)],
        "dashboard": dict(dashboard),
        **SERVICE_ATTRIBUTION_SAFETY_FLAGS,
    }


def deterministic_service_attribution_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _protocol_index(protocol_records: Iterable[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    index = {}
    for row in protocol_records or []:
        if isinstance(row, dict):
            flow_ref = str(row.get("flow_ref") or "")
            if flow_ref:
                index[flow_ref] = dict(row)
    return index


def _service_name(*, service_hint: dict[str, Any], protocol_record: dict[str, Any]) -> str:
    hint_name = str(service_hint.get("service_name") or "unknown")
    if hint_name != "unknown":
        return hint_name
    protocol = str(protocol_record.get("protocol") or "unknown")
    return protocol if protocol != "unknown" else "unknown"


def _service_match_reasons(
    *,
    service_hint: dict[str, Any],
    process_attribution: dict[str, Any],
    protocol_record: dict[str, Any],
) -> list[str]:
    reasons = []
    if str(service_hint.get("service_name") or "unknown") != "unknown":
        reasons.append("service_port_hint")
    if process_attribution.get("status") == "matched":
        reasons.append("process_port_match")
    if str(protocol_record.get("protocol") or "unknown") != "unknown":
        reasons.append("protocol_metadata_hint")
    if not reasons:
        reasons.append("insufficient_attribution_evidence")
    return sorted(reasons)


def _confidence_level(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.5:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, dict):
            continue
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
