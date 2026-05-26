from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.gateway.mirror_profiles import SPAN_READINESS_SAFETY_FLAGS


GATEWAY_VALIDATION_RECORD_VERSION = 1
GATEWAY_VALIDATION_STATES = frozenset({"supported", "degraded", "unavailable", "unsafe"})

GATEWAY_VALIDATION_SAFETY_FLAGS = {
    **SPAN_READINESS_SAFETY_FLAGS,
    "gateway_validation_only": True,
    "bridge_mode_enabled": False,
    "promiscuous_mode_enabled": False,
    "interface_mode_changed": False,
    "router_settings_modified": False,
    "switch_settings_modified": False,
    "service_installed": False,
    "service_started": False,
    "automatic_blocking": False,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "dashboard_safe": True,
    "api_compatible": True,
    "export_ready": True,
}


def build_gateway_mode_validation_report(
    *,
    flow_enrichment: dict[str, Any] | None = None,
    process_service_attribution: dict[str, Any] | None = None,
    dns_visibility: dict[str, Any] | None = None,
    router_logs: dict[str, Any] | None = None,
    span_readiness: dict[str, Any] | None = None,
    topology_correlation: dict[str, Any] | None = None,
    runtime_health: dict[str, Any] | None = None,
    operator_visibility: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build an advisory gateway-mode validation report from local dry-run records."""
    timestamp = generated_at or _now()
    component_validations = [
        validate_telemetry_enrichment(flow_enrichment, generated_at=timestamp),
        validate_process_service_attribution(process_service_attribution, generated_at=timestamp),
        validate_dns_visibility(dns_visibility, generated_at=timestamp),
        validate_router_log_ingestion(router_logs, generated_at=timestamp),
        validate_span_readiness(span_readiness, generated_at=timestamp),
        validate_topology_correlation(topology_correlation, generated_at=timestamp),
        validate_runtime_health(runtime_health, generated_at=timestamp),
        validate_operator_visibility(operator_visibility, generated_at=timestamp),
    ]
    checklist = build_gateway_operator_safety_checklist(component_validations, generated_at=timestamp)
    summary = summarize_gateway_validation(component_validations, checklist=checklist, generated_at=timestamp)
    export_summary = build_gateway_validation_export_summary(summary=summary, validations=component_validations, generated_at=timestamp)
    return {
        "record_type": "gateway_mode_validation_report",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "report_id": "gateway-validation-" + _digest({"generated_at": timestamp, "components": component_validations, "summary": summary})[:16],
        "generated_at": timestamp,
        "component_validations": component_validations,
        "summary": summary,
        "operator_safety_checklist": checklist,
        "export_summary": export_summary,
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def validate_telemetry_enrichment(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("telemetry_enrichment", "unavailable", "No flow enrichment report was provided.", generated_at=generated_at)
    summary = _summary(record)
    count = int(summary.get("observation_count") or record.get("input_flow_count") or 0)
    malformed = int(summary.get("malformed_flow_count") or 0)
    dropped = int(summary.get("dropped_observation_count") or record.get("dropped_observation_count") or 0)
    warnings = []
    if malformed:
        warnings.append("malformed_flow_observations_present")
    if dropped:
        warnings.append("flow_observations_dropped_by_bounds")
    state = "supported" if count and not warnings else "degraded" if count else "unavailable"
    return _component_validation(
        "telemetry_enrichment",
        state,
        "Flow enrichment records are available." if count else "Flow enrichment has no observations.",
        metrics={"observation_count": count, "malformed_flow_count": malformed, "dropped_observation_count": dropped},
        warnings=warnings,
        source_refs=[str(record.get("report_id") or "")],
        generated_at=generated_at,
    )


def validate_process_service_attribution(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("process_service_attribution", "unavailable", "No process/service attribution report was provided.", generated_at=generated_at)
    summary = _summary(record)
    count = int(summary.get("attribution_count") or summary.get("socket_count") or record.get("count") or 0)
    degraded = str(record.get("status") or (record.get("dashboard_status") or {}).get("status") or "").lower() in {"degraded", "review_required", "unsupported", "permission_denied"}
    warnings = list(summary.get("warnings") or [])
    state = "degraded" if degraded else "supported" if count or summary else "unavailable"
    return _component_validation(
        "process_service_attribution",
        state,
        "Process and service attribution is available." if state != "unavailable" else "Process and service attribution is unavailable.",
        metrics={"attribution_count": count},
        warnings=warnings,
        generated_at=generated_at,
    )


def validate_dns_visibility(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("dns_visibility", "unavailable", "No DNS visibility report was provided.", generated_at=generated_at)
    summary = _summary(record)
    query_count = int(summary.get("query_count") or len(record.get("queries") or []))
    response_count = int(summary.get("response_count") or len(record.get("responses") or []))
    encrypted_limitations = record.get("encrypted_dns_limitations") if isinstance(record.get("encrypted_dns_limitations"), dict) else {}
    encrypted_count = int(encrypted_limitations.get("encrypted_flow_count") or 0)
    anomaly_count = int(summary.get("anomaly_hint_count") or len(record.get("anomaly_hints") or []))
    warnings = []
    if encrypted_count:
        warnings.append("encrypted_dns_visibility_limited")
    if anomaly_count:
        warnings.append("dns_anomaly_hints_present")
    state = "supported" if query_count or response_count else "unavailable"
    if state == "supported" and warnings:
        state = "degraded"
    return _component_validation(
        "dns_visibility",
        state,
        "DNS metadata visibility is available." if state != "unavailable" else "DNS visibility has no records.",
        metrics={"query_count": query_count, "response_count": response_count, "encrypted_flow_count": encrypted_count, "anomaly_hint_count": anomaly_count},
        warnings=warnings,
        source_refs=[str(record.get("report_id") or "")],
        generated_at=generated_at,
    )


def validate_router_log_ingestion(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("router_log_ingestion", "unavailable", "No gateway/router log ingestion report was provided.", generated_at=generated_at)
    summary = _summary(record)
    count = int(summary.get("record_count") or len(record.get("records") or []))
    malformed = int(summary.get("malformed_count") or 0)
    deny = int(summary.get("deny_count") or 0)
    warnings = []
    if malformed:
        warnings.append("malformed_gateway_logs_present")
    if deny:
        warnings.append("gateway_deny_events_require_review")
    state = "supported" if count and not malformed else "degraded" if count else "unavailable"
    return _component_validation(
        "router_log_ingestion",
        state,
        "Gateway/router log summaries are available." if count else "Gateway/router log ingestion has no records.",
        metrics={"record_count": count, "malformed_count": malformed, "deny_count": deny},
        warnings=warnings,
        source_refs=[str(record.get("report_id") or "")],
        generated_at=generated_at,
    )


def validate_span_readiness(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("span_readiness", "unavailable", "No SPAN/mirror-port readiness report was provided.", generated_at=generated_at)
    summary = _summary(record)
    status = str(summary.get("status") or record.get("status") or "unknown")
    state = "supported" if status == "ready" else "unsafe" if status == "unsafe" else "degraded"
    warnings = list(summary.get("warnings") or [])
    if status == "review_required":
        warnings.append("span_readiness_requires_operator_review")
    return _component_validation(
        "span_readiness",
        state,
        "SPAN readiness is ready." if state == "supported" else f"SPAN readiness is {status}.",
        metrics={
            "check_count": int(summary.get("check_count") or 0),
            "review_count": int(summary.get("review_count") or 0),
            "blocked_count": int(summary.get("blocked_count") or 0),
        },
        warnings=warnings,
        source_refs=[str(record.get("report_id") or "")],
        generated_at=generated_at,
    )


def validate_topology_correlation(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("topology_correlation", "unavailable", "No live topology correlation report was provided.", generated_at=generated_at)
    graph = record.get("graph") if isinstance(record.get("graph"), dict) else record
    health = record.get("health_summary") if isinstance(record.get("health_summary"), dict) else record.get("topology_health") if isinstance(record.get("topology_health"), dict) else {}
    node_count = int(graph.get("node_count") or len(graph.get("nodes") or []))
    edge_count = int(graph.get("edge_count") or len(graph.get("edges") or []))
    warnings = list(health.get("warnings") or record.get("warnings") or [])
    state = "supported" if node_count or edge_count else "unavailable"
    if state == "supported" and (str(health.get("status") or record.get("status") or "") == "review_required" or warnings):
        state = "degraded"
    return _component_validation(
        "topology_correlation",
        state,
        "Topology correlation has graph records." if state != "unavailable" else "Topology correlation has no graph records.",
        metrics={"node_count": node_count, "edge_count": edge_count},
        warnings=warnings,
        source_refs=[str(record.get("topology_id") or record.get("report_id") or "")],
        generated_at=generated_at,
    )


def validate_runtime_health(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("runtime_health", "unavailable", "No runtime health summary was provided.", generated_at=generated_at)
    status = str(record.get("status") or "unknown")
    state = "supported" if status == "ok" else "degraded" if status in {"degraded", "review_required", "unknown"} else "unsafe" if status == "unsafe" else "degraded"
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    return _component_validation(
        "runtime_health",
        state,
        f"Runtime health status is {status}.",
        metrics={"check_count": int(summary.get("check_count") or len(record.get("checks") or [])), "failed_count": int(summary.get("failed_count") or 0)},
        warnings=[] if state == "supported" else [f"runtime_health:{status}"],
        generated_at=generated_at,
    )


def validate_operator_visibility(record: dict[str, Any] | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if not record:
        return _component_validation("operator_visibility", "unavailable", "No operator visibility summary was provided.", generated_at=generated_at)
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    status = str(record.get("status") or summary.get("status") or "ok")
    state = "supported" if status in {"ok", "ready"} else "degraded"
    return _component_validation(
        "operator_visibility",
        state,
        f"Operator visibility status is {status}.",
        metrics={"panel_count": len(record.get("panels") or {}) if isinstance(record.get("panels"), dict) else 0},
        warnings=[] if state == "supported" else [f"operator_visibility:{status}"],
        generated_at=generated_at,
    )


def build_gateway_operator_safety_checklist(
    validations: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = list(validations or [])
    checks = [
        _check_item("bridge_mode_disabled", "Bridge mode is not enabled by validation.", "pass", []),
        _check_item("promiscuous_mode_disabled", "Promiscuous mode is not enabled automatically.", "pass", []),
        _check_item("router_switch_unchanged", "Router and switch settings are not modified.", "pass", []),
        _check_item("services_not_started", "Services are not installed or started automatically.", "pass", []),
        _check_item("automatic_blocking_disabled", "Automatic blocking remains disabled.", "pass", []),
    ]
    for validation in rows:
        state = str(validation.get("state") or "unavailable")
        status = "block" if state == "unsafe" else "review" if state in {"degraded", "unavailable"} else "pass"
        checks.append(
            _check_item(
                f"component:{validation.get('component')}",
                f"{validation.get('component')} validation state is {state}.",
                status,
                validation.get("warnings") or [],
            )
        )
    return {
        "record_type": "gateway_operator_safety_checklist",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "checks": checks,
        "check_count": len(checks),
        "passed_count": sum(1 for item in checks if item["status"] == "pass"),
        "review_count": sum(1 for item in checks if item["status"] == "review"),
        "blocked_count": sum(1 for item in checks if item["status"] == "block"),
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def summarize_gateway_validation(
    validations: Iterable[dict[str, Any]],
    *,
    checklist: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = list(validations or [])
    counts = _count_by(rows, "state")
    blocked = int(checklist.get("blocked_count") or 0)
    review = int(checklist.get("review_count") or 0)
    if blocked or counts.get("unsafe", 0):
        status = "unsafe"
    elif review or counts.get("degraded", 0) or counts.get("unavailable", 0):
        status = "degraded"
    else:
        status = "supported"
    return {
        "record_type": "gateway_validation_summary",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "component_count": len(rows),
        "supported_count": counts.get("supported", 0),
        "degraded_count": counts.get("degraded", 0),
        "unavailable_count": counts.get("unavailable", 0),
        "unsafe_count": counts.get("unsafe", 0),
        "check_count": int(checklist.get("check_count") or 0),
        "review_count": review,
        "blocked_count": blocked,
        "warnings": sorted({warning for row in rows for warning in row.get("warnings") or []}),
        "operator_summary": _operator_summary(status),
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def build_gateway_validation_export_summary(
    *,
    summary: dict[str, Any],
    validations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = list(validations or [])
    digest = "sha256:" + _digest({"summary": summary, "components": rows})
    return {
        "record_type": "gateway_validation_export_summary",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "export_ready": True,
        "digest": digest,
        "record_counts": {
            "component_validations": len(rows),
            "warnings": len(summary.get("warnings") or []),
            "blocked_checks": int(summary.get("blocked_count") or 0),
        },
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def deterministic_gateway_validation_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _component_validation(
    component: str,
    state: str,
    operator_summary: str,
    *,
    metrics: dict[str, Any] | None = None,
    warnings: Iterable[Any] | None = None,
    source_refs: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    normalized_state = state if state in GATEWAY_VALIDATION_STATES else "degraded"
    row = {
        "record_type": "gateway_component_validation",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "component": component,
        "state": normalized_state,
        "metrics": dict(metrics or {}),
        "warnings": sorted(str(item) for item in warnings or [] if str(item)),
        "source_refs": sorted(str(item) for item in source_refs or [] if str(item)),
        "operator_summary": operator_summary,
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }
    row["validation_id"] = "gateway-component-" + _digest(row)[:16]
    return row


def _check_item(check_id: str, label: str, status: str, warnings: Iterable[Any]) -> dict[str, Any]:
    return {
        "check_id": check_id,
        "label": label,
        "status": status,
        "warnings": sorted(str(item) for item in warnings or [] if str(item)),
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def _summary(record: dict[str, Any]) -> dict[str, Any]:
    if isinstance(record.get("summary"), dict):
        return dict(record["summary"])
    if isinstance(record.get("api_status"), dict) and isinstance(record["api_status"].get("summary"), dict):
        return dict(record["api_status"]["summary"])
    return {}


def _count_by(rows: Iterable[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(key) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _operator_summary(status: str) -> str:
    if status == "supported":
        return "Gateway mode validation is supported in dry-run readiness records."
    if status == "unsafe":
        return "Gateway mode validation found unsafe readiness conditions; operator action is required before any gateway deployment."
    return "Gateway mode validation is degraded and requires operator review before gateway deployment."


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "GATEWAY_VALIDATION_RECORD_VERSION",
    "GATEWAY_VALIDATION_SAFETY_FLAGS",
    "GATEWAY_VALIDATION_STATES",
    "build_gateway_mode_validation_report",
    "build_gateway_operator_safety_checklist",
    "build_gateway_validation_export_summary",
    "deterministic_gateway_validation_json",
    "summarize_gateway_validation",
    "validate_dns_visibility",
    "validate_operator_visibility",
    "validate_process_service_attribution",
    "validate_router_log_ingestion",
    "validate_runtime_health",
    "validate_span_readiness",
    "validate_telemetry_enrichment",
    "validate_topology_correlation",
]
