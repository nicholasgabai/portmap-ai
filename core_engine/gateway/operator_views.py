from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.gateway.validation import GATEWAY_VALIDATION_RECORD_VERSION, GATEWAY_VALIDATION_SAFETY_FLAGS


def build_gateway_validation_dashboard_record(
    validation_report: dict[str, Any] | None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not validation_report:
        return build_empty_gateway_validation_model(generated_at=timestamp)
    summary = validation_report.get("summary") if isinstance(validation_report.get("summary"), dict) else {}
    checklist = validation_report.get("operator_safety_checklist") if isinstance(validation_report.get("operator_safety_checklist"), dict) else {}
    validations = _rows(validation_report.get("component_validations"))
    return {
        "record_type": "gateway_validation_dashboard",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "panel": "gateway_mode_validation",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": timestamp,
        "metrics": {
            "component_count": int(summary.get("component_count") or len(validations)),
            "supported_count": int(summary.get("supported_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "unsafe_count": int(summary.get("unsafe_count") or 0),
            "review_count": int(summary.get("review_count") or checklist.get("review_count") or 0),
            "blocked_count": int(summary.get("blocked_count") or checklist.get("blocked_count") or 0),
        },
        "rows": [
            {
                "component": row.get("component"),
                "state": row.get("state"),
                "warnings": list(row.get("warnings") or []),
                "operator_summary": row.get("operator_summary"),
            }
            for row in sorted(validations, key=lambda item: str(item.get("component") or ""))
        ],
        "checklist_rows": [
            {
                "check_id": row.get("check_id"),
                "status": row.get("status"),
                "label": row.get("label"),
            }
            for row in checklist.get("checks") or []
            if isinstance(row, dict)
        ],
        "recommended_review": str(summary.get("status")) != "supported",
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def build_gateway_validation_api_response(
    validation_report: dict[str, Any] | None,
    *,
    dashboard: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    if not validation_report:
        empty = dashboard or build_empty_gateway_validation_model(generated_at=timestamp)
        return {
            "record_type": "gateway_validation_api",
            "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
            "status": "unavailable",
            "generated_at": timestamp,
            "summary": empty.get("summary") or {},
            "component_validations": [],
            "dashboard": empty,
            **GATEWAY_VALIDATION_SAFETY_FLAGS,
        }
    effective_dashboard = dashboard or build_gateway_validation_dashboard_record(validation_report, generated_at=timestamp)
    return {
        "record_type": "gateway_validation_api",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "status": str((validation_report.get("summary") or {}).get("status") if isinstance(validation_report.get("summary"), dict) else "unknown"),
        "generated_at": timestamp,
        "summary": dict(validation_report.get("summary") or {}),
        "component_validations": _rows(validation_report.get("component_validations")),
        "operator_safety_checklist": dict(validation_report.get("operator_safety_checklist") or {}),
        "export_summary": dict(validation_report.get("export_summary") or {}),
        "dashboard": effective_dashboard,
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def build_gateway_validation_operator_view(
    validation_report: dict[str, Any] | None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    dashboard = build_gateway_validation_dashboard_record(validation_report, generated_at=timestamp)
    api = build_gateway_validation_api_response(validation_report, dashboard=dashboard, generated_at=timestamp)
    summary = dict((validation_report or {}).get("summary") or {})
    return {
        "record_type": "gateway_validation_operator_view",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "generated_at": timestamp,
        "status": str(summary.get("status") or dashboard.get("status") or "unavailable"),
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        "empty_state": build_empty_gateway_validation_model(generated_at=timestamp) if not validation_report else None,
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def build_empty_gateway_validation_model(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "gateway_validation_empty_state",
        "record_version": GATEWAY_VALIDATION_RECORD_VERSION,
        "panel": "gateway_mode_validation",
        "status": "unavailable",
        "generated_at": generated_at or _now(),
        "summary": {
            "status": "unavailable",
            "component_count": 0,
            "supported_count": 0,
            "degraded_count": 0,
            "unavailable_count": 0,
            "unsafe_count": 0,
        },
        "metrics": {
            "component_count": 0,
            "supported_count": 0,
            "degraded_count": 0,
            "unavailable_count": 0,
            "unsafe_count": 0,
            "review_count": 0,
            "blocked_count": 0,
        },
        "rows": [],
        "checklist_rows": [],
        "recommended_review": False,
        **GATEWAY_VALIDATION_SAFETY_FLAGS,
    }


def deterministic_gateway_operator_view_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "build_empty_gateway_validation_model",
    "build_gateway_validation_api_response",
    "build_gateway_validation_dashboard_record",
    "build_gateway_validation_operator_view",
    "deterministic_gateway_operator_view_json",
]
