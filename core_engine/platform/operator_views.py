from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from core_engine.platform.validation_summary import (
    PLATFORM_VALIDATION_RECORD_VERSION,
    PLATFORM_VALIDATION_SAFETY_FLAGS,
    build_cli_table_rows,
    build_cross_platform_validation_report,
)


def build_cross_platform_validation_operator_view(
    validation_report: dict[str, Any] | None = None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    report = validation_report or build_cross_platform_validation_report(generated_at=timestamp)
    dashboard = build_cross_platform_validation_dashboard_record(report, generated_at=timestamp)
    api = build_cross_platform_validation_api_response(report, dashboard=dashboard, generated_at=timestamp)
    table = build_cross_platform_validation_table(report, generated_at=timestamp)
    return {
        "record_type": "cross_platform_validation_operator_view",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "generated_at": timestamp,
        "status": str((report.get("summary") or {}).get("status") if isinstance(report.get("summary"), dict) else "unknown"),
        "summary": dict(report.get("summary") or {}),
        "dashboard_status": dashboard,
        "api_status": api,
        "table_status": table,
        "empty_state": build_empty_platform_validation_model(generated_at=timestamp) if not report.get("platforms") else None,
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def build_cross_platform_validation_dashboard_record(
    validation_report: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = dict(validation_report.get("summary") or {})
    rows = [
        {
            "platform": row.get("platform_family"),
            "status": row.get("status"),
            "supported_count": row.get("supported_count"),
            "degraded_count": row.get("degraded_count"),
            "unavailable_count": row.get("unavailable_count"),
            "unknown_count": row.get("unknown_count"),
        }
        for row in validation_report.get("platforms") or []
        if isinstance(row, dict)
    ]
    return {
        "record_type": "cross_platform_validation_dashboard",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "panel": "cross_platform_validation",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": timestamp,
        "metrics": {
            "platform_count": int(summary.get("platform_count") or 0),
            "supported_count": int(summary.get("supported_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "unknown_count": int(summary.get("unknown_count") or 0),
        },
        "rows": sorted(rows, key=lambda item: str(item.get("platform") or "")),
        "recommended_review": str(summary.get("status") or "") != "supported",
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def build_cross_platform_validation_api_response(
    validation_report: dict[str, Any],
    *,
    dashboard: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = dict(validation_report.get("summary") or {})
    return {
        "record_type": "cross_platform_validation_api",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "status": str(summary.get("status") or "unknown"),
        "generated_at": timestamp,
        "summary": summary,
        "platforms": [dict(row) for row in validation_report.get("platforms") or [] if isinstance(row, dict)],
        "operator_recommendations": dict(validation_report.get("operator_recommendations") or {}),
        "dashboard": dashboard or build_cross_platform_validation_dashboard_record(validation_report, generated_at=timestamp),
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def build_cross_platform_validation_table(
    validation_report: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = build_cli_table_rows(validation_report)
    return {
        "record_type": "cross_platform_validation_table",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "columns": ["platform", "status", "runtime", "capture", "firewall", "filesystem", "windows", "review"],
        "rows": rows,
        "row_count": len(rows),
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def build_empty_platform_validation_model(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "cross_platform_validation_empty_state",
        "record_version": PLATFORM_VALIDATION_RECORD_VERSION,
        "panel": "cross_platform_validation",
        "status": "unknown",
        "generated_at": generated_at or _now(),
        "summary": {
            "status": "unknown",
            "platform_count": 0,
            "supported_count": 0,
            "degraded_count": 0,
            "unavailable_count": 0,
            "unknown_count": 0,
        },
        "rows": [],
        **PLATFORM_VALIDATION_SAFETY_FLAGS,
    }


def deterministic_platform_operator_view_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "build_cross_platform_validation_api_response",
    "build_cross_platform_validation_dashboard_record",
    "build_cross_platform_validation_operator_view",
    "build_cross_platform_validation_table",
    "build_empty_platform_validation_model",
    "deterministic_platform_operator_view_json",
]
