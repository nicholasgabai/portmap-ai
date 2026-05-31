from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.export.node_manifest import digest_payload
from core_engine.history.resource_retention import RESOURCE_RETENTION_SAFETY_FLAGS


LONG_TERM_OPERATOR_VIEW_RECORD_VERSION = 1

LONG_TERM_OPERATOR_VIEW_SAFETY_FLAGS = {
    **RESOURCE_RETENTION_SAFETY_FLAGS,
    "long_term_intelligence_operator_view": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "dashboard_safe": True,
    "export_ready": True,
    "automatic_deletion": False,
    "delete_performed": False,
    "packet_payloads_stored": False,
    "credentials_stored": False,
    "raw_browsing_history_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}


def build_long_term_intelligence_dashboard_record(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "long_term_intelligence_dashboard",
        "record_version": LONG_TERM_OPERATOR_VIEW_RECORD_VERSION,
        "panel": "long_term_intelligence",
        "generated_at": timestamp,
        "status": str(state_summary.get("overall_state") or "unknown"),
        "metrics": {
            "supported_component_count": int(state_summary.get("supported_component_count") or 0),
            "degraded_component_count": int(state_summary.get("degraded_component_count") or 0),
            "unavailable_component_count": int(state_summary.get("unavailable_component_count") or 0),
            "recommended_review_count": int(state_summary.get("recommended_review_count") or 0),
            "total_record_count": int(state_summary.get("total_record_count") or 0),
        },
        "component_rows": [
            {
                "component": name,
                "state": row.get("state"),
                "record_count": row.get("record_count"),
                "recommended_review_count": row.get("recommended_review_count"),
                "source_report_type": row.get("source_report_type"),
            }
            for name, row in sorted(rollups.items())
        ],
        "recommendations": _rows(recommendations)[:20],
        "recommended_review": int(state_summary.get("recommended_review_count") or 0) > 0,
        **LONG_TERM_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def build_long_term_intelligence_api_response(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    privacy_safety_summary: dict[str, Any],
    dashboard: dict[str, Any],
    export: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "long_term_intelligence_api",
        "record_version": LONG_TERM_OPERATOR_VIEW_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": str(state_summary.get("overall_state") or "unknown"),
        "rollups": dict(rollups),
        "state_summary": dict(state_summary),
        "recommendations": _rows(recommendations),
        "privacy_safety_summary": dict(privacy_safety_summary),
        "dashboard_status": dict(dashboard),
        "export_summary": dict(export),
        **LONG_TERM_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def build_long_term_intelligence_export_summary(
    *,
    rollups: dict[str, dict[str, Any]],
    state_summary: dict[str, Any],
    recommendations: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    record_counts = {name: int(row.get("record_count") or 0) for name, row in sorted(rollups.items())}
    payload = {
        "record_type": "long_term_intelligence_export_summary",
        "record_version": LONG_TERM_OPERATOR_VIEW_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "overall_state": str(state_summary.get("overall_state") or "unknown"),
        "record_counts": record_counts,
        "recommendation_count": len(_rows(recommendations)),
        "digest": "",
        **LONG_TERM_OPERATOR_VIEW_SAFETY_FLAGS,
    }
    payload["digest"] = digest_payload(
        {
            "overall_state": payload["overall_state"],
            "record_counts": record_counts,
            "recommendation_count": payload["recommendation_count"],
        }
    )
    return payload


def build_long_term_privacy_safety_summary(*, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "record_type": "long_term_intelligence_privacy_safety_summary",
        "record_version": LONG_TERM_OPERATOR_VIEW_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "metadata_only": True,
        "payloads_stored": False,
        "packet_payloads_stored": False,
        "credentials_stored": False,
        "raw_browsing_history_stored": False,
        "raw_runtime_logs_stored": False,
        "external_services_used": False,
        "automatic_deletion": False,
        "automatic_enforcement": False,
        "operator_review_required_for_action": True,
        **LONG_TERM_OPERATOR_VIEW_SAFETY_FLAGS,
    }


def _rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _now() -> str:
    return datetime.now(UTC).isoformat()
