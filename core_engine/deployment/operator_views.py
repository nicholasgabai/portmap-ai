from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.deployment.deployment_summary import (
    DEPLOYMENT_SUMMARY_RECORD_VERSION,
    DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    build_deployment_operator_summary,
)


def build_deployment_operator_dashboard_view(
    *,
    deployment_summary: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = deployment_summary or build_deployment_operator_summary(generated_at=timestamp)
    cards = build_deployment_summary_cards(summary, generated_at=timestamp)
    checklist = build_readiness_checklist_view(summary, generated_at=timestamp)
    recommendations = build_deployment_recommendations(summary, generated_at=timestamp)
    platform_rollups = build_cross_platform_compatibility_rollup(summary, generated_at=timestamp)
    view = {
        "record_type": "deployment_operator_dashboard_view",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "view_id": "deployment-dashboard-" + _digest(
            {
                "state": summary.get("deployment_state"),
                "score": summary.get("readiness_score"),
                "generated_at": timestamp,
            }
        )[:16],
        "generated_at": timestamp,
        "summary_cards": cards,
        "readiness_checklist": checklist,
        "deployment_recommendations": recommendations,
        "cross_platform_compatibility_rollup": platform_rollups,
        "edge_raspberry_pi_readiness_rollup": build_platform_family_rollup("raspberry-pi-linux-arm", summary, generated_at=timestamp),
        "windows_macos_linux_readiness_rollup": {
            "windows": build_platform_family_rollup("windows", summary, generated_at=timestamp),
            "macos": build_platform_family_rollup("macos", summary, generated_at=timestamp),
            "linux": build_platform_family_rollup("linux", summary, generated_at=timestamp),
        },
        "backup_restore_readiness_rollup": build_component_view_rollup("backup_restore_planning", summary, generated_at=timestamp),
        "migration_readiness_rollup": build_component_view_rollup("upgrade_migration_readiness", summary, generated_at=timestamp),
        "api_status": build_deployment_operator_api_view(deployment_summary=summary, generated_at=timestamp),
        "dry_run_only": True,
        "destructive_action": False,
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }
    return view


def build_deployment_operator_api_view(
    *,
    deployment_summary: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    summary = deployment_summary or build_deployment_operator_summary(generated_at=timestamp)
    return {
        "record_type": "deployment_operator_api_view",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "generated_at": timestamp,
        "deployment_state": str(summary.get("deployment_state") or "unknown"),
        "readiness_score": int(summary.get("readiness_score") or 0),
        "cards": build_deployment_summary_cards(summary, generated_at=timestamp),
        "checklist": build_readiness_checklist_view(summary, generated_at=timestamp),
        "recommendations": build_deployment_recommendations(summary, generated_at=timestamp),
        "component_states": {
            name: row.get("state")
            for name, row in sorted(dict(summary.get("component_rollups") or {}).items())
            if isinstance(row, dict)
        },
        "dry_run_only": True,
        "destructive_action": False,
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }


def build_deployment_summary_cards(summary: dict[str, Any], *, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    rows = [
        ("deployment_state", "Deployment State", str(summary.get("deployment_state") or "unknown")),
        ("readiness_score", "Readiness Score", str(summary.get("readiness_score") or 0)),
        ("supported_components", "Supported Components", str(len(summary.get("supported_components") or []))),
        ("operator_actions", "Operator Actions", str(len(summary.get("operator_required_actions") or []))),
    ]
    return [
        {
            "record_type": "deployment_summary_card",
            "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
            "generated_at": timestamp,
            "card_id": card_id,
            "title": title,
            "value": value,
            "dashboard_safe": True,
            "api_compatible": True,
            **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
        }
        for card_id, title, value in rows
    ]


def build_readiness_checklist_view(summary: dict[str, Any], *, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    items = summary.get("release_readiness_checklist") or []
    return [
        {
            "record_type": "deployment_checklist_view_item",
            "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
            "generated_at": timestamp,
            "check_id": str(item.get("check_id") or "unknown"),
            "summary": str(item.get("summary") or ""),
            "state": str(item.get("state") or "unknown"),
            "complete": bool(item.get("complete", False)),
            "operator_review_required": bool(item.get("operator_review_required", True)),
            **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
        }
        for item in items
        if isinstance(item, dict)
    ]


def build_deployment_recommendations(summary: dict[str, Any], *, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    actions = summary.get("operator_required_actions") or []
    return [
        {
            "record_type": "deployment_recommendation",
            "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
            "generated_at": timestamp,
            "component": str(action.get("component") or "deployment"),
            "state": str(action.get("state") or "unknown"),
            "recommendation": str(action.get("action") or "Review deployment readiness."),
            "advisory_only": True,
            "operator_review_required": bool(action.get("operator_review_required", True)),
            **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
        }
        for action in actions
        if isinstance(action, dict)
    ]


def build_cross_platform_compatibility_rollup(summary: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "deployment_cross_platform_rollup",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "generated_at": timestamp,
        "state": _component_state("cross_platform_compatibility", summary),
        "platforms": {
            "macos": build_platform_family_rollup("macos", summary, generated_at=timestamp),
            "linux": build_platform_family_rollup("linux", summary, generated_at=timestamp),
            "raspberry-pi-linux-arm": build_platform_family_rollup("raspberry-pi-linux-arm", summary, generated_at=timestamp),
            "windows": build_platform_family_rollup("windows", summary, generated_at=timestamp),
        },
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }


def build_platform_family_rollup(platform_family: str, summary: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    base_state = _component_state("cross_platform_compatibility", summary)
    if base_state == "unknown":
        state = "degraded"
    else:
        state = base_state
    return {
        "record_type": "deployment_platform_family_rollup",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "platform_family": str(platform_family),
        "state": state,
        "operator_summary": f"{platform_family} deployment compatibility remains advisory and dry-run only.",
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }


def build_component_view_rollup(component: str, summary: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    state = _component_state(component, summary)
    return {
        "record_type": "deployment_component_view_rollup",
        "record_version": DEPLOYMENT_SUMMARY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "component": component,
        "state": state,
        "operator_review_required": state != "ready",
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }


def export_deployment_operator_view(view: dict[str, Any]) -> str:
    payload = {
        "record_type": str(view.get("record_type") or "deployment_operator_dashboard_view"),
        "deployment_state": str((view.get("api_status") or {}).get("deployment_state") or "unknown"),
        "readiness_score": int((view.get("api_status") or {}).get("readiness_score") or 0),
        "summary_card_count": len(view.get("summary_cards") or []),
        "recommendation_count": len(view.get("deployment_recommendations") or []),
        "dry_run_only": True,
        "destructive_action": False,
        **DEPLOYMENT_SUMMARY_SAFETY_FLAGS,
    }
    return json.dumps(payload, sort_keys=True)


def _component_state(component: str, summary: dict[str, Any]) -> str:
    rollups = summary.get("component_rollups") if isinstance(summary.get("component_rollups"), dict) else {}
    row = rollups.get(component) if isinstance(rollups, dict) else None
    if isinstance(row, dict):
        return str(row.get("state") or "unknown")
    return "unknown"


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
