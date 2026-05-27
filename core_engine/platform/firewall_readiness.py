from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.platform.firewall_providers import (
    FIREWALL_PROVIDER_SAFETY_FLAGS,
    build_firewall_provider_summary,
    build_firewall_rule_preview,
)
from core_engine.platform.runtime_detection import build_platform_runtime_record
from core_engine.remediation_safety import safety_policy


FIREWALL_READINESS_RECORD_VERSION = 1

FIREWALL_READINESS_SAFETY_FLAGS = {
    **FIREWALL_PROVIDER_SAFETY_FLAGS,
    "firewall_readiness_only": True,
    "operator_review_required": True,
    "automatic_enforcement_enabled": False,
    "automatic_blocking": False,
    "rules_applied_count": 0,
    "dry_run_rule_count": 0,
    "admin_elevation_requested": False,
}


def build_cross_platform_firewall_readiness_report(
    *,
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    is_admin: bool | None = None,
    provider_statuses: dict[str, str] | None = None,
    rule_previews: list[dict[str, Any]] | None = None,
    runtime_health: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    remediation_settings: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a dry-run firewall provider readiness report without modifying rules."""
    timestamp = generated_at or _now()
    platform_payload = platform_record or build_platform_runtime_record(
        platform_info=platform_info,
        is_admin=is_admin,
        generated_at=timestamp,
    )
    providers = build_firewall_provider_summary(
        platform_record=platform_payload,
        provider_statuses=provider_statuses,
        generated_at=timestamp,
    )
    previews = _rule_previews(providers, rule_previews=rule_previews, generated_at=timestamp)
    permission = build_firewall_permission_requirement_summary(platform_payload, generated_at=timestamp)
    safety = build_firewall_rule_safety_summary(
        providers=providers,
        rule_previews=previews,
        runtime_health=runtime_health,
        gateway_validation=gateway_validation,
        remediation_settings=remediation_settings,
        generated_at=timestamp,
    )
    summary = summarize_firewall_readiness(
        platform_record=platform_payload,
        providers=providers,
        permission=permission,
        safety=safety,
        rule_previews=previews,
        generated_at=timestamp,
    )
    dashboard = build_firewall_readiness_dashboard_record(
        summary=summary,
        providers=providers,
        permission=permission,
        safety=safety,
        rule_previews=previews,
        generated_at=timestamp,
    )
    api = build_firewall_readiness_api_response(
        summary=summary,
        platform_record=platform_payload,
        providers=providers,
        permission=permission,
        safety=safety,
        rule_previews=previews,
        dashboard=dashboard,
        generated_at=timestamp,
    )
    return {
        "record_type": "cross_platform_firewall_readiness_report",
        "record_version": FIREWALL_READINESS_RECORD_VERSION,
        "report_id": "firewall-readiness-" + _digest({"generated_at": timestamp, "platform": platform_payload.get("platform_family"), "summary": summary})[:16],
        "generated_at": timestamp,
        "platform": platform_payload,
        "provider_readiness": providers,
        "permission_requirements": permission,
        "rule_previews": previews,
        "rule_safety": safety,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **FIREWALL_READINESS_SAFETY_FLAGS,
    }


def build_firewall_permission_requirement_summary(
    platform_record: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    platform_family = str(platform_record.get("platform_family") or "unknown")
    permissions = platform_record.get("permissions") if isinstance(platform_record.get("permissions"), dict) else {}
    elevated = bool(permissions.get("elevated"))
    requires_manual_permission = platform_family in {"windows", "macos", "linux", "raspberry-pi-linux-arm"}
    status = "supported" if requires_manual_permission and elevated else "degraded" if requires_manual_permission else "unknown"
    warnings = []
    if requires_manual_permission and not elevated:
        warnings.append("manual_firewall_permission_review_required")
    if platform_family == "unknown":
        warnings.append("platform_family_unknown")
    return {
        "record_type": "firewall_permission_requirement_summary",
        "record_version": FIREWALL_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "platform_family": platform_family,
        "status": status,
        "currently_elevated": elevated,
        "requires_manual_permission_for_future_rules": requires_manual_permission,
        "admin_or_root_required_for_future_rules": requires_manual_permission,
        "elevation_requested": False,
        "permission_change_attempted": False,
        "warnings": sorted(set(warnings)),
        **FIREWALL_READINESS_SAFETY_FLAGS,
    }


def build_firewall_rule_safety_summary(
    *,
    providers: dict[str, Any],
    rule_previews: list[dict[str, Any]],
    runtime_health: dict[str, Any] | None = None,
    gateway_validation: dict[str, Any] | None = None,
    remediation_settings: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    policy = safety_policy(remediation_settings or {})
    warnings = {
        "dry_run_rule_preview_only",
        "manual_operator_review_required",
        "automatic_blocking_disabled",
        "firewall_rule_changes_disabled",
    }
    provider_summary = providers.get("summary") if isinstance(providers.get("summary"), dict) else {}
    warnings.update(provider_summary.get("warnings") or [])
    for source_name, record in {"runtime_health": runtime_health, "gateway_validation": gateway_validation}.items():
        status = _nested_status(record)
        if status in {"degraded", "review_required", "unsafe", "unknown"}:
            warnings.add(f"{source_name}_{status}")
    active_enforcement = bool(policy.get("active_enforcement_enabled"))
    if active_enforcement:
        warnings.add("active_enforcement_setting_ignored_by_readiness_preview")
    return {
        "record_type": "firewall_rule_safety_summary",
        "record_version": FIREWALL_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": "review_required",
        "rule_preview_count": len(rule_previews),
        "rules_applied_count": 0,
        "operator_review_required": True,
        "active_enforcement_setting": active_enforcement,
        "active_enforcement_enabled": False,
        "warnings": sorted(warnings),
        **FIREWALL_READINESS_SAFETY_FLAGS,
    }


def summarize_firewall_readiness(
    *,
    platform_record: dict[str, Any],
    providers: dict[str, Any],
    permission: dict[str, Any],
    safety: dict[str, Any],
    rule_previews: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    platform_family = str(platform_record.get("platform_family") or "unknown")
    provider_status = str((providers.get("summary") or {}).get("status") or "unknown")
    permission_status = str(permission.get("status") or "unknown")
    if platform_family == "unknown":
        status = "unknown"
    elif provider_status == "supported" and permission_status == "supported":
        status = "supported"
    elif provider_status in {"supported", "degraded"} or permission_status == "degraded":
        status = "degraded"
    else:
        status = "unavailable"
    warnings = sorted(set(list((providers.get("summary") or {}).get("warnings") or []) + list(permission.get("warnings") or []) + list(safety.get("warnings") or [])))
    return {
        "record_type": "firewall_readiness_summary",
        "record_version": FIREWALL_READINESS_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "platform_family": platform_family,
        "provider_status": provider_status,
        "permission_status": permission_status,
        "provider_count": int((providers.get("summary") or {}).get("provider_count") or 0),
        "rule_preview_count": len(rule_previews),
        "rules_applied_count": 0,
        "operator_review_required": True,
        "warning_count": len(warnings),
        "warnings": warnings,
        "operator_summary": _operator_summary(status, platform_family),
        **FIREWALL_READINESS_SAFETY_FLAGS,
    }


def build_firewall_readiness_dashboard_record(
    *,
    summary: dict[str, Any],
    providers: dict[str, Any],
    permission: dict[str, Any],
    safety: dict[str, Any],
    rule_previews: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "firewall_readiness_dashboard",
        "panel": "cross_platform_firewall_provider_readiness",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "provider_count": int(summary.get("provider_count") or 0),
            "rule_preview_count": len(rule_previews),
            "rules_applied_count": 0,
            "warning_count": int(summary.get("warning_count") or 0),
        },
        "provider_rows": [
            {
                "provider_name": row.get("provider_name"),
                "status": row.get("status"),
                "provider_label": row.get("provider_label"),
            }
            for row in providers.get("providers") or []
            if isinstance(row, dict)
        ],
        "permission_status": str(permission.get("status") or "unknown"),
        "safety_status": str(safety.get("status") or "review_required"),
        "operator_review_required": True,
        "recommended_review": True,
        **FIREWALL_READINESS_SAFETY_FLAGS,
    }


def build_firewall_readiness_api_response(
    *,
    summary: dict[str, Any],
    platform_record: dict[str, Any],
    providers: dict[str, Any],
    permission: dict[str, Any],
    safety: dict[str, Any],
    rule_previews: list[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "firewall_readiness_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "platform": dict(platform_record),
        "provider_readiness": dict(providers),
        "permission_requirements": dict(permission),
        "rule_safety": dict(safety),
        "rule_previews": [dict(row) for row in rule_previews],
        "dashboard": dict(dashboard),
        **FIREWALL_READINESS_SAFETY_FLAGS,
    }


def deterministic_firewall_readiness_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _rule_previews(providers: dict[str, Any], *, rule_previews: list[dict[str, Any]] | None, generated_at: str) -> list[dict[str, Any]]:
    if rule_previews is not None:
        return [dict(row) for row in rule_previews if isinstance(row, dict)]
    return [
        build_firewall_rule_preview(provider_name=str(provider.get("provider_name") or ""), generated_at=generated_at)
        for provider in providers.get("providers") or []
        if isinstance(provider, dict)
    ]


def _nested_status(record: dict[str, Any] | None) -> str:
    if not isinstance(record, dict):
        return "unknown"
    summary = record.get("summary") if isinstance(record.get("summary"), dict) else {}
    dashboard = record.get("dashboard_status") if isinstance(record.get("dashboard_status"), dict) else {}
    return str(record.get("status") or summary.get("status") or dashboard.get("status") or "unknown")


def _operator_summary(status: str, platform_family: str) -> str:
    if status == "supported":
        return f"{platform_family} firewall readiness is supported for dry-run previews."
    if status == "degraded":
        return f"{platform_family} firewall readiness requires operator review before any future rule changes."
    if status == "unavailable":
        return "Firewall readiness is unavailable for the provided platform records."
    return "Firewall readiness is unknown and requires operator review."


def _digest(payload: Any) -> str:
    return sha256(deterministic_firewall_readiness_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "FIREWALL_READINESS_RECORD_VERSION",
    "FIREWALL_READINESS_SAFETY_FLAGS",
    "build_cross_platform_firewall_readiness_report",
    "build_firewall_permission_requirement_summary",
    "build_firewall_readiness_api_response",
    "build_firewall_readiness_dashboard_record",
    "build_firewall_rule_safety_summary",
    "deterministic_firewall_readiness_json",
    "summarize_firewall_readiness",
]
