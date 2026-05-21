from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.installers.service_templates import (
    generate_service_templates,
    summarize_service_template_result,
)
from core_engine.policy.review_queue import ReviewQueue
from core_engine.policy.review_store import PersistentReviewStore
from core_engine.runtime.health import (
    build_runtime_health_summary,
    export_readiness_health_check,
    review_queue_health_check,
    storage_health_check,
)
from core_engine.runtime.profiles import (
    RuntimeProfile,
    default_runtime_profile,
    merge_runtime_profiles,
    summarize_runtime_profile,
    validate_runtime_profile,
)
from core_engine.runtime.session import RuntimeSessionManager
from core_engine.runtime.session_state import create_runtime_session, summarize_runtime_session
from core_engine.storage.repositories import LocalStorageRepository


SERVICE_MODE_SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
    "dry_run": True,
    "preview_only": True,
    "install_executed": False,
    "installation_performed": False,
    "service_enabled": False,
    "service_started": False,
    "service_stopped": False,
    "registry_changed": False,
    "privilege_escalation": False,
}

DEFAULT_SERVICE_PLATFORMS = ("systemd", "windows")
DEFAULT_SERVICE_COMPONENTS = (
    "runtime_session",
    "runtime_profile",
    "storage",
    "review_queue",
    "export_bundle",
    "runtime_health",
    "service_templates",
)


def build_service_mode_definition(
    *,
    service_id: str = "service.portmap.runtime",
    name: str = "portmap-runtime",
    display_name: str = "PortMap Runtime",
    description: str = "Runs the local PortMap runtime workflow after operator installation.",
    command: list[str] | None = None,
    working_directory: str = "<portmap-app-dir>",
    environment_file: str = "<portmap-env-file>",
    user: str = "<portmap-service-user>",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a sanitized service definition for dry-run service previews."""
    return {
        "service_id": str(service_id),
        "name": str(name),
        "display_name": str(display_name),
        "description": str(description),
        "command": list(["<portmap-command>", "runtime", "status", "--output", "json"] if command is None else command),
        "working_directory": str(working_directory),
        "environment_file": str(environment_file),
        "user": str(user),
        "metadata": {
            "service_mode": "preview",
            "manual_operator_review_required": True,
            **dict(metadata or {}),
        },
    }


def build_service_template_compatibility(
    definition: dict[str, Any] | None = None,
    *,
    platforms: list[str] | tuple[str, ...] | None = None,
) -> dict[str, Any]:
    requested = list(platforms or DEFAULT_SERVICE_PLATFORMS)
    result = generate_service_templates(definition or build_service_mode_definition(), platforms=requested)
    summary = summarize_service_template_result(result)
    status = "compatible" if result.get("ok") else "review_required"
    return {
        "status": status,
        "compatible": bool(result.get("ok")),
        "platforms": requested,
        "service_id": summary["service_id"],
        "summary": summary,
        "template_result": result,
        "errors": list(result.get("errors") or []),
        "warnings": list(result.get("warnings") or []),
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def build_service_command_previews(template_compatibility: dict[str, Any]) -> dict[str, Any]:
    template_result = dict(template_compatibility.get("template_result") or {})
    previews: dict[str, dict[str, Any]] = {}
    for platform, item in sorted(dict(template_result.get("templates") or {}).items()):
        if not isinstance(item, dict):
            continue
        previews[str(platform)] = {
            "platform": str(platform),
            "status": str(item.get("status") or "invalid"),
            "template_id": str(item.get("template_id") or ""),
            "template_text": str(item.get("template_text") or ""),
            "line_count": int(item.get("line_count") or 0),
            "manual_review_required": True,
            **SERVICE_MODE_SAFETY_FLAGS,
        }
    return {
        "preview_count": len(previews),
        "previews": previews,
        "manual_review_required": True,
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def build_manual_operator_checklist(*, platforms: list[str] | tuple[str, ...] | None = None) -> list[dict[str, Any]]:
    requested = list(platforms or DEFAULT_SERVICE_PLATFORMS)
    steps = [
        ("review_profile", "Review the runtime profile summary and confirm service-preview mode."),
        ("review_storage", "Confirm the local storage location placeholder resolves to an operator-approved location."),
        ("review_exports", "Confirm export and review queues are ready for local evidence retention."),
        ("review_templates", "Inspect generated service template text before using it outside PortMap-AI."),
        ("manual_install", "Install, enable, or start any service manually outside this dry-run preview."),
    ]
    if "windows" in requested:
        steps.append(("windows_review", "Review Windows service command text manually before any operator-run command."))
    if "systemd" in requested:
        steps.append(("systemd_review", "Review systemd unit text manually before any operator-run command."))
    return [
        {
            "step_id": step_id,
            "summary": summary,
            "required": True,
            **SERVICE_MODE_SAFETY_FLAGS,
        }
        for step_id, summary in steps
    ]


def build_service_mode_preflight(
    *,
    profile: RuntimeProfile | dict[str, Any] | None = None,
    repository: LocalStorageRepository | None = None,
    review_store: PersistentReviewStore | ReviewQueue | None = None,
    export_bundle: dict[str, Any] | None = None,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    runtime_profile, profile_validation = _safe_service_preview_profile(profile, generated_at=generated_at)
    storage_check = storage_health_check(repository)
    review_check = review_queue_health_check(review_store)
    export_check = export_readiness_health_check(repository=repository, review_store=review_store, export_bundle=export_bundle)
    checks = [
        _preflight_check(
            "profile_validation",
            "ok" if profile_validation["ok"] else "blocked",
            "info" if profile_validation["ok"] else "high",
            "Runtime profile validated for service-preview use.",
            profile_validation,
        ),
        _preflight_check(
            "dry_run_preview",
            "ok",
            "info",
            "Service-mode readiness is a dry-run preview only.",
            {
                "installation_performed": False,
                "service_enabled": False,
                "service_started": False,
                "privilege_escalation": False,
            },
        ),
        _from_health_check(storage_check),
        _from_health_check(review_check),
        _from_health_check(export_check),
    ]
    return {
        "status": _preflight_status(checks),
        "generated_at": generated_at or _now(),
        "edge_device": bool(edge_device),
        "profile_validation": profile_validation,
        "checks": checks,
        "summary": _summarize_checks(checks),
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def build_service_mode_readiness(
    *,
    profile: RuntimeProfile | dict[str, Any] | None = None,
    repository: LocalStorageRepository | None = None,
    review_store: PersistentReviewStore | ReviewQueue | None = None,
    scheduler: Any | dict[str, Any] | None = None,
    event_queue: Any | list[Any] | None = None,
    dashboard_provider: Any | dict[str, Any] | None = None,
    sessions: RuntimeSessionManager | list[Any] | None = None,
    export_bundle: dict[str, Any] | None = None,
    service_definition: dict[str, Any] | None = None,
    platforms: list[str] | tuple[str, ...] | None = None,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    runtime_profile, profile_validation = _safe_service_preview_profile(profile, generated_at=timestamp)
    profile_summary = summarize_runtime_profile(runtime_profile)
    profile_summary["validation"] = profile_validation
    session = create_runtime_session(
        session_id=_stable_id("runtime-session", profile_summary["profile_id"], timestamp),
        mode="service-preview",
        started_at=timestamp,
        enabled_components=DEFAULT_SERVICE_COMPONENTS,
        metadata={"service_mode": "readiness-preview"},
    )
    session_summary = summarize_runtime_session(session)
    health = build_runtime_health_summary(
        profile=runtime_profile,
        scheduler=scheduler,
        event_queue=event_queue,
        repository=repository,
        review_store=review_store,
        dashboard_provider=dashboard_provider,
        sessions=sessions if sessions is not None else [session],
        export_bundle=export_bundle,
        edge_device=edge_device,
        generated_at=timestamp,
    )
    template_compatibility = build_service_template_compatibility(service_definition, platforms=platforms)
    command_previews = build_service_command_previews(template_compatibility)
    preflight = build_service_mode_preflight(
        profile=runtime_profile,
        repository=repository,
        review_store=review_store,
        export_bundle=export_bundle,
        edge_device=edge_device,
        generated_at=timestamp,
    )
    checks = [
        *list(preflight["checks"]),
        _preflight_check(
            "service_template_compatibility",
            "ok" if template_compatibility["compatible"] else "blocked",
            "info" if template_compatibility["compatible"] else "high",
            "Service lifecycle templates were generated for operator review.",
            {
                "service_id": template_compatibility["service_id"],
                "platforms": template_compatibility["platforms"],
                "errors": template_compatibility["errors"],
            },
        ),
    ]
    summary = _readiness_summary(checks, command_previews, health)
    status = "ready" if summary["blocked_count"] == 0 and health["status"] == "ok" else "review_required"
    return {
        "readiness_id": _stable_id("service-readiness", profile_summary["profile_id"], template_compatibility["service_id"], timestamp),
        "status": status,
        "generated_at": timestamp,
        "profile_summary": profile_summary,
        "runtime_session": session_summary,
        "health_summary": health,
        "preflight": {**preflight, "checks": checks, "summary": _summarize_checks(checks)},
        "template_compatibility": template_compatibility,
        "command_previews": command_previews,
        "manual_operator_checklist": build_manual_operator_checklist(platforms=platforms),
        "summary": summary,
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def summarize_service_mode_readiness(readiness: dict[str, Any]) -> dict[str, Any]:
    checks = list(((readiness.get("preflight") or {}).get("checks") or []))
    template_summary = (((readiness.get("template_compatibility") or {}).get("summary")) or {})
    return {
        "readiness_id": str(readiness.get("readiness_id") or ""),
        "status": str(readiness.get("status") or "unknown"),
        "generated_at": str(readiness.get("generated_at") or ""),
        "check_summary": _summarize_checks(checks),
        "template_count": int(template_summary.get("template_count") or 0),
        "manual_checklist_count": len(readiness.get("manual_operator_checklist") or []),
        "recommended_review": str(readiness.get("status") or "") != "ready",
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def _service_preview_profile(profile: RuntimeProfile | dict[str, Any] | None, *, generated_at: str | None) -> RuntimeProfile:
    base = default_runtime_profile(generated_at=generated_at)
    override = {"runtime_mode": "service-preview"}
    if profile is None:
        override.update(
            {
                "profile_id": "runtime-service-preview",
                "name": "Service Preview Runtime",
                "description": "Dry-run service-mode readiness profile for local operator review.",
                "profile_type": "operator",
            }
        )
        return merge_runtime_profiles(base, override)
    return merge_runtime_profiles(profile, override)


def _safe_service_preview_profile(
    profile: RuntimeProfile | dict[str, Any] | None,
    *,
    generated_at: str | None,
) -> tuple[RuntimeProfile, dict[str, Any]]:
    try:
        runtime_profile = _service_preview_profile(profile, generated_at=generated_at)
        return runtime_profile, validate_runtime_profile(runtime_profile)
    except Exception as exc:
        fallback = _service_preview_profile(None, generated_at=generated_at)
        return fallback, {
            "ok": False,
            "status": "invalid",
            "errors": [str(exc)],
            "warnings": [],
            **SERVICE_MODE_SAFETY_FLAGS,
        }


def _from_health_check(check: dict[str, Any]) -> dict[str, Any]:
    status = str(check.get("status") or "unknown")
    return _preflight_check(
        str(check.get("name") or "health_check"),
        "ok" if status in {"ok", "unavailable"} else "review_required",
        str(check.get("severity") or "info"),
        str(check.get("message") or ""),
        dict(check.get("details") or {}),
    )


def _preflight_check(
    name: str,
    status: str,
    severity: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "name": str(name),
        "status": str(status),
        "severity": str(severity),
        "message": str(message),
        "details": dict(details or {}),
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def _preflight_status(checks: list[dict[str, Any]]) -> str:
    if any(check.get("status") == "blocked" or check.get("severity") in {"high", "critical"} for check in checks):
        return "blocked"
    if any(check.get("status") == "review_required" for check in checks):
        return "review_required"
    return "ok"


def _summarize_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    by_status: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for check in checks:
        status = str(check.get("status") or "unknown")
        severity = str(check.get("severity") or "info")
        by_status[status] = by_status.get(status, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {
        "check_count": len(checks),
        "by_status": dict(sorted(by_status.items())),
        "by_severity": dict(sorted(by_severity.items())),
        "blocked_count": by_status.get("blocked", 0),
        "review_required_count": by_status.get("review_required", 0),
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def _readiness_summary(
    checks: list[dict[str, Any]],
    command_previews: dict[str, Any],
    health_summary: dict[str, Any],
) -> dict[str, Any]:
    check_summary = _summarize_checks(checks)
    return {
        **check_summary,
        "preview_count": int(command_previews.get("preview_count") or 0),
        "health_status": str(health_summary.get("status") or "unknown"),
        "manual_operator_review_required": True,
        **SERVICE_MODE_SAFETY_FLAGS,
    }


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
