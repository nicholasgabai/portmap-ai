from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.deployment.runtime_profiles import (
    DEPLOYMENT_MODES,
    DEPLOYMENT_PROFILE_RECORD_VERSION,
    DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    build_deployment_runtime_profile,
    deployment_runtime_profile_to_dict,
)
from core_engine.platform.runtime_detection import build_platform_runtime_record


PROFILE_VALIDATION_STATES = frozenset({"supported", "degraded", "unsupported"})


def validate_deployment_runtime_profile(
    profile: dict[str, Any] | str,
    *,
    platform_record: dict[str, Any] | None = None,
    platform_info: dict[str, Any] | None = None,
    operating_system: str | None = None,
    available_memory_mb: int | None = None,
    available_disk_mb: int | None = None,
    packet_capture_readiness: dict[str, Any] | str | None = None,
    firewall_provider_readiness: dict[str, Any] | str | None = None,
    deployment_mode: str = "endpoint-agent",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Validate deployment profile compatibility without touching host state."""
    timestamp = generated_at or _now()
    payload = _profile(profile, generated_at=timestamp)
    platform_payload = platform_record or _platform_record(platform_info=platform_info, operating_system=operating_system, generated_at=timestamp)
    platform_family = str(platform_payload.get("platform_family") or "unknown")
    mode = _deployment_mode(deployment_mode)
    checks = [
        build_profile_compatibility_check(
            "operating_system",
            _os_state(platform_family, payload),
            _os_summary(platform_family, payload),
            details={
                "platform_family": platform_family,
                "supported_platforms": payload["platform_support"],
            },
            generated_at=timestamp,
        ),
        build_profile_compatibility_check(
            "memory",
            _budget_state(available_memory_mb, payload["resource_budget"], "memory"),
            _budget_summary(available_memory_mb, payload["resource_budget"], "memory"),
            details={
                "available_memory_mb": _int_or_none(available_memory_mb),
                "min_memory_mb": payload["resource_budget"]["min_memory_mb"],
                "recommended_memory_mb": payload["resource_budget"]["recommended_memory_mb"],
            },
            generated_at=timestamp,
        ),
        build_profile_compatibility_check(
            "disk",
            _budget_state(available_disk_mb, payload["resource_budget"], "disk"),
            _budget_summary(available_disk_mb, payload["resource_budget"], "disk"),
            details={
                "available_disk_mb": _int_or_none(available_disk_mb),
                "min_disk_mb": payload["resource_budget"]["min_disk_mb"],
                "recommended_disk_mb": payload["resource_budget"]["recommended_disk_mb"],
            },
            generated_at=timestamp,
        ),
        build_profile_compatibility_check(
            "packet_capture_readiness",
            _readiness_state(packet_capture_readiness, optional=payload["telemetry_level"] == "minimal"),
            _readiness_summary("packet capture", packet_capture_readiness, optional=payload["telemetry_level"] == "minimal"),
            details={
                "readiness_status": _nested_status(packet_capture_readiness),
                "telemetry_level": payload["telemetry_level"],
                "packet_capture_enabled": False,
            },
            generated_at=timestamp,
        ),
        build_profile_compatibility_check(
            "firewall_provider_readiness",
            _firewall_state(firewall_provider_readiness),
            _readiness_summary("firewall provider", firewall_provider_readiness, optional=True),
            details={
                "readiness_status": _nested_status(firewall_provider_readiness),
                "firewall_rules_changed": False,
                "preview_only": True,
            },
            generated_at=timestamp,
        ),
        build_profile_compatibility_check(
            "deployment_mode",
            _deployment_mode_state(mode, payload),
            _deployment_mode_summary(mode, payload),
            details={
                "deployment_mode": mode,
                "supported_deployment_modes": payload["deployment_modes"],
            },
            generated_at=timestamp,
        ),
    ]
    state = summarize_profile_compatibility_checks(checks)
    advisory = build_profile_advisory_summary(profile=payload, checks=checks, state=state, generated_at=timestamp)
    export = build_profile_validation_export_dict(profile=payload, platform_record=platform_payload, checks=checks, state=state, advisory=advisory, generated_at=timestamp)
    return {
        "record_type": "deployment_runtime_profile_validation",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "validation_id": "deployment-profile-validation-" + _digest(
            {
                "generated_at": timestamp,
                "profile_name": payload["profile_name"],
                "platform_family": platform_family,
                "deployment_mode": mode,
                "checks": checks,
            }
        )[:16],
        "generated_at": timestamp,
        "profile": payload,
        "platform": _platform_export(platform_payload),
        "deployment_mode": mode,
        "state": state["state"],
        "summary": state,
        "checks": sorted(checks, key=lambda item: str(item.get("check_name") or "")),
        "operator_advisory": advisory,
        "export": export,
        "dashboard_status": build_profile_validation_dashboard_record(profile=payload, state=state, checks=checks, generated_at=timestamp),
        "api_status": build_profile_validation_api_response(profile=payload, state=state, advisory=advisory, generated_at=timestamp),
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def build_profile_compatibility_check(
    check_name: str,
    state: str,
    operator_summary: str,
    *,
    details: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    normalized = _state(state)
    return {
        "record_type": "deployment_profile_compatibility_check",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "check_name": str(check_name),
        "state": normalized,
        "operator_summary": str(operator_summary),
        "details": _sorted_dict(dict(details or {})),
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def summarize_profile_compatibility_checks(checks: list[dict[str, Any]]) -> dict[str, Any]:
    states = [str(row.get("state") or "degraded") for row in checks]
    state = "supported"
    if "unsupported" in states:
        state = "unsupported"
    elif "degraded" in states:
        state = "degraded"
    counts = {name: states.count(name) for name in sorted(PROFILE_VALIDATION_STATES)}
    return {
        "record_type": "deployment_profile_compatibility_summary",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "state": state,
        "check_count": len(checks),
        "supported_count": counts["supported"],
        "degraded_count": counts["degraded"],
        "unsupported_count": counts["unsupported"],
        "operator_review_required": state != "supported",
        "operator_summary": _state_summary(state),
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def build_profile_advisory_summary(
    *,
    profile: dict[str, Any],
    checks: list[dict[str, Any]],
    state: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    items = [
        {
            "check_name": row["check_name"],
            "state": row["state"],
            "recommendation": _recommendation(row["check_name"], row["state"]),
        }
        for row in checks
        if row.get("state") != "supported"
    ]
    if not items:
        items.append(
            {
                "check_name": "deployment_profile",
                "state": "supported",
                "recommendation": "Profile is compatible with the supplied sanitized deployment inputs.",
            }
        )
    return {
        "record_type": "deployment_profile_advisory_summary",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "profile_name": profile["profile_name"],
        "state": state["state"],
        "advisory_count": len(items),
        "items": items,
        "operator_review_required": state["state"] != "supported",
        "operator_summary": _state_summary(state["state"]),
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def build_profile_validation_export_dict(
    *,
    profile: dict[str, Any],
    platform_record: dict[str, Any],
    checks: list[dict[str, Any]],
    state: dict[str, Any],
    advisory: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "deployment_profile_validation_export",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "profile_name": profile["profile_name"],
        "platform_family": str(platform_record.get("platform_family") or "unknown"),
        "state": state["state"],
        "check_states": {row["check_name"]: row["state"] for row in sorted(checks, key=lambda item: item["check_name"])},
        "operator_review_required": advisory["operator_review_required"],
        "advisory_count": advisory["advisory_count"],
        "profile_digest": profile["profile_digest"],
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def build_profile_validation_dashboard_record(
    *,
    profile: dict[str, Any],
    state: dict[str, Any],
    checks: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "deployment_profile_validation_dashboard",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "title": "Production Runtime Profile",
        "profile_name": profile["profile_name"],
        "state": state["state"],
        "check_count": len(checks),
        "operator_review_required": state["operator_review_required"],
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def build_profile_validation_api_response(
    *,
    profile: dict[str, Any],
    state: dict[str, Any],
    advisory: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "deployment_profile_validation_api_response",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "profile": profile["profile_name"],
        "state": state["state"],
        "advisory": advisory,
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def _profile(profile: dict[str, Any] | str, *, generated_at: str) -> dict[str, Any]:
    if isinstance(profile, str):
        return build_deployment_runtime_profile(profile, generated_at=generated_at)
    return deployment_runtime_profile_to_dict(profile)


def _platform_record(
    *,
    platform_info: dict[str, Any] | None,
    operating_system: str | None,
    generated_at: str,
) -> dict[str, Any]:
    if platform_info:
        return build_platform_runtime_record(platform_info=platform_info, generated_at=generated_at)
    if operating_system:
        return build_platform_runtime_record(system=operating_system, generated_at=generated_at)
    return build_platform_runtime_record(system="Unknown", release="sanitized-release", machine="unknown", python_version="3.11.5", generated_at=generated_at)


def _platform_export(platform_record: dict[str, Any]) -> dict[str, Any]:
    return {
        "platform_family": str(platform_record.get("platform_family") or "unknown"),
        "status": str(platform_record.get("status") or "unknown"),
        "architecture": {
            "normalized": str((platform_record.get("architecture") or {}).get("normalized") or "unknown"),
            "is_arm": bool((platform_record.get("architecture") or {}).get("is_arm", False)),
            "is_64_bit": bool((platform_record.get("architecture") or {}).get("is_64_bit", False)),
        },
        "python": {
            "supported": bool((platform_record.get("python") or {}).get("supported", False)),
            "requires_python": str((platform_record.get("python") or {}).get("requires_python") or ">=3.11"),
        },
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def _os_state(platform_family: str, profile: dict[str, Any]) -> str:
    if platform_family in profile["platform_support"]:
        return "supported"
    return "unsupported" if platform_family != "unknown" else "degraded"


def _os_summary(platform_family: str, profile: dict[str, Any]) -> str:
    if platform_family in profile["platform_support"]:
        return f"{platform_family} is supported by the {profile['profile_name']} profile."
    if platform_family == "unknown":
        return "Platform family is unknown; operator review is required."
    return f"{platform_family} is not supported by the {profile['profile_name']} profile."


def _budget_state(available: int | None, budget: dict[str, Any], kind: str) -> str:
    if available is None:
        return "degraded"
    prefix = "memory" if kind == "memory" else "disk"
    minimum = int(budget.get(f"min_{prefix}_mb") or 0)
    recommended = int(budget.get(f"recommended_{prefix}_mb") or minimum)
    if available < minimum:
        return "unsupported"
    if available < recommended:
        return "degraded"
    return "supported"


def _budget_summary(available: int | None, budget: dict[str, Any], kind: str) -> str:
    label = "memory" if kind == "memory" else "disk"
    if available is None:
        return f"Available {label} was not supplied; compatibility is degraded pending operator review."
    minimum = int(budget.get(f"min_{label}_mb") or 0)
    recommended = int(budget.get(f"recommended_{label}_mb") or minimum)
    if available < minimum:
        return f"Available {label} is below the minimum profile budget."
    if available < recommended:
        return f"Available {label} meets the minimum but is below the recommended profile budget."
    return f"Available {label} meets the recommended profile budget."


def _readiness_state(value: dict[str, Any] | str | None, *, optional: bool) -> str:
    status = _nested_status(value)
    if status in {"supported", "ready", "ok", "compatible"}:
        return "supported"
    if status in {"unsafe", "unavailable", "unsupported"}:
        return "unsupported" if not optional else "degraded"
    if status in {"degraded", "review_required", "unknown"}:
        return "degraded"
    return "degraded"


def _firewall_state(value: dict[str, Any] | str | None) -> str:
    status = _nested_status(value)
    if status in {"supported", "ready", "ok", "compatible"}:
        return "supported"
    if status in {"unsafe"}:
        return "unsupported"
    return "degraded"


def _readiness_summary(label: str, value: dict[str, Any] | str | None, *, optional: bool) -> str:
    status = _nested_status(value)
    if status in {"supported", "ready", "ok", "compatible"}:
        return f"{label.title()} readiness is available for preview validation."
    if optional:
        return f"{label.title()} readiness is degraded or unavailable, but this profile treats it as operator-reviewable."
    return f"{label.title()} readiness requires operator review before deployment."


def _deployment_mode(value: str) -> str:
    normalized = str(value or "endpoint-agent").strip().lower().replace("_", "-")
    return normalized if normalized in DEPLOYMENT_MODES else "endpoint-agent"


def _deployment_mode_state(mode: str, profile: dict[str, Any]) -> str:
    return "supported" if mode in profile["deployment_modes"] else "unsupported"


def _deployment_mode_summary(mode: str, profile: dict[str, Any]) -> str:
    if mode in profile["deployment_modes"]:
        return f"{mode} deployment mode is supported by the {profile['profile_name']} profile."
    return f"{mode} deployment mode is not supported by the {profile['profile_name']} profile."


def _nested_status(record: dict[str, Any] | str | None) -> str:
    if isinstance(record, str):
        return record.strip().lower() or "unknown"
    if not isinstance(record, dict):
        return "unknown"
    for key in ("state", "status"):
        if record.get(key):
            return str(record[key]).strip().lower()
    for key in ("summary", "dashboard_status", "api_status"):
        nested = record.get(key)
        if isinstance(nested, dict):
            status = _nested_status(nested)
            if status != "unknown":
                return status
    return "unknown"


def _state(value: str) -> str:
    normalized = str(value or "degraded").strip().lower()
    return normalized if normalized in PROFILE_VALIDATION_STATES else "degraded"


def _state_summary(state: str) -> str:
    if state == "supported":
        return "Deployment profile is supported for the supplied sanitized compatibility inputs."
    if state == "unsupported":
        return "Deployment profile has unsupported compatibility checks and should not be used without changing inputs."
    return "Deployment profile is degraded and requires operator review before use."


def _recommendation(check_name: str, state: str) -> str:
    if state == "unsupported":
        return f"Resolve unsupported {check_name} input before selecting this deployment profile."
    if state == "degraded":
        return f"Review degraded {check_name} input and confirm it is acceptable for this deployment profile."
    return f"{check_name} is compatible."


def _int_or_none(value: int | None) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _sorted_dict(value: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key in sorted(value):
        item = value[key]
        if isinstance(item, dict):
            result[str(key)] = _sorted_dict(item)
        elif isinstance(item, list):
            result[str(key)] = list(item)
        else:
            result[str(key)] = item
    return result


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
