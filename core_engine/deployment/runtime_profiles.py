from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


DEPLOYMENT_PROFILE_RECORD_VERSION = 1

DEPLOYMENT_PROFILE_NAMES = frozenset({"development", "staging", "production", "edge", "lab"})
SAFETY_MODES = frozenset({"dry-run", "review-required", "operator-approved-local-write"})
TELEMETRY_LEVELS = frozenset({"minimal", "standard", "enhanced"})
ORCHESTRATION_MODES = frozenset({"single-node", "master-worker", "orchestrator-managed"})
REMEDIATION_MODES = frozenset({"advisory-only", "review-queue"})
HISTORY_RETENTION_MODES = frozenset({"short", "balanced", "long", "edge-bounded", "lab-temporary"})
DEPLOYMENT_MODES = frozenset({"endpoint-agent", "master", "worker", "orchestrator", "edge", "lab"})
PLATFORM_FAMILIES = frozenset({"macos", "linux", "raspberry-pi-linux-arm", "windows"})

DEPLOYMENT_PROFILE_SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "administrator_controlled": True,
    "advisory": True,
    "advisory_first": True,
    "dry_run": True,
    "preview_only": True,
    "metadata_only": True,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "credentials_stored": False,
    "credential_handling_enabled": False,
    "automatic_changes": False,
    "service_installed": False,
    "service_started": False,
    "firewall_rules_changed": False,
    "packet_capture_enabled": False,
    "privilege_escalation_attempted": False,
    "admin_elevation_requested": False,
    "host_identifier_included": False,
    "username_included": False,
    "ip_address_included": False,
    "mac_address_included": False,
    "hardware_fingerprint_included": False,
    "dashboard_safe": True,
    "api_compatible": True,
    "export_safe": True,
}


def build_deployment_runtime_profile(
    profile_name: str,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a production-safe deployment runtime profile record."""
    name = _profile_name(profile_name)
    profile = _profile_templates()[name]
    timestamp = generated_at or _now()
    record = {
        "record_type": "deployment_runtime_profile",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "profile_id": f"deployment-profile-{name}",
        "profile_name": name,
        "generated_at": timestamp,
        "display_name": profile["display_name"],
        "description": profile["description"],
        "safety_mode": profile["safety_mode"],
        "telemetry_level": profile["telemetry_level"],
        "orchestration_mode": profile["orchestration_mode"],
        "remediation_mode": profile["remediation_mode"],
        "history_retention_mode": profile["history_retention_mode"],
        "resource_budget": _sorted_dict(profile["resource_budget"]),
        "platform_support": sorted(profile["platform_support"]),
        "deployment_modes": sorted(profile["deployment_modes"]),
        "capability_flags": _sorted_dict(profile["capability_flags"]),
        "configuration_readiness_flags": _sorted_dict(profile["configuration_readiness_flags"]),
        "advisory_notes": sorted(profile["advisory_notes"]),
        "operator_summary": profile["operator_summary"],
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }
    record["profile_digest"] = _digest(
        {
            "profile_name": record["profile_name"],
            "safety_mode": record["safety_mode"],
            "telemetry_level": record["telemetry_level"],
            "orchestration_mode": record["orchestration_mode"],
            "resource_budget": record["resource_budget"],
        }
    )
    return record


def development_runtime_profile(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_deployment_runtime_profile("development", generated_at=generated_at)


def staging_runtime_profile(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_deployment_runtime_profile("staging", generated_at=generated_at)


def production_runtime_profile(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_deployment_runtime_profile("production", generated_at=generated_at)


def edge_runtime_profile(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_deployment_runtime_profile("edge", generated_at=generated_at)


def lab_runtime_profile(*, generated_at: str | None = None) -> dict[str, Any]:
    return build_deployment_runtime_profile("lab", generated_at=generated_at)


def list_deployment_runtime_profiles(*, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    return [build_deployment_runtime_profile(name, generated_at=timestamp) for name in sorted(DEPLOYMENT_PROFILE_NAMES)]


def summarize_deployment_runtime_profile(profile: dict[str, Any]) -> dict[str, Any]:
    payload = deployment_runtime_profile_to_dict(profile)
    capability_flags = dict(payload.get("capability_flags") or {})
    readiness_flags = dict(payload.get("configuration_readiness_flags") or {})
    return {
        "record_type": "deployment_runtime_profile_summary",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "generated_at": payload["generated_at"],
        "profile_name": payload["profile_name"],
        "safety_mode": payload["safety_mode"],
        "telemetry_level": payload["telemetry_level"],
        "orchestration_mode": payload["orchestration_mode"],
        "remediation_mode": payload["remediation_mode"],
        "history_retention_mode": payload["history_retention_mode"],
        "platform_count": len(payload["platform_support"]),
        "deployment_mode_count": len(payload["deployment_modes"]),
        "enabled_capabilities": sorted(name for name, enabled in capability_flags.items() if enabled is True),
        "readiness_flag_count": len(readiness_flags),
        "operator_summary": payload["operator_summary"],
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def build_deployment_profile_catalog(*, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    profiles = list_deployment_runtime_profiles(generated_at=timestamp)
    summaries = [summarize_deployment_runtime_profile(profile) for profile in profiles]
    return {
        "record_type": "deployment_runtime_profile_catalog",
        "record_version": DEPLOYMENT_PROFILE_RECORD_VERSION,
        "catalog_id": "deployment-profile-catalog-" + _digest({"generated_at": timestamp, "profiles": [row["profile_name"] for row in profiles]})[:16],
        "generated_at": timestamp,
        "profile_count": len(profiles),
        "profiles": profiles,
        "summaries": summaries,
        "profile_names": [row["profile_name"] for row in profiles],
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def deployment_runtime_profile_to_dict(profile: dict[str, Any]) -> dict[str, Any]:
    payload = dict(profile or {})
    name = _profile_name(payload.get("profile_name") or payload.get("name") or "development")
    timestamp = str(payload.get("generated_at") or _now())
    resource_budget = _resource_budget(payload.get("resource_budget") or {})
    capability_flags = _bool_map(payload.get("capability_flags") or {})
    readiness_flags = _bool_map(payload.get("configuration_readiness_flags") or {})
    return {
        "record_type": str(payload.get("record_type") or "deployment_runtime_profile"),
        "record_version": int(payload.get("record_version") or DEPLOYMENT_PROFILE_RECORD_VERSION),
        "profile_id": str(payload.get("profile_id") or f"deployment-profile-{name}"),
        "profile_name": name,
        "generated_at": timestamp,
        "display_name": str(payload.get("display_name") or name.title()),
        "description": str(payload.get("description") or ""),
        "safety_mode": _choice(payload.get("safety_mode"), SAFETY_MODES, "dry-run"),
        "telemetry_level": _choice(payload.get("telemetry_level"), TELEMETRY_LEVELS, "standard"),
        "orchestration_mode": _choice(payload.get("orchestration_mode"), ORCHESTRATION_MODES, "single-node"),
        "remediation_mode": _choice(payload.get("remediation_mode"), REMEDIATION_MODES, "advisory-only"),
        "history_retention_mode": _choice(payload.get("history_retention_mode"), HISTORY_RETENTION_MODES, "balanced"),
        "resource_budget": resource_budget,
        "platform_support": _string_list(payload.get("platform_support") or []),
        "deployment_modes": _string_list(payload.get("deployment_modes") or []),
        "capability_flags": _sorted_dict(capability_flags),
        "configuration_readiness_flags": _sorted_dict(readiness_flags),
        "advisory_notes": _string_list(payload.get("advisory_notes") or []),
        "operator_summary": str(payload.get("operator_summary") or ""),
        "profile_digest": str(payload.get("profile_digest") or _digest({"profile_name": name, "resource_budget": resource_budget})),
        **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    }


def export_deployment_runtime_profile(profile: dict[str, Any]) -> str:
    return json.dumps(deployment_runtime_profile_to_dict(profile), sort_keys=True)


def _profile_templates() -> dict[str, dict[str, Any]]:
    all_platforms = sorted(PLATFORM_FAMILIES)
    return {
        "development": {
            "display_name": "Development",
            "description": "Local developer profile with dry-run defaults and lightweight retention.",
            "safety_mode": "dry-run",
            "telemetry_level": "standard",
            "orchestration_mode": "single-node",
            "remediation_mode": "advisory-only",
            "history_retention_mode": "short",
            "resource_budget": _budget(min_memory_mb=1024, recommended_memory_mb=2048, min_disk_mb=512, recommended_disk_mb=2048, cpu_profile="developer"),
            "platform_support": all_platforms,
            "deployment_modes": ["endpoint-agent", "lab"],
            "capability_flags": _flags(federation=False, service_preview=True, export_enabled=True, history_enabled=True, gateway_ready=False),
            "configuration_readiness_flags": _readiness(local_api_loopback=True, explicit_write_required=True, manual_service_review=True, redaction_required=True),
            "advisory_notes": ["dry_run_default", "developer_fixture_friendly", "manual_review_required_for_local_writes"],
            "operator_summary": "Development profile keeps local dry-run behavior and lightweight history for test fixtures.",
        },
        "staging": {
            "display_name": "Staging",
            "description": "Pre-production profile for validating deployment posture with stronger resource expectations.",
            "safety_mode": "review-required",
            "telemetry_level": "enhanced",
            "orchestration_mode": "orchestrator-managed",
            "remediation_mode": "review-queue",
            "history_retention_mode": "balanced",
            "resource_budget": _budget(min_memory_mb=2048, recommended_memory_mb=4096, min_disk_mb=2048, recommended_disk_mb=8192, cpu_profile="balanced"),
            "platform_support": all_platforms,
            "deployment_modes": ["endpoint-agent", "master", "worker", "orchestrator", "lab"],
            "capability_flags": _flags(federation=True, service_preview=True, export_enabled=True, history_enabled=True, gateway_ready=True),
            "configuration_readiness_flags": _readiness(local_api_loopback=True, explicit_write_required=True, manual_service_review=True, redaction_required=True),
            "advisory_notes": ["operator_review_required", "service_install_preview_only", "firewall_changes_disabled"],
            "operator_summary": "Staging profile validates multi-node deployment readiness without performing host changes.",
        },
        "production": {
            "display_name": "Production",
            "description": "Production-safe profile with explicit review gates and conservative automation controls.",
            "safety_mode": "review-required",
            "telemetry_level": "enhanced",
            "orchestration_mode": "orchestrator-managed",
            "remediation_mode": "review-queue",
            "history_retention_mode": "long",
            "resource_budget": _budget(min_memory_mb=4096, recommended_memory_mb=8192, min_disk_mb=8192, recommended_disk_mb=32768, cpu_profile="production"),
            "platform_support": all_platforms,
            "deployment_modes": ["endpoint-agent", "master", "worker", "orchestrator", "edge"],
            "capability_flags": _flags(federation=True, service_preview=True, export_enabled=True, history_enabled=True, gateway_ready=True),
            "configuration_readiness_flags": _readiness(local_api_loopback=True, explicit_write_required=True, manual_service_review=True, redaction_required=True),
            "advisory_notes": ["manual_operator_approval_required", "no_automatic_service_installation", "no_automatic_firewall_changes"],
            "operator_summary": "Production profile is deployment-ready only after operator review; destructive automation remains disabled.",
        },
        "edge": {
            "display_name": "Edge",
            "description": "Raspberry Pi and edge-device profile with bounded telemetry and retention budgets.",
            "safety_mode": "dry-run",
            "telemetry_level": "minimal",
            "orchestration_mode": "master-worker",
            "remediation_mode": "advisory-only",
            "history_retention_mode": "edge-bounded",
            "resource_budget": _budget(min_memory_mb=512, recommended_memory_mb=1024, min_disk_mb=512, recommended_disk_mb=4096, cpu_profile="edge"),
            "platform_support": ["linux", "raspberry-pi-linux-arm"],
            "deployment_modes": ["edge", "worker", "endpoint-agent"],
            "capability_flags": _flags(federation=True, service_preview=True, export_enabled=True, history_enabled=True, gateway_ready=True),
            "configuration_readiness_flags": _readiness(local_api_loopback=True, explicit_write_required=True, manual_service_review=True, redaction_required=True),
            "advisory_notes": ["edge_resource_budget_required", "bounded_history_retention", "manual_capture_permission_review_required"],
            "operator_summary": "Edge profile favors bounded metadata and Raspberry Pi compatible resource settings.",
        },
        "lab": {
            "display_name": "Lab",
            "description": "Isolated lab profile for sanitized validation fixtures and temporary local testing.",
            "safety_mode": "dry-run",
            "telemetry_level": "standard",
            "orchestration_mode": "single-node",
            "remediation_mode": "advisory-only",
            "history_retention_mode": "lab-temporary",
            "resource_budget": _budget(min_memory_mb=1024, recommended_memory_mb=2048, min_disk_mb=512, recommended_disk_mb=4096, cpu_profile="lab"),
            "platform_support": all_platforms,
            "deployment_modes": ["lab", "endpoint-agent"],
            "capability_flags": _flags(federation=False, service_preview=False, export_enabled=True, history_enabled=True, gateway_ready=False),
            "configuration_readiness_flags": _readiness(local_api_loopback=True, explicit_write_required=True, manual_service_review=True, redaction_required=True),
            "advisory_notes": ["sanitized_fixtures_only", "temporary_records_expected", "no_service_install_preview_required"],
            "operator_summary": "Lab profile supports isolated dry-run validation with sanitized temporary records.",
        },
    }


def _budget(
    *,
    min_memory_mb: int,
    recommended_memory_mb: int,
    min_disk_mb: int,
    recommended_disk_mb: int,
    cpu_profile: str,
) -> dict[str, Any]:
    return {
        "min_memory_mb": min_memory_mb,
        "recommended_memory_mb": recommended_memory_mb,
        "min_disk_mb": min_disk_mb,
        "recommended_disk_mb": recommended_disk_mb,
        "cpu_profile": cpu_profile,
        "bounded_history": True,
        "resource_review_required": True,
    }


def _flags(
    *,
    federation: bool,
    service_preview: bool,
    export_enabled: bool,
    history_enabled: bool,
    gateway_ready: bool,
) -> dict[str, bool]:
    return {
        "telemetry_enabled": True,
        "federation_enabled": federation,
        "service_lifecycle_preview_enabled": service_preview,
        "export_enabled": export_enabled,
        "historical_intelligence_enabled": history_enabled,
        "gateway_readiness_checks_enabled": gateway_ready,
        "automatic_remediation_enabled": False,
        "automatic_firewall_changes_enabled": False,
        "credential_storage_enabled": False,
    }


def _readiness(
    *,
    local_api_loopback: bool,
    explicit_write_required: bool,
    manual_service_review: bool,
    redaction_required: bool,
) -> dict[str, bool]:
    return {
        "local_api_loopback": local_api_loopback,
        "explicit_write_required": explicit_write_required,
        "manual_service_review": manual_service_review,
        "export_redaction_required": redaction_required,
        "dry_run_default": True,
        "operator_review_required": True,
    }


def _profile_name(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    aliases = {"dev": "development", "prod": "production", "raspberry-pi": "edge", "edge-device": "edge"}
    normalized = aliases.get(normalized, normalized)
    if normalized not in DEPLOYMENT_PROFILE_NAMES:
        raise ValueError(f"profile_name must be one of: {', '.join(sorted(DEPLOYMENT_PROFILE_NAMES))}")
    return normalized


def _resource_budget(value: dict[str, Any]) -> dict[str, Any]:
    return {
        "min_memory_mb": _int_at_least(value.get("min_memory_mb"), 0),
        "recommended_memory_mb": _int_at_least(value.get("recommended_memory_mb"), 0),
        "min_disk_mb": _int_at_least(value.get("min_disk_mb"), 0),
        "recommended_disk_mb": _int_at_least(value.get("recommended_disk_mb"), 0),
        "cpu_profile": str(value.get("cpu_profile") or "unknown"),
        "bounded_history": bool(value.get("bounded_history", True)),
        "resource_review_required": bool(value.get("resource_review_required", True)),
    }


def _bool_map(value: dict[str, Any]) -> dict[str, bool]:
    return {str(key): bool(item) for key, item in dict(value or {}).items()}


def _choice(value: Any, choices: frozenset[str], default: str) -> str:
    normalized = str(value or default).strip().lower()
    return normalized if normalized in choices else default


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _int_at_least(value: Any, minimum: int) -> int:
    if isinstance(value, bool):
        return minimum
    try:
        return max(int(value), minimum)
    except (TypeError, ValueError):
        return minimum


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
