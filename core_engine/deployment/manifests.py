from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.deployment.node_profiles import (
    NODE_PROFILE_SAFETY_FLAGS,
    build_node_deployment_profile,
    node_deployment_profile_to_dict,
)
from core_engine.deployment.runtime_profiles import (
    build_deployment_runtime_profile,
    deployment_runtime_profile_to_dict,
)
from core_engine.deployment.service_providers import build_service_provider_readiness


DEPLOYMENT_MANIFEST_RECORD_VERSION = 1

DEPLOYMENT_MANIFEST_MODES = frozenset({"standalone", "orchestrator", "worker", "edge", "lab", "production_preview"})
DEPLOYMENT_READINESS_STATES = frozenset({"supported", "degraded", "unsupported"})

DEPLOYMENT_MANIFEST_SAFETY_FLAGS = {
    **NODE_PROFILE_SAFETY_FLAGS,
    "manifest_only": True,
    "deployment_action_performed": False,
    "deployment_config_written": False,
    "deployment_package_created": False,
    "installer_created": False,
    "credentials_generated": False,
    "real_paths_included": False,
    "private_runtime_identifiers_included": False,
}


def build_deployment_manifest(
    deployment_mode: str,
    *,
    runtime_profile: dict[str, Any] | str | None = None,
    node_profile: dict[str, Any] | str | None = None,
    service_provider: dict[str, Any] | str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a sanitized deployment manifest without performing deployment actions."""
    timestamp = generated_at or _now()
    mode = _manifest_mode(deployment_mode)
    template = _manifest_templates()[mode]
    runtime = _runtime_profile(runtime_profile or template["runtime_profile"], generated_at=timestamp)
    node = _node_profile(node_profile or template["node_profile"], generated_at=timestamp)
    service = _service_provider(service_provider or template["service_provider"], mode=mode, generated_at=timestamp)
    readiness = build_deployment_readiness_summary(
        deployment_mode=mode,
        runtime_profile=runtime,
        node_profile=node,
        service_provider=service,
        generated_at=timestamp,
    )
    manifest = {
        "record_type": "deployment_manifest",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "manifest_id": "deployment-manifest-" + _digest(
            {
                "deployment_mode": mode,
                "runtime_profile": runtime["profile_name"],
                "node_profile": node["profile_name"],
                "service_provider": service["provider"],
                "generated_at": timestamp,
            }
        )[:16],
        "generated_at": timestamp,
        "deployment_mode": mode,
        "runtime_profile": runtime,
        "node_profile": node,
        "supported_platforms": _supported_platforms(runtime, node),
        "telemetry_mode": template["telemetry_mode"],
        "orchestration_mode": runtime["orchestration_mode"],
        "service_provider_mode": service["provider"],
        "retention_policy_mode": runtime["history_retention_mode"],
        "deployment_readiness": readiness,
        "required_components": sorted(template["required_components"]),
        "optional_components": sorted(template["optional_components"]),
        "export_paths": build_manifest_export_paths(mode, generated_at=timestamp),
        "backup_recommendations": build_backup_recommendations(mode, runtime_profile=runtime, generated_at=timestamp),
        "advisory_notes": build_manifest_advisory_notes(mode, readiness=readiness, runtime_profile=runtime, service_provider=service),
        "dashboard_status": build_deployment_manifest_dashboard_record(mode=mode, readiness=readiness, generated_at=timestamp),
        "api_status": build_deployment_manifest_api_response(mode=mode, readiness=readiness, generated_at=timestamp),
        "export": build_deployment_manifest_export_dict(mode=mode, readiness=readiness, runtime_profile=runtime, node_profile=node, service_provider=service, generated_at=timestamp),
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }
    return manifest


def build_deployment_manifest_catalog(*, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    manifests = [build_deployment_manifest(mode, generated_at=timestamp) for mode in sorted(DEPLOYMENT_MANIFEST_MODES)]
    states = [row["deployment_readiness"]["state"] for row in manifests]
    return {
        "record_type": "deployment_manifest_catalog",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "catalog_id": "deployment-manifest-catalog-" + _digest({"generated_at": timestamp, "modes": [row["deployment_mode"] for row in manifests]})[:16],
        "generated_at": timestamp,
        "manifest_count": len(manifests),
        "manifests": manifests,
        "deployment_modes": [row["deployment_mode"] for row in manifests],
        "supported_count": states.count("supported"),
        "degraded_count": states.count("degraded"),
        "unsupported_count": states.count("unsupported"),
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def build_deployment_readiness_summary(
    *,
    deployment_mode: str,
    runtime_profile: dict[str, Any],
    node_profile: dict[str, Any],
    service_provider: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    mode = _manifest_mode(deployment_mode)
    checks = {
        "runtime_mode": _runtime_mode_state(mode, runtime_profile),
        "node_suitability": _node_suitability_state(mode, node_profile),
        "service_provider": _provider_state(service_provider),
        "platform_overlap": "supported" if _supported_platforms(runtime_profile, node_profile) else "unsupported",
    }
    state = "supported"
    if "unsupported" in checks.values() or "unavailable" in checks.values():
        state = "unsupported"
    elif "degraded" in checks.values() or "unknown" in checks.values():
        state = "degraded"
    return {
        "record_type": "deployment_readiness_summary",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "deployment_mode": mode,
        "state": state,
        "check_states": dict(sorted(checks.items())),
        "operator_review_required": state != "supported",
        "operator_summary": _readiness_summary(state, mode),
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def build_manifest_export_paths(deployment_mode: str, *, generated_at: str | None = None) -> dict[str, Any]:
    mode = _manifest_mode(deployment_mode)
    return {
        "record_type": "deployment_manifest_export_paths",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "deployment_mode": mode,
        "manifest_output_path": f"<operator-approved-export-dir>/{mode}-manifest.json",
        "bundle_output_path": f"<operator-approved-export-dir>/{mode}-deployment-bundle-preview.json",
        "backup_reference_path": f"<operator-approved-backup-dir>/{mode}-backup-preview.json",
        "real_paths_included": False,
        "paths_created": False,
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def build_backup_recommendations(
    deployment_mode: str,
    *,
    runtime_profile: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    mode = _manifest_mode(deployment_mode)
    recommendations = [
        "export_current_runtime_summary",
        "include_historical_metadata_snapshots",
        "verify_redaction_before_public_sharing",
    ]
    if runtime_profile.get("history_retention_mode") in {"long", "balanced"}:
        recommendations.append("include_long_term_intelligence_rollups")
    if mode in {"edge", "worker"}:
        recommendations.append("keep_edge_backups_small_and_bounded")
    return {
        "record_type": "deployment_manifest_backup_recommendations",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "deployment_mode": mode,
        "recommendations": sorted(set(recommendations)),
        "automatic_backup_created": False,
        "automatic_restore_enabled": False,
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def build_manifest_advisory_notes(
    deployment_mode: str,
    *,
    readiness: dict[str, Any],
    runtime_profile: dict[str, Any],
    service_provider: dict[str, Any],
) -> list[str]:
    mode = _manifest_mode(deployment_mode)
    notes = {
        "Deployment manifest is metadata-only and sanitized.",
        "No deployment package, installer, service, credential, or system configuration is created.",
        "Operator review is required before using any manifest outside dry-run planning.",
    }
    if readiness.get("state") != "supported":
        notes.add("Resolve degraded or unsupported readiness checks before deployment.")
    if runtime_profile.get("safety_mode") != "dry-run":
        notes.add("Runtime profile requires explicit operator review before local writes.")
    if service_provider.get("state") != "supported":
        notes.add("Service provider readiness requires review before lifecycle planning.")
    if mode == "edge":
        notes.add("Edge deployments should use bounded retention and modest telemetry settings.")
    return sorted(notes)


def build_deployment_manifest_dashboard_record(
    *,
    mode: str,
    readiness: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "deployment_manifest_dashboard",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "deployment_mode": mode,
        "state": readiness["state"],
        "operator_review_required": readiness["operator_review_required"],
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def build_deployment_manifest_api_response(
    *,
    mode: str,
    readiness: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "deployment_manifest_api_response",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "deployment_mode": mode,
        "state": readiness["state"],
        "check_states": readiness["check_states"],
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def build_deployment_manifest_export_dict(
    *,
    mode: str,
    readiness: dict[str, Any],
    runtime_profile: dict[str, Any],
    node_profile: dict[str, Any],
    service_provider: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "deployment_manifest_export",
        "record_version": DEPLOYMENT_MANIFEST_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "deployment_mode": mode,
        "state": readiness["state"],
        "runtime_profile": runtime_profile["profile_name"],
        "node_profile": node_profile["profile_name"],
        "service_provider": service_provider["provider"],
        "profile_digests": {
            "runtime_profile": runtime_profile.get("profile_digest"),
            "node_profile": node_profile.get("profile_digest"),
        },
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def deployment_manifest_to_dict(manifest: dict[str, Any]) -> dict[str, Any]:
    payload = dict(manifest or {})
    mode = _manifest_mode(payload.get("deployment_mode") or "lab")
    return {
        "record_type": str(payload.get("record_type") or "deployment_manifest"),
        "record_version": int(payload.get("record_version") or DEPLOYMENT_MANIFEST_RECORD_VERSION),
        "manifest_id": str(payload.get("manifest_id") or f"deployment-manifest-{mode}"),
        "generated_at": str(payload.get("generated_at") or _now()),
        "deployment_mode": mode,
        "telemetry_mode": str(payload.get("telemetry_mode") or "metadata-only"),
        "orchestration_mode": str(payload.get("orchestration_mode") or "single-node"),
        "service_provider_mode": str(payload.get("service_provider_mode") or "foreground-process"),
        "retention_policy_mode": str(payload.get("retention_policy_mode") or "balanced"),
        "required_components": _string_list(payload.get("required_components") or []),
        "optional_components": _string_list(payload.get("optional_components") or []),
        "advisory_notes": _string_list(payload.get("advisory_notes") or []),
        "dry_run_only": True,
        **DEPLOYMENT_MANIFEST_SAFETY_FLAGS,
    }


def export_deployment_manifest(manifest: dict[str, Any]) -> str:
    return json.dumps(deployment_manifest_to_dict(manifest), sort_keys=True)


def _manifest_templates() -> dict[str, dict[str, Any]]:
    common_required = ["runtime_profile", "local_storage", "runtime_health", "export_safety"]
    common_optional = ["dashboard_views", "historical_intelligence", "federation_summaries"]
    return {
        "standalone": _template("development", "macos-workstation", "foreground-process", "standard", common_required + ["local_api"], common_optional),
        "orchestrator": _template("production", "linux-server", "linux-systemd", "enhanced", common_required + ["federation_runtime", "cluster_health"], common_optional),
        "worker": _template("edge", "lightweight-worker", "foreground-process", "minimal", common_required + ["trusted_peer_summary"], common_optional),
        "edge": _template("edge", "raspberry-pi-edge", "raspberry-pi-systemd-edge", "minimal", common_required + ["gateway_readiness"], common_optional),
        "lab": _template("lab", "lab-node", "foreground-process", "standard", ["runtime_profile", "sanitized_fixtures", "temporary_export_path"], ["dashboard_views"]),
        "production_preview": _template("production", "linux-server", "linux-systemd", "enhanced", common_required + ["service_lifecycle_preview", "backup_plan"], common_optional + ["deployment_validation"]),
    }


def _template(runtime_profile: str, node_profile: str, service_provider: str, telemetry_mode: str, required: list[str], optional: list[str]) -> dict[str, Any]:
    return {
        "runtime_profile": runtime_profile,
        "node_profile": node_profile,
        "service_provider": service_provider,
        "telemetry_mode": telemetry_mode,
        "required_components": required,
        "optional_components": optional,
    }


def _runtime_profile(value: dict[str, Any] | str, *, generated_at: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return deployment_runtime_profile_to_dict(value)
    return build_deployment_runtime_profile(str(value), generated_at=generated_at)


def _node_profile(value: dict[str, Any] | str, *, generated_at: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return node_deployment_profile_to_dict(value)
    return build_node_deployment_profile(str(value), generated_at=generated_at)


def _service_provider(value: dict[str, Any] | str, *, mode: str, generated_at: str) -> dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    platform_info = _platform_fixture_for_mode(mode, str(value))
    return build_service_provider_readiness(
        service_name=f"portmap-{mode}",
        platform_info=platform_info,
        provider=str(value),
        install_path="<portmap-install-dir>",
        generated_at=generated_at,
    )


def _platform_fixture_for_mode(mode: str, provider: str) -> dict[str, Any]:
    if mode == "edge" or provider == "raspberry-pi-systemd-edge":
        return {"system": "Linux", "release": "raspberry-pi-release-placeholder", "machine": "aarch64", "python_version": "3.11.5"}
    if provider == "macos-launchd":
        return {"system": "Darwin", "release": "macos-release-placeholder", "machine": "arm64", "python_version": "3.11.5"}
    if provider == "windows-service-control-manager":
        return {"system": "Windows", "release": "windows-release-placeholder", "machine": "AMD64", "python_version": "3.11.5"}
    if provider in {"linux-systemd", "systemd"} or mode in {"orchestrator", "production_preview"}:
        return {"system": "Linux", "release": "linux-release-placeholder", "machine": "x86_64", "python_version": "3.11.5"}
    return {"system": "Unknown", "release": "unknown-release-placeholder", "machine": "unknown", "python_version": "3.11.5"}


def _supported_platforms(runtime: dict[str, Any], node: dict[str, Any]) -> list[str]:
    return sorted(set(runtime.get("platform_support") or []) & set(node.get("supported_platforms") or []))


def _runtime_mode_state(mode: str, runtime: dict[str, Any]) -> str:
    deployment_map = {
        "standalone": "endpoint-agent",
        "orchestrator": "orchestrator",
        "worker": "worker",
        "edge": "edge",
        "lab": "lab",
        "production_preview": "orchestrator",
    }
    return "supported" if deployment_map[mode] in set(runtime.get("deployment_modes") or []) else "unsupported"


def _node_suitability_state(mode: str, node: dict[str, Any]) -> str:
    key_map = {
        "standalone": "standalone",
        "orchestrator": "orchestrator",
        "worker": "worker",
        "edge": "edge",
        "lab": "lab",
        "production_preview": "orchestrator",
    }
    suitability = node.get("deployment_suitability") if isinstance(node.get("deployment_suitability"), dict) else {}
    state = str(suitability.get(key_map[mode]) or "unsupported")
    return state if state in DEPLOYMENT_READINESS_STATES else "degraded"


def _provider_state(service_provider: dict[str, Any]) -> str:
    state = str(service_provider.get("state") or "unknown")
    if state == "unavailable":
        return "unsupported"
    if state in {"supported", "degraded", "unsupported"}:
        return state
    return "degraded"


def _readiness_summary(state: str, mode: str) -> str:
    if state == "supported":
        return f"{mode} deployment manifest is supported for sanitized dry-run planning."
    if state == "unsupported":
        return f"{mode} deployment manifest has unsupported readiness checks."
    return f"{mode} deployment manifest is degraded and requires operator review."


def _manifest_mode(value: Any) -> str:
    normalized = str(value or "lab").strip().lower().replace("-", "_")
    normalized = normalized.replace("_preview", "_preview")
    if normalized in DEPLOYMENT_MANIFEST_MODES:
        return normalized
    if normalized == "production-preview":
        return "production_preview"
    raise ValueError(f"deployment_mode must be one of: {', '.join(sorted(DEPLOYMENT_MANIFEST_MODES))}")


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


def _digest(payload: dict[str, Any]) -> str:
    return sha256(json.dumps(payload, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
