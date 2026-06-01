from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.deployment.runtime_profiles import DEPLOYMENT_PROFILE_SAFETY_FLAGS


NODE_PROFILE_RECORD_VERSION = 1

NODE_PROFILE_NAMES = frozenset(
    {
        "raspberry-pi-edge",
        "macos-workstation",
        "windows-workstation",
        "linux-server",
        "lab-node",
        "lightweight-worker",
    }
)

NODE_PROFILE_SAFETY_FLAGS = {
    **DEPLOYMENT_PROFILE_SAFETY_FLAGS,
    "dry_run_only": True,
    "deployment_action_performed": False,
    "deployment_package_created": False,
    "installer_created": False,
    "config_written": False,
    "system_location_written": False,
    "credentials_generated": False,
}


def build_node_deployment_profile(
    profile_name: str,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    name = _profile_name(profile_name)
    template = _profile_templates()[name]
    timestamp = generated_at or _now()
    profile = {
        "record_type": "node_deployment_profile",
        "record_version": NODE_PROFILE_RECORD_VERSION,
        "node_profile_id": f"node-profile-{name}",
        "profile_name": name,
        "generated_at": timestamp,
        "display_name": template["display_name"],
        "estimated_resource_envelope": _sorted_dict(template["estimated_resource_envelope"]),
        "deployment_suitability": _sorted_dict(template["deployment_suitability"]),
        "telemetry_suitability": _sorted_dict(template["telemetry_suitability"]),
        "orchestration_suitability": _sorted_dict(template["orchestration_suitability"]),
        "degraded_mode_recommendations": sorted(template["degraded_mode_recommendations"]),
        "advisory_only_warnings": sorted(template["advisory_only_warnings"]),
        "supported_platforms": sorted(template["supported_platforms"]),
        "operator_summary": template["operator_summary"],
        **NODE_PROFILE_SAFETY_FLAGS,
    }
    profile["profile_digest"] = _digest(
        {
            "profile_name": profile["profile_name"],
            "resource": profile["estimated_resource_envelope"],
            "deployment": profile["deployment_suitability"],
        }
    )
    return profile


def list_node_deployment_profiles(*, generated_at: str | None = None) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    return [build_node_deployment_profile(name, generated_at=timestamp) for name in sorted(NODE_PROFILE_NAMES)]


def build_node_profile_catalog(*, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    profiles = list_node_deployment_profiles(generated_at=timestamp)
    return {
        "record_type": "node_deployment_profile_catalog",
        "record_version": NODE_PROFILE_RECORD_VERSION,
        "catalog_id": "node-profile-catalog-" + _digest({"generated_at": timestamp, "profiles": [row["profile_name"] for row in profiles]})[:16],
        "generated_at": timestamp,
        "profile_count": len(profiles),
        "profiles": profiles,
        "profile_names": [row["profile_name"] for row in profiles],
        **NODE_PROFILE_SAFETY_FLAGS,
    }


def node_deployment_profile_to_dict(profile: dict[str, Any]) -> dict[str, Any]:
    payload = dict(profile or {})
    name = _profile_name(payload.get("profile_name") or "lab-node")
    return {
        "record_type": str(payload.get("record_type") or "node_deployment_profile"),
        "record_version": int(payload.get("record_version") or NODE_PROFILE_RECORD_VERSION),
        "node_profile_id": str(payload.get("node_profile_id") or f"node-profile-{name}"),
        "profile_name": name,
        "generated_at": str(payload.get("generated_at") or _now()),
        "display_name": str(payload.get("display_name") or name),
        "estimated_resource_envelope": _sorted_dict(dict(payload.get("estimated_resource_envelope") or {})),
        "deployment_suitability": _sorted_dict(dict(payload.get("deployment_suitability") or {})),
        "telemetry_suitability": _sorted_dict(dict(payload.get("telemetry_suitability") or {})),
        "orchestration_suitability": _sorted_dict(dict(payload.get("orchestration_suitability") or {})),
        "degraded_mode_recommendations": _string_list(payload.get("degraded_mode_recommendations") or []),
        "advisory_only_warnings": _string_list(payload.get("advisory_only_warnings") or []),
        "supported_platforms": _string_list(payload.get("supported_platforms") or []),
        "operator_summary": str(payload.get("operator_summary") or ""),
        "profile_digest": str(payload.get("profile_digest") or _digest({"profile_name": name})),
        **NODE_PROFILE_SAFETY_FLAGS,
    }


def _profile_templates() -> dict[str, dict[str, Any]]:
    return {
        "raspberry-pi-edge": {
            "display_name": "Raspberry Pi Edge Node",
            "estimated_resource_envelope": _resource(cpu="low-power-arm", memory_mb=1024, disk_mb=4096, network="lan-edge"),
            "deployment_suitability": _suitability(edge="supported", worker="supported", standalone="degraded", orchestrator="degraded"),
            "telemetry_suitability": _suitability(passive="supported", enriched_flows="degraded", gateway_logs="supported", span="degraded"),
            "orchestration_suitability": _suitability(master="degraded", worker="supported", orchestrator="degraded"),
            "degraded_mode_recommendations": ["lower_retention_window", "limit_dashboard_refresh", "prefer_worker_or_edge_mode"],
            "advisory_only_warnings": ["edge_resource_review_required", "no_promiscuous_mode_changes", "manual_service_review_required"],
            "supported_platforms": ["linux", "raspberry-pi-linux-arm"],
            "operator_summary": "Raspberry Pi edge nodes should use bounded telemetry, local placeholders, and manual service review.",
        },
        "macos-workstation": {
            "display_name": "macOS Workstation",
            "estimated_resource_envelope": _resource(cpu="workstation", memory_mb=4096, disk_mb=8192, network="local-workstation"),
            "deployment_suitability": _suitability(standalone="supported", lab="supported", worker="supported", orchestrator="degraded"),
            "telemetry_suitability": _suitability(passive="degraded", enriched_flows="supported", gateway_logs="degraded", span="degraded"),
            "orchestration_suitability": _suitability(master="supported", worker="supported", orchestrator="degraded"),
            "degraded_mode_recommendations": ["use_launchd_preview_only", "keep_api_loopback", "review_capture_permissions_manually"],
            "advisory_only_warnings": ["launch_agent_creation_disabled", "manual_capture_permission_review_required"],
            "supported_platforms": ["macos"],
            "operator_summary": "macOS workstations are suitable for local review, lab validation, and launchd preview planning.",
        },
        "windows-workstation": {
            "display_name": "Windows Workstation",
            "estimated_resource_envelope": _resource(cpu="workstation", memory_mb=4096, disk_mb=8192, network="local-workstation"),
            "deployment_suitability": _suitability(standalone="supported", lab="supported", worker="degraded", orchestrator="degraded"),
            "telemetry_suitability": _suitability(passive="degraded", enriched_flows="supported", gateway_logs="degraded", span="degraded"),
            "orchestration_suitability": _suitability(master="degraded", worker="supported", orchestrator="degraded"),
            "degraded_mode_recommendations": ["use_windows_service_preview_only", "do_not_assume_npcap", "review_elevation_requirements"],
            "advisory_only_warnings": ["windows_service_registration_disabled", "registry_changes_disabled", "npcap_not_assumed"],
            "supported_platforms": ["windows"],
            "operator_summary": "Windows workstations support compatibility planning and service previews without registry or service changes.",
        },
        "linux-server": {
            "display_name": "Linux Server",
            "estimated_resource_envelope": _resource(cpu="server", memory_mb=8192, disk_mb=32768, network="server-lan"),
            "deployment_suitability": _suitability(standalone="supported", master="supported", worker="supported", orchestrator="supported"),
            "telemetry_suitability": _suitability(passive="supported", enriched_flows="supported", gateway_logs="supported", span="degraded"),
            "orchestration_suitability": _suitability(master="supported", worker="supported", orchestrator="supported"),
            "degraded_mode_recommendations": ["review_systemd_unit_manually", "confirm_export_path_placeholder", "keep_firewall_changes_disabled"],
            "advisory_only_warnings": ["systemd_unit_creation_disabled", "firewall_changes_disabled"],
            "supported_platforms": ["linux"],
            "operator_summary": "Linux servers are suitable for orchestrator, master, worker, or standalone deployment planning.",
        },
        "lab-node": {
            "display_name": "Lab Node",
            "estimated_resource_envelope": _resource(cpu="fixture", memory_mb=1024, disk_mb=2048, network="isolated-lab"),
            "deployment_suitability": _suitability(lab="supported", standalone="supported", worker="degraded"),
            "telemetry_suitability": _suitability(passive="degraded", enriched_flows="supported", gateway_logs="supported", span="degraded"),
            "orchestration_suitability": _suitability(master="degraded", worker="degraded", orchestrator="degraded"),
            "degraded_mode_recommendations": ["use_sanitized_fixtures", "prefer_temporary_outputs", "disable_service_installation"],
            "advisory_only_warnings": ["lab_records_only", "no_private_artifacts"],
            "supported_platforms": ["macos", "linux", "raspberry-pi-linux-arm", "windows"],
            "operator_summary": "Lab nodes are for sanitized local fixtures and temporary dry-run validation.",
        },
        "lightweight-worker": {
            "display_name": "Lightweight Worker",
            "estimated_resource_envelope": _resource(cpu="modest", memory_mb=1024, disk_mb=4096, network="trusted-node"),
            "deployment_suitability": _suitability(worker="supported", edge="supported", standalone="degraded"),
            "telemetry_suitability": _suitability(passive="supported", enriched_flows="degraded", gateway_logs="degraded", span="degraded"),
            "orchestration_suitability": _suitability(master="unavailable", worker="supported", orchestrator="unavailable"),
            "degraded_mode_recommendations": ["prefer_worker_mode", "use_bounded_history", "keep_export_bundles_small"],
            "advisory_only_warnings": ["worker_requires_approved_master_summary", "bounded_resource_profile_required"],
            "supported_platforms": ["linux", "raspberry-pi-linux-arm", "macos", "windows"],
            "operator_summary": "Lightweight workers should run bounded telemetry and report to approved local coordination summaries.",
        },
    }


def _resource(*, cpu: str, memory_mb: int, disk_mb: int, network: str) -> dict[str, Any]:
    return {
        "cpu_class": cpu,
        "recommended_memory_mb": memory_mb,
        "recommended_disk_mb": disk_mb,
        "network_class": network,
        "bounded_retention_required": True,
    }


def _suitability(**values: str) -> dict[str, str]:
    return {str(key): str(value) for key, value in values.items()}


def _profile_name(value: Any) -> str:
    normalized = str(value or "").strip().lower().replace("_", "-")
    aliases = {
        "raspberry-pi": "raspberry-pi-edge",
        "edge": "raspberry-pi-edge",
        "macos": "macos-workstation",
        "windows": "windows-workstation",
        "linux": "linux-server",
        "lab": "lab-node",
        "worker": "lightweight-worker",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized not in NODE_PROFILE_NAMES:
        raise ValueError(f"profile_name must be one of: {', '.join(sorted(NODE_PROFILE_NAMES))}")
    return normalized


def _string_list(value: Iterable[Any]) -> list[str]:
    return sorted({str(item).strip() for item in value or [] if str(item).strip()})


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
