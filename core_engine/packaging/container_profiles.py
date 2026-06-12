from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.installer_previews import PACKAGING_SAFETY_FLAGS, sanitize_list
from core_engine.scaling.bus_envelopes import digest, sanitize_reference, sanitize_text, sanitize_token


CONTAINER_PROFILE_RECORD_VERSION = 1
CONTAINER_PROFILE_TYPES = {
    "single_node_preview",
    "multi_service_preview",
    "worker_only_preview",
    "orchestrator_preview",
    "edge_preview",
    "unknown",
}
CONTAINER_RUNTIMES = {"docker", "podman", "compose", "containerd_preview", "unknown"}
CONTAINER_PROFILE_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    "image_built": False,
    "image_created": False,
    "image_pushed": False,
    "image_pulled": False,
    "registry_published": False,
    "container_started": False,
    "container_stopped": False,
    "container_runtime_api_called": False,
    "docker_api_called": False,
    "podman_api_called": False,
    "compose_file_written": False,
    "filesystem_written": False,
    "network_created": False,
    "volume_created": False,
    "environment_written": False,
    "admin_escalation_requested": False,
    "credential_stored": False,
}


@dataclass(frozen=True)
class ContainerProfilePreviewRecord:
    profile_id: str
    profile_name: str
    profile_type: str
    container_runtime: str
    image_reference_preview: str
    compose_service_preview: dict[str, Any] = field(default_factory=dict)
    volume_layout_preview: dict[str, Any] = field(default_factory=dict)
    network_layout_preview: dict[str, Any] = field(default_factory=dict)
    environment_preview: dict[str, Any] = field(default_factory=dict)
    resource_limits_preview: dict[str, Any] = field(default_factory=dict)
    rollback_available: bool = False
    uninstall_available: bool = False
    validation_steps: list[str] = field(default_factory=list)
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "container_profile_preview",
            "record_version": CONTAINER_PROFILE_RECORD_VERSION,
            "profile_id": sanitize_reference(self.profile_id),
            "profile_name": sanitize_text(self.profile_name) or "container profile preview",
            "profile_type": normalize_container_profile_type(self.profile_type),
            "container_runtime": normalize_container_runtime(self.container_runtime),
            "image_reference_preview": sanitize_image_reference_preview(self.image_reference_preview),
            "compose_service_preview": sanitize_preview_mapping(self.compose_service_preview),
            "volume_layout_preview": sanitize_preview_mapping(self.volume_layout_preview),
            "network_layout_preview": sanitize_preview_mapping(self.network_layout_preview),
            "environment_preview": sanitize_environment_preview(self.environment_preview),
            "resource_limits_preview": sanitize_resource_limits(self.resource_limits_preview),
            "rollback_available": bool(self.rollback_available),
            "uninstall_available": bool(self.uninstall_available),
            "validation_steps": sanitize_list(self.validation_steps),
            "advisory_notes": sanitize_list(self.advisory_notes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **CONTAINER_PROFILE_SAFETY_FLAGS,
        }


def build_container_profile_preview(
    *,
    profile_id: Any = "",
    profile_name: Any = "PortMap-AI container profile",
    profile_type: Any = "single_node_preview",
    container_runtime: Any = "docker",
    image_reference_preview: Any = "portmap-ai:preview",
    compose_service_preview: dict[str, Any] | None = None,
    volume_layout_preview: dict[str, Any] | None = None,
    network_layout_preview: dict[str, Any] | None = None,
    environment_preview: dict[str, Any] | None = None,
    resource_limits_preview: dict[str, Any] | None = None,
    rollback_available: Any = False,
    uninstall_available: Any = False,
    validation_steps: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> ContainerProfilePreviewRecord:
    normalized_type = normalize_container_profile_type(profile_type)
    normalized_runtime = normalize_container_runtime(container_runtime)
    safe_image = sanitize_image_reference_preview(image_reference_preview)
    compose = sanitize_preview_mapping(compose_service_preview or default_compose_service_preview(normalized_type))
    volumes = sanitize_preview_mapping(volume_layout_preview or default_volume_layout_preview(normalized_type))
    network = sanitize_preview_mapping(network_layout_preview or default_network_layout_preview(normalized_type))
    environment = sanitize_environment_preview(environment_preview or default_environment_preview(normalized_type))
    resources = sanitize_resource_limits(resource_limits_preview or default_resource_limits_preview(normalized_type))
    validations = sanitize_list(validation_steps or default_validation_steps(normalized_runtime))
    notes = sanitize_list(advisory_notes or ["container profile is metadata-only and advisory"])
    safe_id = sanitize_reference(profile_id)
    if not safe_id:
        safe_id = "container-profile-" + digest(
            {
                "profile_name": sanitize_text(profile_name),
                "profile_type": normalized_type,
                "container_runtime": normalized_runtime,
                "image_reference_preview": safe_image,
            }
        )[:16]
    return ContainerProfilePreviewRecord(
        profile_id=safe_id,
        profile_name=sanitize_text(profile_name) or "PortMap-AI container profile",
        profile_type=normalized_type,
        container_runtime=normalized_runtime,
        image_reference_preview=safe_image,
        compose_service_preview=compose,
        volume_layout_preview=volumes,
        network_layout_preview=network,
        environment_preview=environment,
        resource_limits_preview=resources,
        rollback_available=bool(rollback_available),
        uninstall_available=bool(uninstall_available),
        validation_steps=validations,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_container_profile_preview(value: Any) -> ContainerProfilePreviewRecord:
    if isinstance(value, ContainerProfilePreviewRecord):
        return value
    if not isinstance(value, dict):
        return build_container_profile_preview(
            profile_type="unknown",
            container_runtime="unknown",
            advisory_notes=["invalid container profile generated from malformed input"],
        )
    try:
        return build_container_profile_preview(
            profile_id=value.get("profile_id", ""),
            profile_name=value.get("profile_name", "PortMap-AI container profile"),
            profile_type=value.get("profile_type", value.get("type", "unknown")),
            container_runtime=value.get("container_runtime", value.get("runtime", "unknown")),
            image_reference_preview=value.get("image_reference_preview", ""),
            compose_service_preview=value.get("compose_service_preview") if isinstance(value.get("compose_service_preview"), dict) else None,
            volume_layout_preview=value.get("volume_layout_preview") if isinstance(value.get("volume_layout_preview"), dict) else None,
            network_layout_preview=value.get("network_layout_preview") if isinstance(value.get("network_layout_preview"), dict) else None,
            environment_preview=value.get("environment_preview") if isinstance(value.get("environment_preview"), dict) else None,
            resource_limits_preview=value.get("resource_limits_preview") if isinstance(value.get("resource_limits_preview"), dict) else None,
            rollback_available=value.get("rollback_available", False),
            uninstall_available=value.get("uninstall_available", False),
            validation_steps=value.get("validation_steps") if isinstance(value.get("validation_steps"), list) else None,
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_container_profile_preview(profile_type="unknown", advisory_notes=[str(exc)])


def summarize_container_profiles(profiles: Iterable[ContainerProfilePreviewRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_container_profile_preview(profile).to_dict() for profile in list(profiles or [])]
    type_counts: dict[str, int] = {}
    runtime_counts: dict[str, int] = {}
    for row in rows:
        type_counts[row["profile_type"]] = type_counts.get(row["profile_type"], 0) + 1
        runtime_counts[row["container_runtime"]] = runtime_counts.get(row["container_runtime"], 0) + 1
    return {
        "profile_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "runtime_counts": dict(sorted(runtime_counts.items())),
        "rollback_available_count": sum(1 for row in rows if row.get("rollback_available")),
        "uninstall_available_count": sum(1 for row in rows if row.get("uninstall_available")),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_PROFILE_SAFETY_FLAGS,
    }


def default_compose_service_preview(profile_type: str) -> dict[str, Any]:
    normalized = normalize_container_profile_type(profile_type)
    service_name = {
        "worker_only_preview": "portmap-worker",
        "orchestrator_preview": "portmap-orchestrator",
        "edge_preview": "portmap-edge",
    }.get(normalized, "portmap-ai")
    return {
        "service_name": service_name,
        "command_preview": "portmap stack --preview",
        "replicas_preview": 1 if normalized != "multi_service_preview" else 3,
    }


def default_volume_layout_preview(profile_type: str) -> dict[str, Any]:
    return {
        "config_volume": "portmap-config-preview",
        "state_volume": "portmap-state-preview",
        "read_only_docs": True,
        "runtime_database_mount": False,
    }


def default_network_layout_preview(profile_type: str) -> dict[str, Any]:
    normalized = normalize_container_profile_type(profile_type)
    return {
        "network_name": "portmap-preview-net",
        "exposed_ports_preview": [] if normalized == "worker_only_preview" else ["local-ui-preview"],
        "host_network_required": False,
    }


def default_environment_preview(profile_type: str) -> dict[str, Any]:
    return {
        "PORTMAP_MODE": "preview",
        "PORTMAP_PROFILE": normalize_container_profile_type(profile_type),
        "PORTMAP_SECRET": "<redacted>",
    }


def default_resource_limits_preview(profile_type: str) -> dict[str, Any]:
    normalized = normalize_container_profile_type(profile_type)
    return {
        "cpu_limit": "1.0" if normalized != "edge_preview" else "0.5",
        "memory_limit_mb": 512 if normalized != "edge_preview" else 256,
        "storage_limit_mb": 1024 if normalized != "edge_preview" else 512,
    }


def default_validation_steps(runtime: str) -> list[str]:
    return [
        f"review {normalize_container_runtime(runtime)} runtime preview",
        "confirm no image build or registry publish",
        "confirm no container start or compose file write",
    ]


def sanitize_image_reference_preview(value: Any) -> str:
    text = str(value or "")
    text = re.sub(r"[\r\n\t]+", " ", text.strip())
    text = re.sub(r"[;&|`$<>]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return "<no-image-preview>"
    return sanitize_text(text)[:180]


def sanitize_preview_mapping(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    sanitized: dict[str, Any] = {}
    for key, raw_value in list(value.items())[:32]:
        safe_key = sanitize_token(key).upper() if str(key).isupper() else sanitize_token(key).lower()
        if not safe_key:
            continue
        if isinstance(raw_value, bool):
            sanitized[safe_key] = raw_value
        elif isinstance(raw_value, (int, float)):
            sanitized[safe_key] = raw_value
        elif isinstance(raw_value, (list, tuple)):
            sanitized[safe_key] = [sanitize_text(item)[:120] for item in raw_value][:16]
        else:
            sanitized[safe_key] = sanitize_image_reference_preview(raw_value)
    return sanitized


def sanitize_environment_preview(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    sanitized: dict[str, str] = {}
    for key, raw_value in list(value.items())[:32]:
        safe_key = sanitize_token(key).upper()
        if not safe_key:
            continue
        if any(marker in safe_key for marker in ("SECRET", "TOKEN", "PASSWORD", "KEY", "CREDENTIAL")):
            sanitized[safe_key] = "<redacted>"
        else:
            sanitized[safe_key] = sanitize_image_reference_preview(raw_value)
    return sanitized


def sanitize_resource_limits(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    sanitized = sanitize_preview_mapping(value)
    sanitized["preview_only"] = True
    sanitized["destructive_action"] = False
    return sanitized


def normalize_container_profile_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in CONTAINER_PROFILE_TYPES else "unknown"


def normalize_container_runtime(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in CONTAINER_RUNTIMES else "unknown"


def deterministic_container_profile_json(record: ContainerProfilePreviewRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, ContainerProfilePreviewRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "CONTAINER_PROFILE_SAFETY_FLAGS",
    "CONTAINER_PROFILE_TYPES",
    "CONTAINER_RUNTIMES",
    "ContainerProfilePreviewRecord",
    "build_container_profile_preview",
    "deterministic_container_profile_json",
    "normalize_container_profile_preview",
    "normalize_container_profile_type",
    "normalize_container_runtime",
    "sanitize_environment_preview",
    "sanitize_image_reference_preview",
    "sanitize_preview_mapping",
    "summarize_container_profiles",
]
