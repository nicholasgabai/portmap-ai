from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.container_profiles import (
    CONTAINER_PROFILE_SAFETY_FLAGS,
    ContainerProfilePreviewRecord,
    build_container_profile_preview,
    normalize_container_profile_preview,
    normalize_container_profile_type,
    normalize_container_runtime,
    sanitize_environment_preview,
    sanitize_preview_mapping,
    summarize_container_profiles,
)
from core_engine.packaging.installer_previews import (
    PACKAGING_SAFETY_FLAGS,
    InstallerPreviewRecord,
    build_installer_preview,
    normalize_installer_preview,
    sanitize_list,
    summarize_installer_previews,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_text, sanitize_token


CONTAINER_DEPLOYMENT_RECORD_VERSION = 1
CONTAINER_DEPLOYMENT_STATES = {"ready", "degraded", "blocked", "unavailable", "unknown"}
CONTAINER_DEPLOYMENT_METHODS = {"docker_preview", "compose_preview", "podman_preview", "containerd_preview", "unknown"}
CONTAINER_DEPLOYMENT_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    **CONTAINER_PROFILE_SAFETY_FLAGS,
    "docker_api_called": False,
    "podman_api_called": False,
    "containerd_api_called": False,
    "image_build_executed": False,
    "image_created": False,
    "registry_published": False,
    "container_started": False,
    "container_stopped": False,
    "compose_file_written": False,
    "filesystem_written": False,
}


@dataclass(frozen=True)
class ContainerDeploymentReadinessRecord:
    deployment_id: str
    generated_at: str
    deployment_state: str
    target_platform: str
    deployment_method: str
    container_profiles: list[dict[str, Any]] = field(default_factory=list)
    runtime_readiness: dict[str, Any] = field(default_factory=dict)
    image_build_readiness: dict[str, Any] = field(default_factory=dict)
    compose_readiness: dict[str, Any] = field(default_factory=dict)
    volume_readiness: dict[str, Any] = field(default_factory=dict)
    network_readiness: dict[str, Any] = field(default_factory=dict)
    environment_readiness: dict[str, Any] = field(default_factory=dict)
    rollback_preview: dict[str, Any] = field(default_factory=dict)
    uninstall_preview: dict[str, Any] = field(default_factory=dict)
    validation_summary: dict[str, Any] = field(default_factory=dict)
    required_permissions: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "container_deployment_readiness",
            "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
            "deployment_id": sanitize_reference(self.deployment_id),
            "generated_at": str(self.generated_at or ""),
            "deployment_state": normalize_container_deployment_state(self.deployment_state),
            "target_platform": normalize_container_target_platform(self.target_platform),
            "deployment_method": normalize_container_deployment_method(self.deployment_method),
            "container_profiles": list(self.container_profiles),
            "runtime_readiness": dict(self.runtime_readiness),
            "image_build_readiness": dict(self.image_build_readiness),
            "compose_readiness": dict(self.compose_readiness),
            "volume_readiness": dict(self.volume_readiness),
            "network_readiness": dict(self.network_readiness),
            "environment_readiness": dict(self.environment_readiness),
            "rollback_preview": dict(self.rollback_preview),
            "uninstall_preview": dict(self.uninstall_preview),
            "validation_summary": dict(self.validation_summary),
            "required_permissions": sanitize_list(self.required_permissions),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
        }


def build_container_deployment_readiness(
    *,
    deployment_id: Any = "",
    generated_at: Any = None,
    target_platform: Any = "cross_platform",
    deployment_method: Any = "docker_preview",
    container_profiles: Iterable[ContainerProfilePreviewRecord | dict[str, Any] | Any] | None = None,
    runtime_readiness: dict[str, Any] | None = None,
    image_build_readiness: dict[str, Any] | None = None,
    compose_readiness: dict[str, Any] | None = None,
    volume_readiness: dict[str, Any] | None = None,
    network_readiness: dict[str, Any] | None = None,
    environment_readiness: dict[str, Any] | None = None,
    rollback_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    uninstall_preview: InstallerPreviewRecord | dict[str, Any] | Any | None = None,
    required_permissions: Iterable[Any] | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> ContainerDeploymentReadinessRecord:
    timestamp = str(generated_at or now_timestamp())
    platform = normalize_container_target_platform(target_platform)
    method = normalize_container_deployment_method(deployment_method)
    runtime = runtime_for_method(method)
    permissions = sanitize_list(required_permissions or ["operator_review"])
    profiles = normalize_profiles(container_profiles, method=method)
    profile_rows = [profile.to_dict() for profile in profiles]
    runtime_summary = build_runtime_readiness(runtime_readiness, runtime=runtime)
    image_summary = build_image_build_readiness(image_build_readiness)
    compose_summary = build_compose_readiness(compose_readiness, method=method)
    volume_summary = build_volume_readiness(volume_readiness, profile_rows)
    network_summary = build_network_readiness(network_readiness, profile_rows)
    environment_summary = build_environment_readiness(environment_readiness, profile_rows)
    rollback = normalize_installer_preview(rollback_preview) if rollback_preview is not None else default_container_rollback_preview()
    uninstall = normalize_installer_preview(uninstall_preview) if uninstall_preview is not None else default_container_uninstall_preview()
    preview_rows = [rollback.to_dict(), uninstall.to_dict()]
    state = infer_container_deployment_state(
        platform=platform,
        method=method,
        profiles=profile_rows,
        runtime_readiness=runtime_summary,
    )
    validation = build_container_validation_summary(
        deployment_state=state,
        deployment_method=method,
        profiles=profile_rows,
        previews=preview_rows,
        runtime_readiness=runtime_summary,
        image_build_readiness=image_summary,
        compose_readiness=compose_summary,
        volume_readiness=volume_summary,
        network_readiness=network_summary,
        environment_readiness=environment_summary,
        required_permissions=permissions,
        advisory_notes=advisory_notes,
    )
    safe_id = sanitize_reference(deployment_id)
    if not safe_id:
        safe_id = "container-deployment-" + digest(
            {
                "generated_at": timestamp,
                "target_platform": platform,
                "deployment_method": method,
                "profile_count": len(profile_rows),
                "required_permissions": permissions,
            }
        )[:16]
    return ContainerDeploymentReadinessRecord(
        deployment_id=safe_id,
        generated_at=timestamp,
        deployment_state=state,
        target_platform=platform,
        deployment_method=method,
        container_profiles=profile_rows,
        runtime_readiness=runtime_summary,
        image_build_readiness=image_summary,
        compose_readiness=compose_summary,
        volume_readiness=volume_summary,
        network_readiness=network_summary,
        environment_readiness=environment_summary,
        rollback_preview=rollback.to_dict(),
        uninstall_preview=uninstall.to_dict(),
        validation_summary=validation,
        required_permissions=permissions,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_container_deployment_readiness(*, generated_at: Any = None) -> ContainerDeploymentReadinessRecord:
    return build_container_deployment_readiness(
        generated_at=generated_at,
        target_platform="unknown",
        deployment_method="unknown",
        container_profiles=[],
        advisory_notes=["empty container deployment readiness summary"],
    )


def normalize_profiles(
    values: Iterable[ContainerProfilePreviewRecord | dict[str, Any] | Any] | None,
    *,
    method: str,
) -> list[ContainerProfilePreviewRecord]:
    if values is None:
        return default_container_profiles(method)
    return [normalize_container_profile_preview(value) for value in list(values or [])[:16]]


def default_container_profiles(method: str) -> list[ContainerProfilePreviewRecord]:
    normalized = normalize_container_deployment_method(method)
    runtime = runtime_for_method(normalized)
    profile_type = {
        "compose_preview": "multi_service_preview",
        "podman_preview": "single_node_preview",
        "containerd_preview": "orchestrator_preview",
    }.get(normalized, "single_node_preview")
    return [
        build_container_profile_preview(
            profile_type=profile_type,
            container_runtime=runtime,
            rollback_available=True,
            uninstall_available=True,
        )
    ]


def runtime_for_method(method: str) -> str:
    normalized = normalize_container_deployment_method(method)
    return {
        "docker_preview": "docker",
        "compose_preview": "compose",
        "podman_preview": "podman",
        "containerd_preview": "containerd_preview",
        "unknown": "unknown",
    }.get(normalized, "unknown")


def build_runtime_readiness(value: dict[str, Any] | None = None, *, runtime: str) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    normalized_runtime = normalize_container_runtime(payload.get("container_runtime", runtime))
    return {
        "record_type": "container_runtime_readiness",
        "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
        "container_runtime": normalized_runtime,
        "runtime_available": bool(payload.get("runtime_available", True)),
        "api_call_required": False,
        "api_called": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
    }


def build_image_build_readiness(value: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    return {
        "record_type": "container_image_build_readiness",
        "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
        "dockerfile_preview": sanitize_text(payload.get("dockerfile_preview", "Dockerfile preview only"))[:160],
        "image_build_ready": bool(payload.get("image_build_ready", True)),
        "image_build_executed": False,
        "image_created": False,
        "registry_published": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
    }


def build_compose_readiness(value: dict[str, Any] | None = None, *, method: str) -> dict[str, Any]:
    payload = value if isinstance(value, dict) else {}
    return {
        "record_type": "container_compose_readiness",
        "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
        "compose_applicable": normalize_container_deployment_method(method) == "compose_preview",
        "compose_services_preview": sanitize_preview_mapping(payload.get("compose_services_preview", {"portmap-ai": "preview"})),
        "compose_file_written": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
    }


def build_volume_readiness(value: dict[str, Any] | None, profiles: list[dict[str, Any]]) -> dict[str, Any]:
    payload = sanitize_preview_mapping(value or {})
    volume_count = sum(len(profile.get("volume_layout_preview", {})) for profile in profiles)
    return {
        "record_type": "container_volume_readiness",
        "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
        "volume_count": volume_count,
        "volume_layout_preview": payload,
        "volume_created": False,
        "filesystem_written": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
    }


def build_network_readiness(value: dict[str, Any] | None, profiles: list[dict[str, Any]]) -> dict[str, Any]:
    payload = sanitize_preview_mapping(value or {})
    network_count = sum(1 for profile in profiles if profile.get("network_layout_preview"))
    return {
        "record_type": "container_network_readiness",
        "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
        "network_count": network_count,
        "network_layout_preview": payload,
        "network_created": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
    }


def build_environment_readiness(value: dict[str, Any] | None, profiles: list[dict[str, Any]]) -> dict[str, Any]:
    payload = sanitize_environment_preview(value or {})
    env_count = sum(len(profile.get("environment_preview", {})) for profile in profiles)
    return {
        "record_type": "container_environment_readiness",
        "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
        "environment_variable_count": env_count,
        "environment_preview": payload,
        "environment_written": False,
        "credential_stored": False,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
    }


def default_container_rollback_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="rollback",
        platform_family="container",
        action_summary="container deployment rollback preview",
        command_preview='container-runtime rollback "<previous-image>" --preview-only',
        required_permissions=["operator_review"],
        rollback_available=True,
        uninstall_available=False,
        validation_steps=["review previous image and volume plan", "confirm rollback remains preview-only"],
        safety_warnings=["rollback is preview-only; no image, container, volume, network, or compose change is performed"],
    )


def default_container_uninstall_preview() -> InstallerPreviewRecord:
    return build_installer_preview(
        preview_type="uninstall",
        platform_family="container",
        action_summary="container deployment uninstall preview",
        command_preview='container-runtime remove portmap-ai --preview-only',
        required_permissions=["operator_review"],
        rollback_available=False,
        uninstall_available=True,
        validation_steps=["review container resources", "confirm no uninstall action is executed"],
        safety_warnings=["uninstall is preview-only; no containers, images, networks, volumes, or files are removed"],
    )


def build_container_validation_summary(
    *,
    deployment_state: str,
    deployment_method: str,
    profiles: list[dict[str, Any]],
    previews: list[dict[str, Any]],
    runtime_readiness: dict[str, Any],
    image_build_readiness: dict[str, Any],
    compose_readiness: dict[str, Any],
    volume_readiness: dict[str, Any],
    network_readiness: dict[str, Any],
    environment_readiness: dict[str, Any],
    required_permissions: list[str],
    advisory_notes: Iterable[Any] | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "container_deployment_validation_summary",
        "record_version": CONTAINER_DEPLOYMENT_RECORD_VERSION,
        "deployment_state": normalize_container_deployment_state(deployment_state),
        "deployment_method": normalize_container_deployment_method(deployment_method),
        "profile_summary": summarize_container_profiles(profiles),
        "preview_summary": summarize_installer_previews(previews),
        "runtime_readiness": {
            "container_runtime": runtime_readiness.get("container_runtime", "unknown"),
            "runtime_available": bool(runtime_readiness.get("runtime_available")),
            "api_called": False,
        },
        "image_build_ready": bool(image_build_readiness.get("image_build_ready")),
        "compose_applicable": bool(compose_readiness.get("compose_applicable")),
        "volume_count": int(volume_readiness.get("volume_count", 0)),
        "network_count": int(network_readiness.get("network_count", 0)),
        "environment_variable_count": int(environment_readiness.get("environment_variable_count", 0)),
        "validation_steps": [
            "container profiles generated",
            "runtime readiness summarized",
            "image build readiness summarized",
            "compose, volume, network, and environment previews generated",
            "rollback preview generated",
            "uninstall preview generated",
            "no image build, registry publish, runtime API call, container start, compose write, or filesystem side effect",
        ],
        "required_permissions": sanitize_list(required_permissions),
        "advisory_notes": sanitize_list(advisory_notes or []),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **CONTAINER_DEPLOYMENT_SAFETY_FLAGS,
    }


def infer_container_deployment_state(
    *,
    platform: str,
    method: str,
    profiles: list[dict[str, Any]],
    runtime_readiness: dict[str, Any],
) -> str:
    if platform == "unknown":
        return "unavailable"
    if method == "unknown":
        return "blocked"
    if not profiles or any(profile.get("profile_type") == "unknown" for profile in profiles):
        return "degraded"
    if not runtime_readiness.get("runtime_available", False):
        return "degraded"
    return "ready"


def normalize_container_deployment_method(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in CONTAINER_DEPLOYMENT_METHODS else "unknown"


def normalize_container_deployment_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in CONTAINER_DEPLOYMENT_STATES else "unknown"


def normalize_container_target_platform(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"cross_platform", "linux", "macos", "windows", "raspberry_pi", "linux_arm"}:
        return safe_value
    return "unknown"


def deterministic_container_deployment_json(record: ContainerDeploymentReadinessRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, ContainerDeploymentReadinessRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "CONTAINER_DEPLOYMENT_METHODS",
    "CONTAINER_DEPLOYMENT_SAFETY_FLAGS",
    "CONTAINER_DEPLOYMENT_STATES",
    "ContainerDeploymentReadinessRecord",
    "build_container_deployment_readiness",
    "build_container_validation_summary",
    "deterministic_container_deployment_json",
    "empty_container_deployment_readiness",
    "infer_container_deployment_state",
    "normalize_container_deployment_method",
    "normalize_container_deployment_state",
    "normalize_container_target_platform",
]
