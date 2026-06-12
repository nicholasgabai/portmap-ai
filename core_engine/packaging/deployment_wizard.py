from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.packaging.auto_updater import (
    AutoUpdaterReadinessRecord,
    build_auto_updater_readiness,
)
from core_engine.packaging.container_deployment import (
    ContainerDeploymentReadinessRecord,
    build_container_deployment_readiness,
)
from core_engine.packaging.installer_previews import PACKAGING_SAFETY_FLAGS, sanitize_list
from core_engine.packaging.linux_packaging import (
    LinuxPackagingReadinessRecord,
    build_linux_packaging_readiness,
)
from core_engine.packaging.macos_packaging import (
    MacOSPackagingReadinessRecord,
    build_macos_packaging_readiness,
)
from core_engine.packaging.windows_installer import (
    WindowsInstallerReadinessRecord,
    build_windows_installer_readiness,
)
from core_engine.packaging.wizard_states import (
    WIZARD_STATE_SAFETY_FLAGS,
    WizardStateRecord,
    build_wizard_state,
    normalize_wizard_state_record,
    summarize_wizard_states,
)
from core_engine.scaling.bus_envelopes import digest, now_timestamp, sanitize_reference, sanitize_text, sanitize_token


DEPLOYMENT_WIZARD_RECORD_VERSION = 1
DEPLOYMENT_WIZARD_STATES = {"ready", "guided_ready", "degraded", "blocked", "unavailable", "unknown"}
DEPLOYMENT_WIZARD_SAFETY_FLAGS = {
    **PACKAGING_SAFETY_FLAGS,
    **WIZARD_STATE_SAFETY_FLAGS,
    "installer_executed": False,
    "install_action_executed": False,
    "package_created": False,
    "service_created": False,
    "service_modified": False,
    "launchd_modified": False,
    "systemd_modified": False,
    "registry_written": False,
    "path_modified": False,
    "container_started": False,
    "update_downloaded": False,
    "filesystem_written": False,
    "admin_escalation_requested": False,
    "credential_stored": False,
    "runtime_behavior_changed": False,
}


@dataclass(frozen=True)
class DeploymentWizardSummaryRecord:
    wizard_id: str
    generated_at: str
    wizard_state: str
    target_platform: str
    selected_install_method: str
    selected_profile: str
    wizard_steps: list[dict[str, Any]] = field(default_factory=list)
    windows_readiness: dict[str, Any] = field(default_factory=dict)
    macos_readiness: dict[str, Any] = field(default_factory=dict)
    linux_readiness: dict[str, Any] = field(default_factory=dict)
    container_readiness: dict[str, Any] = field(default_factory=dict)
    updater_readiness: dict[str, Any] = field(default_factory=dict)
    environment_summary: dict[str, Any] = field(default_factory=dict)
    validation_summary: dict[str, Any] = field(default_factory=dict)
    rollback_summary: dict[str, Any] = field(default_factory=dict)
    uninstall_summary: dict[str, Any] = field(default_factory=dict)
    recommendation_summary: dict[str, Any] = field(default_factory=dict)
    tui_screen_recommendation: dict[str, Any] = field(default_factory=dict)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "deployment_wizard_summary",
            "record_version": DEPLOYMENT_WIZARD_RECORD_VERSION,
            "wizard_id": sanitize_reference(self.wizard_id),
            "generated_at": str(self.generated_at or ""),
            "wizard_state": normalize_deployment_wizard_state(self.wizard_state),
            "target_platform": normalize_wizard_target_platform(self.target_platform),
            "selected_install_method": sanitize_text(self.selected_install_method) or "manual_preview",
            "selected_profile": sanitize_text(self.selected_profile) or "default",
            "wizard_steps": list(self.wizard_steps),
            "windows_readiness": dict(self.windows_readiness),
            "macos_readiness": dict(self.macos_readiness),
            "linux_readiness": dict(self.linux_readiness),
            "container_readiness": dict(self.container_readiness),
            "updater_readiness": dict(self.updater_readiness),
            "environment_summary": dict(self.environment_summary),
            "validation_summary": dict(self.validation_summary),
            "rollback_summary": dict(self.rollback_summary),
            "uninstall_summary": dict(self.uninstall_summary),
            "recommendation_summary": dict(self.recommendation_summary),
            "tui_screen_recommendation": dict(self.tui_screen_recommendation),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **DEPLOYMENT_WIZARD_SAFETY_FLAGS,
        }


def build_deployment_wizard_summary(
    *,
    wizard_id: Any = "",
    generated_at: Any = None,
    target_platform: Any = "cross_platform",
    selected_install_method: Any = "manual_preview",
    selected_profile: Any = "default",
    wizard_steps: Iterable[WizardStateRecord | dict[str, Any] | Any] | None = None,
    windows_readiness: WindowsInstallerReadinessRecord | dict[str, Any] | Any | None = None,
    macos_readiness: MacOSPackagingReadinessRecord | dict[str, Any] | Any | None = None,
    linux_readiness: LinuxPackagingReadinessRecord | dict[str, Any] | Any | None = None,
    container_readiness: ContainerDeploymentReadinessRecord | dict[str, Any] | Any | None = None,
    updater_readiness: AutoUpdaterReadinessRecord | dict[str, Any] | Any | None = None,
    advisory_notes: Iterable[Any] | None = None,
) -> DeploymentWizardSummaryRecord:
    timestamp = str(generated_at or now_timestamp())
    platform = normalize_wizard_target_platform(target_platform)
    method = sanitize_text(selected_install_method) or "manual_preview"
    profile = sanitize_text(selected_profile) or "default"
    readiness = {
        "windows": normalize_readiness(
            windows_readiness,
            lambda: build_windows_installer_readiness(generated_at=timestamp),
        ),
        "macos": normalize_readiness(
            macos_readiness,
            lambda: build_macos_packaging_readiness(generated_at=timestamp),
        ),
        "linux": normalize_readiness(
            linux_readiness,
            lambda: build_linux_packaging_readiness(generated_at=timestamp),
        ),
        "container": normalize_readiness(
            container_readiness,
            lambda: build_container_deployment_readiness(generated_at=timestamp),
        ),
        "updater": normalize_readiness(
            updater_readiness,
            lambda: build_auto_updater_readiness(generated_at=timestamp),
        ),
    }
    steps = normalize_wizard_steps(wizard_steps, target_platform=platform, selected_profile=profile, readiness=readiness)
    step_rows = [step.to_dict() for step in steps]
    environment = build_environment_summary(platform=platform, readiness=readiness, steps=step_rows)
    validation = build_wizard_validation_summary(
        selected_install_method=method,
        selected_profile=profile,
        readiness=readiness,
        steps=step_rows,
        advisory_notes=advisory_notes,
    )
    rollback = build_rollback_summary(readiness=readiness, steps=step_rows)
    uninstall = build_uninstall_summary(readiness=readiness, steps=step_rows)
    recommendations = build_recommendation_summary(
        target_platform=platform,
        selected_install_method=method,
        selected_profile=profile,
        readiness=readiness,
    )
    tui_recommendation = build_tui_screen_recommendation(step_rows=step_rows, readiness=readiness)
    state = infer_deployment_wizard_state(platform=platform, readiness=readiness, steps=step_rows)
    safe_id = sanitize_reference(wizard_id)
    if not safe_id:
        safe_id = "deployment-wizard-" + digest(
            {
                "generated_at": timestamp,
                "target_platform": platform,
                "selected_install_method": method,
                "selected_profile": profile,
                "step_count": len(step_rows),
            }
        )[:16]
    return DeploymentWizardSummaryRecord(
        wizard_id=safe_id,
        generated_at=timestamp,
        wizard_state=state,
        target_platform=platform,
        selected_install_method=method,
        selected_profile=profile,
        wizard_steps=step_rows,
        windows_readiness=readiness["windows"],
        macos_readiness=readiness["macos"],
        linux_readiness=readiness["linux"],
        container_readiness=readiness["container"],
        updater_readiness=readiness["updater"],
        environment_summary=environment,
        validation_summary=validation,
        rollback_summary=rollback,
        uninstall_summary=uninstall,
        recommendation_summary=recommendations,
        tui_screen_recommendation=tui_recommendation,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
    )


def empty_deployment_wizard_summary(*, generated_at: Any = None) -> DeploymentWizardSummaryRecord:
    return build_deployment_wizard_summary(
        generated_at=generated_at,
        target_platform="unknown",
        selected_install_method="unknown",
        selected_profile="unknown",
        wizard_steps=[],
        windows_readiness={},
        macos_readiness={},
        linux_readiness={},
        container_readiness={},
        updater_readiness={},
        advisory_notes=["empty deployment wizard summary"],
    )


def normalize_readiness(value: Any, default_factory: Any) -> dict[str, Any]:
    if value is None:
        return default_factory().to_dict()
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, dict):
        return dict(value)
    return {"record_type": "invalid_readiness", "state": "unknown", "preview_only": True, "destructive_action": False}


def normalize_wizard_steps(
    values: Iterable[WizardStateRecord | dict[str, Any] | Any] | None,
    *,
    target_platform: str,
    selected_profile: str,
    readiness: dict[str, dict[str, Any]],
) -> list[WizardStateRecord]:
    if values is not None:
        return [normalize_wizard_state_record(value) for value in list(values or [])[:32]]
    env_state = "complete" if target_platform != "unknown" else "unavailable"
    readiness_states = readiness_state_values(readiness)
    validation_state = "degraded" if "degraded" in readiness_states else "complete"
    if "blocked" in readiness_states:
        validation_state = "blocked"
    if "unavailable" in readiness_states and target_platform == "unknown":
        validation_state = "unavailable"
    return [
        build_wizard_state(
            step_name="Environment checks",
            step_type="environment_check",
            step_state=env_state,
            selected_profile=selected_profile,
            environment_checks={"target_platform": target_platform, "metadata_only": True},
            rollback_available=False,
            uninstall_available=False,
        ),
        build_wizard_state(
            step_name="Platform selection",
            step_type="platform_selection",
            step_state=env_state,
            selected_profile=selected_profile,
            environment_checks={"selected_platform": target_platform},
        ),
        build_wizard_state(
            step_name="Install method selection",
            step_type="install_method_selection",
            step_state="complete" if target_platform != "unknown" else "blocked",
            selected_profile=selected_profile,
            rollback_available=True,
            uninstall_available=True,
        ),
        build_wizard_state(
            step_name="Profile selection",
            step_type="profile_selection",
            step_state="complete",
            selected_profile=selected_profile,
            rollback_available=True,
            uninstall_available=True,
        ),
        build_wizard_state(
            step_name="Service preview",
            step_type="service_preview",
            step_state=validation_state,
            selected_profile=selected_profile,
            rollback_available=True,
            uninstall_available=True,
        ),
        build_wizard_state(
            step_name="Update preview",
            step_type="update_preview",
            step_state=readiness_record_state(readiness["updater"]),
            selected_profile=selected_profile,
            rollback_available=True,
            uninstall_available=False,
        ),
        build_wizard_state(
            step_name="Validation",
            step_type="validation",
            step_state=validation_state,
            selected_profile=selected_profile,
            rollback_available=True,
            uninstall_available=True,
        ),
        build_wizard_state(
            step_name="Summary",
            step_type="summary",
            step_state=validation_state,
            selected_profile=selected_profile,
            rollback_available=True,
            uninstall_available=True,
        ),
    ]


def build_environment_summary(
    *,
    platform: str,
    readiness: dict[str, dict[str, Any]],
    steps: list[dict[str, Any]],
) -> dict[str, Any]:
    readiness_states = readiness_state_values(readiness)
    return {
        "record_type": "deployment_wizard_environment_summary",
        "target_platform": platform,
        "readiness_states": sorted(set(readiness_states)),
        "step_summary": summarize_wizard_states(steps),
        "platform_selection_summary": platform_selection_summary(platform),
        "metadata_only": True,
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DEPLOYMENT_WIZARD_SAFETY_FLAGS,
    }


def build_wizard_validation_summary(
    *,
    selected_install_method: str,
    selected_profile: str,
    readiness: dict[str, dict[str, Any]],
    steps: list[dict[str, Any]],
    advisory_notes: Iterable[Any] | None = None,
) -> dict[str, Any]:
    step_summary = summarize_wizard_states(steps)
    readiness_states = readiness_state_values(readiness)
    return {
        "record_type": "deployment_wizard_validation_summary",
        "selected_install_method": sanitize_text(selected_install_method) or "manual_preview",
        "selected_profile": sanitize_text(selected_profile) or "default",
        "readiness_states": sorted(set(readiness_states)),
        "step_summary": step_summary,
        "validation_steps": [
            "environment checks summarized",
            "platform selection summarized",
            "install method recommendation generated",
            "profile recommendation generated",
            "readiness records aggregated",
            "rollback and uninstall previews summarized",
            "no install, service, package, container, update, admin, filesystem, or runtime side effect",
        ],
        "advisory_notes": sanitize_list(advisory_notes or []),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DEPLOYMENT_WIZARD_SAFETY_FLAGS,
    }


def build_rollback_summary(*, readiness: dict[str, dict[str, Any]], steps: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "record_type": "deployment_wizard_rollback_summary",
        "rollback_available": any_step_or_readiness_flag(steps, readiness, "rollback_available"),
        "rollback_sources": readiness_flag_sources(readiness, "rollback_preview"),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DEPLOYMENT_WIZARD_SAFETY_FLAGS,
    }


def build_uninstall_summary(*, readiness: dict[str, dict[str, Any]], steps: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "record_type": "deployment_wizard_uninstall_summary",
        "uninstall_available": any_step_or_readiness_flag(steps, readiness, "uninstall_available"),
        "uninstall_sources": readiness_flag_sources(readiness, "uninstall_preview"),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DEPLOYMENT_WIZARD_SAFETY_FLAGS,
    }


def build_recommendation_summary(
    *,
    target_platform: str,
    selected_install_method: str,
    selected_profile: str,
    readiness: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    method = sanitize_text(selected_install_method) or recommended_method_for_platform(target_platform)
    profile = sanitize_text(selected_profile) or "default"
    states = readiness_state_values(readiness)
    recommendations = [
        f"use {recommended_method_for_platform(target_platform)} for {target_platform} preview",
        f"review {profile} profile before any future install action",
        "keep rollback and uninstall previews attached to the deployment summary",
    ]
    if "degraded" in states:
        recommendations.append("resolve degraded readiness records before future operator-approved installation")
    if "blocked" in states:
        recommendations.append("clear blocked readiness records before continuing")
    return {
        "record_type": "deployment_wizard_recommendation_summary",
        "install_method_recommendation": method,
        "profile_recommendation": profile,
        "recommendations": sanitize_list(recommendations),
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DEPLOYMENT_WIZARD_SAFETY_FLAGS,
    }


def build_tui_screen_recommendation(
    *,
    step_rows: list[dict[str, Any]],
    readiness: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    component_count = len([row for row in readiness.values() if row])
    recommended = len(step_rows) > 6 or component_count >= 4
    return {
        "record_type": "deployment_wizard_tui_screen_recommendation",
        "dedicated_tui_screen_recommended": recommended,
        "recommended_screen": "deployment_wizard" if recommended else "current_dashboard",
        "reason": "wizard output spans multiple readiness domains; use a dedicated tab instead of adding crowded dashboard panels"
        if recommended
        else "wizard output is small enough for current dashboard validation",
        "preview_only": True,
        "destructive_action": False,
        "export_safe": True,
        **DEPLOYMENT_WIZARD_SAFETY_FLAGS,
    }


def infer_deployment_wizard_state(
    *,
    platform: str,
    readiness: dict[str, dict[str, Any]],
    steps: list[dict[str, Any]],
) -> str:
    if platform == "unknown":
        return "unavailable"
    step_states = {row.get("step_state", "unknown") for row in steps}
    readiness_states = set(readiness_state_values(readiness))
    if "blocked" in step_states or "blocked" in readiness_states:
        return "blocked"
    if "unavailable" in step_states:
        return "unavailable"
    if "degraded" in step_states or "degraded" in readiness_states:
        return "degraded"
    if not steps:
        return "unknown"
    return "guided_ready"


def readiness_record_state(record: dict[str, Any]) -> str:
    for key in (
        "installer_state",
        "packaging_state",
        "deployment_state",
        "updater_state",
        "wizard_state",
        "state",
    ):
        if key in record:
            value = sanitize_token(record.get(key)).lower()
            return value if value else "unknown"
    return "unknown"


def readiness_state_values(readiness: dict[str, dict[str, Any]]) -> list[str]:
    return [readiness_record_state(record) for record in readiness.values() if record]


def platform_selection_summary(platform: str) -> dict[str, Any]:
    return {
        "selected_platform": platform,
        "windows_applicable": platform in {"cross_platform", "windows"},
        "macos_applicable": platform in {"cross_platform", "macos"},
        "linux_applicable": platform in {"cross_platform", "linux", "raspberry_pi", "linux_arm"},
        "container_applicable": platform in {"cross_platform", "linux", "macos", "windows", "raspberry_pi", "linux_arm", "container"},
        "preview_only": True,
        "destructive_action": False,
    }


def recommended_method_for_platform(platform: str) -> str:
    return {
        "windows": "powershell_preview",
        "macos": "app_bundle_preview",
        "linux": "deb_preview",
        "raspberry_pi": "deb_preview",
        "linux_arm": "tarball_preview",
        "container": "compose_preview",
        "cross_platform": "manual_preview",
    }.get(platform, "manual_preview")


def readiness_flag_sources(readiness: dict[str, dict[str, Any]], key: str) -> list[str]:
    sources: list[str] = []
    for name, record in readiness.items():
        value = record.get(key)
        if isinstance(value, dict) and value:
            sources.append(name)
    return sorted(sources)


def any_step_or_readiness_flag(
    steps: list[dict[str, Any]],
    readiness: dict[str, dict[str, Any]],
    key: str,
) -> bool:
    if any(bool(row.get(key)) for row in steps):
        return True
    for record in readiness.values():
        if bool(record.get(key)):
            return True
        for value in record.values():
            if isinstance(value, dict) and bool(value.get(key)):
                return True
    return False


def normalize_deployment_wizard_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in DEPLOYMENT_WIZARD_STATES else "unknown"


def normalize_wizard_target_platform(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"cross_platform", "windows", "macos", "linux", "raspberry_pi", "linux_arm", "container"}:
        return safe_value
    return "unknown"


def deterministic_deployment_wizard_json(record: DeploymentWizardSummaryRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, DeploymentWizardSummaryRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "DEPLOYMENT_WIZARD_SAFETY_FLAGS",
    "DEPLOYMENT_WIZARD_STATES",
    "DeploymentWizardSummaryRecord",
    "build_deployment_wizard_summary",
    "build_environment_summary",
    "build_recommendation_summary",
    "build_rollback_summary",
    "build_tui_screen_recommendation",
    "build_uninstall_summary",
    "build_wizard_validation_summary",
    "deterministic_deployment_wizard_json",
    "empty_deployment_wizard_summary",
    "infer_deployment_wizard_state",
    "normalize_deployment_wizard_state",
    "normalize_wizard_target_platform",
]
