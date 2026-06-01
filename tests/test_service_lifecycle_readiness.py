import json
import re

from core_engine.deployment import (
    SERVICE_LIFECYCLE_ACTIONS,
    build_service_command_preview,
    build_service_lifecycle_preview_plan,
    build_service_lifecycle_readiness,
    build_service_provider_catalog,
    build_service_provider_readiness,
    service_lifecycle_to_dict,
    service_provider_to_dict,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"

PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/Users/"),
    re.compile(r"/home/"),
]


def test_service_provider_catalog_contains_cross_platform_preview_providers():
    catalog = build_service_provider_catalog(generated_at=FIXED_TIME)

    providers = {row["provider"] for row in catalog["providers"]}
    assert providers == {
        "foreground-process",
        "linux-systemd",
        "macos-launchd",
        "raspberry-pi-systemd-edge",
        "windows-service-control-manager",
    }
    assert catalog["dry_run_only"] is True
    assert catalog["service_installed"] is False
    assert catalog["windows_service_registered"] is False


def test_linux_systemd_provider_readiness_is_preview_only():
    readiness = build_service_provider_readiness(
        platform_info={"system": "Linux", "release": "linux-release-placeholder", "machine": "x86_64", "python_version": "3.11.5"},
        provider="systemd",
        generated_at=FIXED_TIME,
    )

    assert readiness["provider"] == "linux-systemd"
    assert readiness["platform"] == "linux"
    assert readiness["state"] == "supported"
    assert readiness["systemd_unit_created"] is False
    assert readiness["admin_elevation_requested"] is False
    assert "systemd_preview_only" in readiness["warnings"]


def test_windows_service_provider_reports_degraded_without_admin_but_no_elevation():
    readiness = build_service_provider_readiness(
        platform_info={"system": "Windows", "release": "windows-release-placeholder", "machine": "AMD64", "python_version": "3.11.5"},
        provider="windows",
        is_admin=False,
        generated_at=FIXED_TIME,
    )

    assert readiness["provider"] == "windows-service-control-manager"
    assert readiness["state"] == "degraded"
    assert readiness["permission_summary"]["admin_or_root_required_for_future_operator_action"] is True
    assert readiness["admin_elevation_requested"] is False
    assert readiness["registry_changed"] is False


def test_provider_platform_mismatch_is_unavailable():
    readiness = build_service_provider_readiness(
        platform_info={"system": "Darwin", "release": "macos-release-placeholder", "machine": "arm64", "python_version": "3.11.5"},
        provider="linux-systemd",
        generated_at=FIXED_TIME,
    )

    assert readiness["state"] == "unavailable"
    assert "provider_platform_mismatch" in readiness["warnings"]


def test_lifecycle_preview_generation_for_all_actions_is_non_destructive():
    provider = build_service_provider_readiness(
        platform_info={"system": "Linux", "release": "linux-release-placeholder", "machine": "x86_64", "python_version": "3.11.5"},
        provider="linux-systemd",
        generated_at=FIXED_TIME,
    )
    plan = build_service_lifecycle_preview_plan(
        service_name="PortMap Runtime!",
        provider_readiness=provider,
        generated_at=FIXED_TIME,
    )

    assert {row["action"] for row in plan["previews"]} == SERVICE_LIFECYCLE_ACTIONS
    for preview in plan["previews"]:
        assert preview["service_name"] == "portmap-runtime"
        assert preview["dry_run_only"] is True
        assert preview["destructive_action"] is False
        assert preview["commands_executed"] is False
        assert preview["service_installed"] is False
        assert preview["service_started"] is False
        assert preview["service_stopped"] is False
        assert preview["command_preview"]["sanitized"] is True


def test_lifecycle_preview_uses_sanitized_command_text():
    preview = build_service_lifecycle_readiness(
        service_name="PortMap Runtime!",
        action="install_preview",
        platform_info={"system": "Darwin", "release": "macos-release-placeholder", "machine": "arm64", "python_version": "3.11.5"},
        provider="launchd",
        generated_at=FIXED_TIME,
    )
    serialized = json.dumps(preview, sort_keys=True)

    assert preview["service_name"] == "portmap-runtime"
    assert preview["provider"] == "macos-launchd"
    assert "<operator-reviewed-plist>" in preview["command_preview"]["command"]
    assert preview["launch_agent_created"] is False
    assert preview["command_preview_sanitized"] is True
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(serialized)


def test_foreground_process_marks_install_preview_unavailable():
    preview = build_service_lifecycle_readiness(
        action="install_preview",
        platform_info={"system": "Unknown", "release": "unknown-release-placeholder", "machine": "unknown", "python_version": "3.11.5"},
        provider="foreground-process",
        generated_at=FIXED_TIME,
    )

    assert preview["provider"] == "foreground-process"
    assert preview["readiness_state"] == "unavailable"
    assert preview["dry_run_only"] is True
    assert preview["destructive_action"] is False


def test_service_provider_and_lifecycle_serialization_are_export_safe():
    provider = build_service_provider_readiness(
        platform_info={"system": "Linux", "release": "raspberry-pi-release-placeholder", "machine": "aarch64", "python_version": "3.11.5"},
        generated_at=FIXED_TIME,
    )
    preview = build_service_lifecycle_readiness(
        service_name="portmap-worker",
        action="status_preview",
        provider_readiness=provider,
        generated_at=FIXED_TIME,
    )

    provider_payload = service_provider_to_dict(provider)
    preview_payload = service_lifecycle_to_dict(preview)
    serialized = json.dumps({"provider": provider_payload, "preview": preview_payload}, sort_keys=True)

    assert provider_payload["export_safe"] is True
    assert preview_payload["export_safe"] is True
    assert provider_payload["raw_payload_stored"] is False
    assert preview_payload["credentials_stored"] is False
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(serialized)


def test_windows_command_preview_is_sanitized_and_not_executed():
    command = build_service_command_preview(
        service_name="PortMap Worker",
        provider="windows-service-control-manager",
        action="start_preview",
    )

    assert command["command"] == ["sc.exe", "start", "portmap-worker"]
    assert command["executed"] is False
    assert command["registry_changed"] is False
    assert command["windows_service_registered"] is False
