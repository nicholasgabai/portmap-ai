from __future__ import annotations

import json

from core_engine.packaging import (
    build_installer_preview,
    build_windows_installer_readiness,
    deterministic_installer_preview_json,
    deterministic_windows_installer_json,
    empty_windows_installer_readiness,
    normalize_install_method,
    normalize_installer_preview,
    normalize_installer_state,
    normalize_preview_type,
)
from core_engine.packaging.installer_previews import sanitize_command_preview


GENERATED_AT = "2026-06-11T12:00:00+00:00"


def test_installer_preview_creation_is_safe():
    preview = build_installer_preview(
        preview_type="install",
        platform_family="windows",
        action_summary="PowerShell setup preview",
        command_preview="powershell -File <script.ps1> -WhatIf",
        rollback_available=True,
        uninstall_available=True,
    ).to_dict()

    assert preview["record_type"] == "installer_preview"
    assert preview["preview_type"] == "install"
    assert preview["platform_family"] == "windows"
    assert preview["rollback_available"] is True
    assert preview["uninstall_available"] is True
    assert preview["preview_only"] is True
    assert preview["destructive_action"] is False
    assert preview["command_executed"] is False
    assert preview["filesystem_written"] is False
    assert preview["service_created"] is False


def test_preview_type_validation():
    assert normalize_preview_type("service_install") == "service_install"
    assert normalize_preview_type("bad-type") == "unknown"

    preview = build_installer_preview(preview_type="danger", platform_family="windows").to_dict()

    assert preview["preview_type"] == "unknown"


def test_command_preview_sanitization():
    sanitized = sanitize_command_preview("powershell; Remove-Item C:\\temp | whoami && echo test")

    assert ";" not in sanitized
    assert "|" not in sanitized
    assert "&" not in sanitized
    assert "powershell" in sanitized


def test_windows_readiness_generation_defaults_to_ready_preview():
    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["record_type"] == "windows_installer_readiness"
    assert readiness["installer_state"] == "ready"
    assert readiness["target_platform"] == "windows"
    assert readiness["install_method"] == "powershell_preview"
    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    assert readiness["export_safe"] is True
    assert readiness["actual_installer_generated"] is False
    assert readiness["windows_service_created"] is False
    assert readiness["registry_keys_written"] is False
    assert readiness["path_modified"] is False
    assert readiness["admin_escalation_requested"] is False


def test_powershell_preview_path():
    readiness = build_windows_installer_readiness(install_method="powershell_preview", generated_at=GENERATED_AT).to_dict()

    assert readiness["install_method"] == "powershell_preview"
    assert "powershell" in readiness["validation_summary"]["preview_summary"]["permission_counts"] or readiness["installer_state"] == "ready"
    assert "PowerShell" in readiness["install_steps"][1]["action_summary"]


def test_msi_preview_is_degraded_when_admin_or_signing_required():
    readiness = build_windows_installer_readiness(
        install_method="msi_preview",
        admin_required=True,
        signing_required=True,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["install_method"] == "msi_preview"
    assert readiness["installer_state"] == "degraded"
    assert readiness["admin_required"] is True
    assert readiness["signing_required"] is True
    assert readiness["validation_summary"]["admin_escalation_requested"] is False
    assert readiness["validation_summary"]["signing_performed"] is False


def test_service_install_preview_is_present_without_service_creation():
    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()
    service = readiness["service_preview"]

    assert service["preview_type"] == "service_install"
    assert service["service_created"] is False
    assert service["service_modified"] is False
    assert service["command_executed"] is False
    assert readiness["windows_service_created"] is False


def test_shortcut_preview_is_present_without_shortcut_creation():
    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()
    shortcut = readiness["shortcut_preview"]

    assert shortcut["preview_type"] == "shortcut_create"
    assert shortcut["shortcut_created"] is False
    assert shortcut["filesystem_written"] is False


def test_uninstall_and_rollback_previews_are_present():
    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["uninstall_preview"]["preview_type"] == "uninstall"
    assert readiness["rollback_preview"]["preview_type"] == "rollback"
    assert readiness["uninstall_preview"]["destructive_action"] is False
    assert readiness["rollback_preview"]["destructive_action"] is False
    assert readiness["rollback_preview"]["rollback_available"] is True


def test_validation_summary_counts_preview_records():
    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()
    validation = readiness["validation_summary"]

    assert validation["record_type"] == "windows_installer_validation_summary"
    assert validation["preview_summary"]["preview_count"] == 5
    assert validation["preview_summary"]["type_counts"]["install"] == 1
    assert validation["preview_summary"]["type_counts"]["service_install"] == 1
    assert validation["preview_summary"]["type_counts"]["shortcut_create"] == 1
    assert validation["preview_only"] is True
    assert validation["destructive_action"] is False


def test_admin_and_signing_requirement_summaries_do_not_escalate():
    readiness = build_windows_installer_readiness(
        admin_required=True,
        signing_required=True,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["admin_required"] is True
    assert readiness["signing_required"] is True
    assert readiness["admin_escalation_requested"] is False
    assert readiness["validation_summary"]["admin_escalation_requested"] is False
    assert readiness["validation_summary"]["signing_performed"] is False


def test_malformed_input_handling():
    preview = normalize_installer_preview(object()).to_dict()
    blocked = build_windows_installer_readiness(target_platform="linux", install_method="invalid", generated_at=GENERATED_AT).to_dict()

    assert preview["preview_type"] == "unknown"
    assert preview["preview_only"] is True
    assert normalize_install_method("bad") == "unknown"
    assert normalize_installer_state("not-real") == "unknown"
    assert blocked["installer_state"] == "unavailable"


def test_empty_readiness_summary_is_unavailable():
    readiness = empty_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["installer_state"] == "unavailable"
    assert readiness["install_method"] == "unknown"


def test_preview_and_destructive_flags_are_fixed():
    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    for key in ["service_preview", "shortcut_preview", "uninstall_preview", "rollback_preview"]:
        assert readiness[key]["preview_only"] is True
        assert readiness[key]["destructive_action"] is False


def test_no_filesystem_service_or_registry_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert readiness["filesystem_written"] is False
    assert readiness["windows_service_created"] is False
    assert readiness["registry_keys_written"] is False
    assert readiness["path_modified"] is False


def test_export_safe_serialization():
    preview = build_installer_preview(preview_type="validation", platform_family="windows")
    readiness = build_windows_installer_readiness(generated_at=GENERATED_AT)

    json.loads(deterministic_installer_preview_json(preview))
    json.loads(deterministic_windows_installer_json(readiness))
    json.dumps(readiness.to_dict(), sort_keys=True)


def test_cross_platform_compatibility_non_windows_target_is_unavailable():
    readiness = build_windows_installer_readiness(target_platform="macos", generated_at=GENERATED_AT).to_dict()

    assert readiness["target_platform"] == "unknown"
    assert readiness["installer_state"] == "unavailable"
