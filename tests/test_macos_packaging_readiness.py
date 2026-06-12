from __future__ import annotations

import json

from core_engine.packaging import (
    build_macos_layout_preview,
    build_macos_packaging_readiness,
    deterministic_macos_layout_json,
    deterministic_macos_packaging_json,
    empty_macos_packaging_readiness,
    normalize_macos_install_scope,
    normalize_macos_layout_preview,
    normalize_macos_layout_type,
    normalize_macos_package_method,
    normalize_macos_packaging_state,
    sanitize_path_preview,
)


GENERATED_AT = "2026-06-11T12:00:00+00:00"


def test_macos_layout_preview_generation_is_safe():
    layout = build_macos_layout_preview(
        layout_type="app_bundle_preview",
        bundle_identifier="ai.portmap.preview",
        app_name="PortMap-AI",
        install_scope="user",
        path_preview="/Applications/PortMap-AI.app",
        rollback_available=True,
        uninstall_available=True,
    ).to_dict()

    assert layout["record_type"] == "macos_layout_preview"
    assert layout["layout_type"] == "app_bundle_preview"
    assert layout["install_scope"] == "user"
    assert layout["preview_only"] is True
    assert layout["destructive_action"] is False
    assert layout["filesystem_written"] is False
    assert layout["launchd_modified"] is False
    assert layout["signing_performed"] is False
    assert layout["notarization_performed"] is False


def test_layout_type_and_install_scope_validation():
    assert normalize_macos_layout_type("pkg_installer_preview") == "pkg_installer_preview"
    assert normalize_macos_layout_type("bad") == "unknown"
    assert normalize_macos_install_scope("portable") == "portable"
    assert normalize_macos_install_scope("bad") == "unknown"

    layout = build_macos_layout_preview(layout_type="danger", install_scope="root").to_dict()

    assert layout["layout_type"] == "unknown"
    assert layout["install_scope"] == "unknown"


def test_path_preview_sanitization():
    sanitized = sanitize_path_preview("/Applications/PortMap-AI.app; launchctl load | whoami && echo test")

    assert ";" not in sanitized
    assert "|" not in sanitized
    assert "&" not in sanitized
    assert "/Applications/PortMap-AI.app" in sanitized


def test_app_bundle_preview_defaults_to_degraded_until_signing_and_notarization_ready():
    readiness = build_macos_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["record_type"] == "macos_packaging_readiness"
    assert readiness["target_platform"] == "macos"
    assert readiness["package_method"] == "app_bundle_preview"
    assert readiness["packaging_state"] == "degraded"
    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    assert readiness["actual_package_created"] is False
    assert readiness["binary_signed"] is False
    assert readiness["notarization_submitted"] is False
    assert readiness["launchd_service_loaded"] is False
    assert readiness["admin_escalation_requested"] is False


def test_pkg_preview_marks_admin_context_as_degraded_without_escalation():
    readiness = build_macos_packaging_readiness(
        package_method="pkg_preview",
        admin_required=True,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["package_method"] == "pkg_preview"
    assert readiness["packaging_state"] == "degraded"
    assert readiness["admin_required"] is True
    assert readiness["admin_escalation_requested"] is False
    assert "future_admin_if_operator_approved" in readiness["required_permissions"]


def test_dmg_homebrew_and_cli_only_preview_methods():
    dmg = build_macos_packaging_readiness(package_method="dmg_preview", generated_at=GENERATED_AT).to_dict()
    brew = build_macos_packaging_readiness(package_method="homebrew_preview", generated_at=GENERATED_AT).to_dict()
    cli = build_macos_packaging_readiness(package_method="cli_only_preview", generated_at=GENERATED_AT).to_dict()

    assert dmg["package_method"] == "dmg_preview"
    assert "Volumes" in dmg["layout_previews"][0]["path_preview"]
    assert brew["package_method"] == "homebrew_preview"
    assert brew["layout_previews"][0]["layout_type"] == "cli_only_preview"
    assert cli["package_method"] == "cli_only_preview"
    assert cli["layout_previews"][0]["layout_type"] == "cli_only_preview"


def test_launchd_service_preview_has_no_launchd_side_effects():
    readiness = build_macos_packaging_readiness(generated_at=GENERATED_AT).to_dict()
    launchd = readiness["launchd_preview"]

    assert launchd["preview_type"] == "service_install"
    assert launchd["platform_family"] == "macos"
    assert launchd["command_executed"] is False
    assert readiness["launchd_plist_written"] is False
    assert readiness["launchd_service_loaded"] is False
    assert readiness["launchd_service_modified"] is False


def test_signing_and_notarization_readiness_can_make_record_ready():
    readiness = build_macos_packaging_readiness(
        signing_readiness={"identity_available": True},
        notarization_readiness={"notarization_configured": True},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["packaging_state"] == "ready"
    assert readiness["signing_readiness"]["identity_required"] is True
    assert readiness["signing_readiness"]["identity_available"] is True
    assert readiness["signing_readiness"]["signing_performed"] is False
    assert readiness["notarization_readiness"]["notarization_configured"] is True
    assert readiness["notarization_readiness"]["notarization_submitted"] is False


def test_uninstall_and_rollback_previews_are_present():
    readiness = build_macos_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["uninstall_preview"]["preview_type"] == "uninstall"
    assert readiness["rollback_preview"]["preview_type"] == "rollback"
    assert readiness["uninstall_preview"]["filesystem_written"] is False
    assert readiness["rollback_preview"]["destructive_action"] is False


def test_validation_summary_counts_layouts_and_previews():
    readiness = build_macos_packaging_readiness(generated_at=GENERATED_AT).to_dict()
    validation = readiness["validation_summary"]

    assert validation["record_type"] == "macos_packaging_validation_summary"
    assert validation["layout_summary"]["layout_count"] == 1
    assert validation["preview_summary"]["preview_count"] == 3
    assert validation["preview_summary"]["type_counts"]["service_install"] == 1
    assert validation["preview_summary"]["type_counts"]["uninstall"] == 1
    assert validation["preview_summary"]["type_counts"]["rollback"] == 1
    assert validation["preview_only"] is True
    assert validation["destructive_action"] is False


def test_malformed_input_handling():
    layout = normalize_macos_layout_preview(object()).to_dict()
    blocked = build_macos_packaging_readiness(
        target_platform="windows",
        package_method="invalid",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert layout["layout_type"] == "unknown"
    assert layout["preview_only"] is True
    assert normalize_macos_package_method("bad") == "unknown"
    assert normalize_macos_packaging_state("bad") == "unknown"
    assert blocked["packaging_state"] == "unavailable"


def test_empty_readiness_summary_is_unavailable():
    readiness = empty_macos_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["packaging_state"] == "unavailable"
    assert readiness["package_method"] == "unknown"


def test_preview_and_destructive_flags_are_fixed():
    readiness = build_macos_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    for layout in readiness["layout_previews"]:
        assert layout["preview_only"] is True
        assert layout["destructive_action"] is False
    for key in ["launchd_preview", "uninstall_preview", "rollback_preview"]:
        assert readiness[key]["preview_only"] is True
        assert readiness[key]["destructive_action"] is False


def test_no_filesystem_launchd_signing_or_notarization_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    readiness = build_macos_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert readiness["filesystem_written"] is False
    assert readiness["launchd_plist_written"] is False
    assert readiness["launchd_service_loaded"] is False
    assert readiness["binary_signed"] is False
    assert readiness["notarization_submitted"] is False


def test_export_safe_serialization():
    layout = build_macos_layout_preview(layout_type="cli_only_preview", path_preview="~/bin/portmap")
    readiness = build_macos_packaging_readiness(generated_at=GENERATED_AT)

    json.loads(deterministic_macos_layout_json(layout))
    json.loads(deterministic_macos_packaging_json(readiness))
    json.dumps(readiness.to_dict(), sort_keys=True)


def test_cross_platform_compatibility_non_macos_target_is_unavailable():
    readiness = build_macos_packaging_readiness(target_platform="linux", generated_at=GENERATED_AT).to_dict()

    assert readiness["target_platform"] == "unknown"
    assert readiness["packaging_state"] == "unavailable"
