from __future__ import annotations

import json

from core_engine.packaging import (
    build_linux_layout_preview,
    build_linux_packaging_readiness,
    deterministic_linux_layout_json,
    deterministic_linux_packaging_json,
    empty_linux_packaging_readiness,
    normalize_linux_distribution_family,
    normalize_linux_install_scope,
    normalize_linux_layout_preview,
    normalize_linux_layout_type,
    normalize_linux_package_method,
    normalize_linux_packaging_state,
    sanitize_linux_path_preview,
)


GENERATED_AT = "2026-06-11T12:00:00+00:00"


def test_linux_layout_preview_generation_is_safe():
    layout = build_linux_layout_preview(
        layout_type="deb_preview",
        distribution_family="debian",
        install_scope="system",
        package_name="portmap-ai",
        path_preview="/usr/share/portmap-ai",
        rollback_available=True,
        uninstall_available=True,
    ).to_dict()

    assert layout["record_type"] == "linux_layout_preview"
    assert layout["layout_type"] == "deb_preview"
    assert layout["distribution_family"] == "debian"
    assert layout["install_scope"] == "system"
    assert layout["package_name"] == "portmap-ai"
    assert layout["preview_only"] is True
    assert layout["destructive_action"] is False
    assert layout["filesystem_written"] is False
    assert layout["package_created"] is False
    assert layout["systemd_modified"] is False


def test_layout_distribution_and_scope_validation():
    assert normalize_linux_layout_type("rpm_preview") == "rpm_preview"
    assert normalize_linux_layout_type("bad") == "unknown"
    assert normalize_linux_distribution_family("raspberry_pi") == "raspberry_pi"
    assert normalize_linux_distribution_family("bad") == "unknown"
    assert normalize_linux_install_scope("portable") == "portable"
    assert normalize_linux_install_scope("bad") == "unknown"

    layout = build_linux_layout_preview(layout_type="danger", distribution_family="mystery", install_scope="root").to_dict()

    assert layout["layout_type"] == "unknown"
    assert layout["distribution_family"] == "unknown"
    assert layout["install_scope"] == "unknown"


def test_path_preview_sanitization():
    sanitized = sanitize_linux_path_preview("/usr/share/portmap-ai; systemctl start x | whoami && echo test")

    assert ";" not in sanitized
    assert "|" not in sanitized
    assert "&" not in sanitized
    assert "/usr/share/portmap-ai" in sanitized


def test_default_deb_preview_is_ready_without_side_effects():
    readiness = build_linux_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["record_type"] == "linux_packaging_readiness"
    assert readiness["target_platform"] == "linux"
    assert readiness["package_method"] == "deb_preview"
    assert readiness["packaging_state"] == "ready"
    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    assert readiness["actual_package_created"] is False
    assert readiness["repository_published"] is False
    assert readiness["systemd_unit_written"] is False
    assert readiness["systemd_service_created"] is False
    assert readiness["admin_escalation_requested"] is False


def test_rpm_preview_and_admin_requirement_summary():
    readiness = build_linux_packaging_readiness(
        package_method="rpm_preview",
        distribution_family="fedora",
        admin_required=True,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["package_method"] == "rpm_preview"
    assert readiness["layout_previews"][0]["layout_type"] == "rpm_preview"
    assert readiness["layout_previews"][0]["distribution_family"] == "fedora"
    assert readiness["packaging_state"] == "degraded"
    assert readiness["admin_required"] is True
    assert readiness["admin_escalation_requested"] is False
    assert "future_admin_if_operator_approved" in readiness["required_permissions"]


def test_tarball_and_cli_only_previews_are_portable_or_user_scoped():
    tarball = build_linux_packaging_readiness(package_method="tarball_preview", generated_at=GENERATED_AT).to_dict()
    cli = build_linux_packaging_readiness(package_method="cli_only_preview", generated_at=GENERATED_AT).to_dict()

    assert tarball["package_method"] == "tarball_preview"
    assert tarball["layout_previews"][0]["layout_type"] == "tarball_preview"
    assert tarball["layout_previews"][0]["install_scope"] == "portable"
    assert cli["package_method"] == "cli_only_preview"
    assert cli["layout_previews"][0]["layout_type"] == "cli_only_preview"
    assert cli["layout_previews"][0]["install_scope"] == "user"


def test_apt_repo_preview_does_not_publish_repository():
    readiness = build_linux_packaging_readiness(
        package_method="apt_repo_preview",
        distribution_family="ubuntu",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["package_method"] == "apt_repo_preview"
    assert readiness["layout_previews"][0]["layout_type"] == "deb_preview"
    assert readiness["repository_published"] is False
    assert readiness["apt_repository_published"] is False


def test_systemd_preview_has_no_systemd_side_effects():
    readiness = build_linux_packaging_readiness(generated_at=GENERATED_AT).to_dict()
    systemd = readiness["systemd_preview"]

    assert systemd["preview_type"] == "service_install"
    assert systemd["platform_family"] == "linux"
    assert systemd["command_executed"] is False
    assert readiness["systemd_unit_written"] is False
    assert readiness["systemd_service_created"] is False
    assert readiness["systemd_service_loaded"] is False
    assert readiness["systemd_service_enabled"] is False


def test_raspberry_pi_readiness():
    readiness = build_linux_packaging_readiness(
        target_platform="raspberry_pi",
        distribution_family="raspberry_pi",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["target_platform"] == "linux"
    assert readiness["raspberry_pi_readiness"]["supported"] is True
    assert readiness["raspberry_pi_readiness"]["preview_only"] is True
    assert readiness["validation_summary"]["raspberry_pi_readiness"]["supported"] is True


def test_linux_arm_readiness():
    readiness = build_linux_packaging_readiness(
        target_platform="linux_arm",
        distribution_family="linux_arm",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert readiness["target_platform"] == "linux"
    assert readiness["linux_arm_readiness"]["supported"] is True
    assert readiness["linux_arm_readiness"]["preview_only"] is True
    assert readiness["validation_summary"]["linux_arm_readiness"]["supported"] is True


def test_uninstall_and_rollback_previews_are_present():
    readiness = build_linux_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["uninstall_preview"]["preview_type"] == "uninstall"
    assert readiness["rollback_preview"]["preview_type"] == "rollback"
    assert readiness["uninstall_preview"]["filesystem_written"] is False
    assert readiness["rollback_preview"]["destructive_action"] is False


def test_validation_summary_counts_layouts_and_previews():
    readiness = build_linux_packaging_readiness(generated_at=GENERATED_AT).to_dict()
    validation = readiness["validation_summary"]

    assert validation["record_type"] == "linux_packaging_validation_summary"
    assert validation["layout_summary"]["layout_count"] == 1
    assert validation["layout_summary"]["type_counts"]["deb_preview"] == 1
    assert validation["preview_summary"]["preview_count"] == 3
    assert validation["preview_summary"]["type_counts"]["service_install"] == 1
    assert validation["preview_summary"]["type_counts"]["uninstall"] == 1
    assert validation["preview_summary"]["type_counts"]["rollback"] == 1
    assert validation["preview_only"] is True
    assert validation["destructive_action"] is False


def test_malformed_input_handling():
    layout = normalize_linux_layout_preview(object()).to_dict()
    blocked = build_linux_packaging_readiness(
        target_platform="macos",
        package_method="invalid",
        distribution_family="bad",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert layout["layout_type"] == "unknown"
    assert layout["preview_only"] is True
    assert normalize_linux_package_method("bad") == "unknown"
    assert normalize_linux_packaging_state("bad") == "unknown"
    assert blocked["packaging_state"] == "unavailable"


def test_empty_readiness_summary_is_unavailable():
    readiness = empty_linux_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["packaging_state"] == "unavailable"
    assert readiness["package_method"] == "unknown"


def test_preview_and_destructive_flags_are_fixed():
    readiness = build_linux_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    assert readiness["preview_only"] is True
    assert readiness["destructive_action"] is False
    for layout in readiness["layout_previews"]:
        assert layout["preview_only"] is True
        assert layout["destructive_action"] is False
    for key in ["systemd_preview", "uninstall_preview", "rollback_preview"]:
        assert readiness[key]["preview_only"] is True
        assert readiness[key]["destructive_action"] is False


def test_no_filesystem_systemd_or_repository_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    readiness = build_linux_packaging_readiness(generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert readiness["filesystem_written"] is False
    assert readiness["actual_package_created"] is False
    assert readiness["repository_published"] is False
    assert readiness["systemd_unit_written"] is False
    assert readiness["systemd_service_created"] is False


def test_export_safe_serialization():
    layout = build_linux_layout_preview(layout_type="cli_only_preview", path_preview="~/.local/bin/portmap")
    readiness = build_linux_packaging_readiness(generated_at=GENERATED_AT)

    json.loads(deterministic_linux_layout_json(layout))
    json.loads(deterministic_linux_packaging_json(readiness))
    json.dumps(readiness.to_dict(), sort_keys=True)


def test_cross_platform_compatibility_non_linux_target_is_unavailable():
    readiness = build_linux_packaging_readiness(target_platform="macos", generated_at=GENERATED_AT).to_dict()

    assert readiness["target_platform"] == "unknown"
    assert readiness["packaging_state"] == "unavailable"
