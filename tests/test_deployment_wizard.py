from __future__ import annotations

import json

from core_engine.packaging import (
    build_auto_updater_readiness,
    build_container_deployment_readiness,
    build_deployment_wizard_summary,
    build_linux_packaging_readiness,
    build_macos_packaging_readiness,
    build_windows_installer_readiness,
    build_wizard_state,
    deterministic_deployment_wizard_json,
    deterministic_wizard_state_json,
    empty_deployment_wizard_summary,
    normalize_deployment_wizard_state,
    normalize_wizard_state_record,
    normalize_wizard_step_state,
    normalize_wizard_step_type,
)


GENERATED_AT = "2026-06-11T12:00:00+00:00"


def test_wizard_state_creation_is_safe():
    state = build_wizard_state(
        step_name="Environment",
        step_type="environment_check",
        step_state="complete",
        selected_profile="workstation",
        environment_checks={"platform": "linux", "disk_ok": True},
        rollback_available=True,
        uninstall_available=True,
    ).to_dict()

    assert state["record_type"] == "deployment_wizard_state"
    assert state["step_type"] == "environment_check"
    assert state["step_state"] == "complete"
    assert state["selected_profile"] == "workstation"
    assert state["environment_checks"]["disk_ok"] is True
    assert state["preview_only"] is True
    assert state["destructive_action"] is False
    assert state["installer_executed"] is False
    assert state["filesystem_written"] is False


def test_step_type_and_state_validation():
    assert normalize_wizard_step_type("profile_selection") == "profile_selection"
    assert normalize_wizard_step_type("bad") == "unknown"
    assert normalize_wizard_step_state("degraded") == "degraded"
    assert normalize_wizard_step_state("bad") == "unknown"

    state = build_wizard_state(step_type="danger", step_state="weird").to_dict()

    assert state["step_type"] == "unknown"
    assert state["step_state"] == "unknown"


def test_windows_readiness_integration():
    windows = build_windows_installer_readiness(generated_at=GENERATED_AT)
    wizard = build_deployment_wizard_summary(
        target_platform="windows",
        selected_install_method="powershell_preview",
        windows_readiness=windows,
        generated_at=GENERATED_AT,
    ).to_dict()

    assert wizard["target_platform"] == "windows"
    assert wizard["windows_readiness"]["record_type"] == "windows_installer_readiness"
    assert wizard["windows_readiness"]["installer_state"] == "ready"
    assert wizard["recommendation_summary"]["install_method_recommendation"] == "powershell_preview"


def test_macos_readiness_integration():
    macos = build_macos_packaging_readiness(
        signing_readiness={"identity_available": True},
        notarization_readiness={"notarization_configured": True},
        generated_at=GENERATED_AT,
    )
    wizard = build_deployment_wizard_summary(target_platform="macos", macos_readiness=macos, generated_at=GENERATED_AT).to_dict()

    assert wizard["macos_readiness"]["record_type"] == "macos_packaging_readiness"
    assert wizard["macos_readiness"]["packaging_state"] == "ready"
    assert wizard["recommendation_summary"]["recommendations"][0] == "use app_bundle_preview for macos preview"


def test_linux_readiness_integration():
    linux = build_linux_packaging_readiness(target_platform="raspberry_pi", distribution_family="raspberry_pi", generated_at=GENERATED_AT)
    wizard = build_deployment_wizard_summary(target_platform="raspberry_pi", linux_readiness=linux, generated_at=GENERATED_AT).to_dict()

    assert wizard["linux_readiness"]["record_type"] == "linux_packaging_readiness"
    assert wizard["linux_readiness"]["raspberry_pi_readiness"]["supported"] is True
    assert wizard["environment_summary"]["platform_selection_summary"]["linux_applicable"] is True


def test_container_readiness_integration():
    container = build_container_deployment_readiness(deployment_method="compose_preview", generated_at=GENERATED_AT)
    wizard = build_deployment_wizard_summary(target_platform="container", container_readiness=container, generated_at=GENERATED_AT).to_dict()

    assert wizard["container_readiness"]["record_type"] == "container_deployment_readiness"
    assert wizard["container_readiness"]["deployment_method"] == "compose_preview"
    assert wizard["environment_summary"]["platform_selection_summary"]["container_applicable"] is True


def test_updater_readiness_integration():
    updater = build_auto_updater_readiness(update_method="offline_preview", generated_at=GENERATED_AT)
    wizard = build_deployment_wizard_summary(updater_readiness=updater, generated_at=GENERATED_AT).to_dict()

    assert wizard["updater_readiness"]["record_type"] == "auto_updater_readiness"
    assert wizard["updater_readiness"]["update_method"] == "offline_preview"
    assert wizard["validation_summary"]["readiness_states"]


def test_platform_selection_summary():
    wizard = build_deployment_wizard_summary(target_platform="linux_arm", generated_at=GENERATED_AT).to_dict()
    summary = wizard["environment_summary"]["platform_selection_summary"]

    assert summary["selected_platform"] == "linux_arm"
    assert summary["linux_applicable"] is True
    assert summary["container_applicable"] is True
    assert summary["windows_applicable"] is False


def test_install_method_and_profile_recommendations():
    wizard = build_deployment_wizard_summary(
        target_platform="container",
        selected_install_method="compose_preview",
        selected_profile="edge",
        generated_at=GENERATED_AT,
    ).to_dict()

    assert wizard["selected_install_method"] == "compose_preview"
    assert wizard["selected_profile"] == "edge"
    assert wizard["recommendation_summary"]["install_method_recommendation"] == "compose_preview"
    assert wizard["recommendation_summary"]["profile_recommendation"] == "edge"


def test_environment_and_validation_summaries():
    wizard = build_deployment_wizard_summary(generated_at=GENERATED_AT).to_dict()

    assert wizard["environment_summary"]["record_type"] == "deployment_wizard_environment_summary"
    assert wizard["validation_summary"]["record_type"] == "deployment_wizard_validation_summary"
    assert wizard["validation_summary"]["step_summary"]["step_count"] == len(wizard["wizard_steps"])
    assert wizard["validation_summary"]["preview_only"] is True


def test_rollback_and_uninstall_summary():
    wizard = build_deployment_wizard_summary(generated_at=GENERATED_AT).to_dict()

    assert wizard["rollback_summary"]["rollback_available"] is True
    assert "windows" in wizard["rollback_summary"]["rollback_sources"]
    assert wizard["uninstall_summary"]["uninstall_available"] is True
    assert "container" in wizard["uninstall_summary"]["uninstall_sources"]


def test_tui_screen_recommendation_behavior():
    wizard = build_deployment_wizard_summary(generated_at=GENERATED_AT).to_dict()

    assert wizard["tui_screen_recommendation"]["dedicated_tui_screen_recommended"] is True
    assert wizard["tui_screen_recommendation"]["recommended_screen"] == "deployment_wizard"
    assert "dedicated tab" in wizard["tui_screen_recommendation"]["reason"]


def test_malformed_input_handling():
    state = normalize_wizard_state_record(object()).to_dict()
    wizard = build_deployment_wizard_summary(
        target_platform="bad",
        wizard_steps=[{"step_type": "bad", "step_state": "bad"}],
        generated_at=GENERATED_AT,
    ).to_dict()

    assert state["step_type"] == "unknown"
    assert state["preview_only"] is True
    assert normalize_deployment_wizard_state("bad") == "unknown"
    assert wizard["wizard_state"] == "unavailable"
    assert wizard["wizard_steps"][0]["step_type"] == "unknown"


def test_empty_degraded_and_blocked_behavior():
    empty = empty_deployment_wizard_summary(generated_at=GENERATED_AT).to_dict()
    degraded = build_deployment_wizard_summary(
        updater_readiness=build_auto_updater_readiness(checksum_validation={"checksum_available": False}, generated_at=GENERATED_AT),
        generated_at=GENERATED_AT,
    ).to_dict()
    blocked = build_deployment_wizard_summary(
        windows_readiness={"record_type": "windows_installer_readiness", "installer_state": "blocked"},
        generated_at=GENERATED_AT,
    ).to_dict()

    assert empty["wizard_state"] == "unavailable"
    assert degraded["wizard_state"] == "degraded"
    assert blocked["wizard_state"] == "blocked"


def test_preview_and_destructive_flags_are_fixed():
    wizard = build_deployment_wizard_summary(generated_at=GENERATED_AT).to_dict()

    assert wizard["preview_only"] is True
    assert wizard["destructive_action"] is False
    for step in wizard["wizard_steps"]:
        assert step["preview_only"] is True
        assert step["destructive_action"] is False


def test_export_safe_serialization():
    state = build_wizard_state(step_type="summary", step_state="complete")
    wizard = build_deployment_wizard_summary(generated_at=GENERATED_AT)

    json.loads(deterministic_wizard_state_json(state))
    json.loads(deterministic_deployment_wizard_json(wizard))
    json.dumps(wizard.to_dict(), sort_keys=True)


def test_no_installer_filesystem_or_service_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    wizard = build_deployment_wizard_summary(generated_at=GENERATED_AT).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert wizard["installer_executed"] is False
    assert wizard["install_action_executed"] is False
    assert wizard["service_created"] is False
    assert wizard["filesystem_written"] is False
    assert wizard["admin_escalation_requested"] is False


def test_cross_platform_compatibility():
    for target in ["cross_platform", "windows", "macos", "linux", "raspberry_pi", "linux_arm", "container"]:
        wizard = build_deployment_wizard_summary(target_platform=target, generated_at=GENERATED_AT).to_dict()
        assert wizard["target_platform"] == target
        assert wizard["wizard_state"] in {"guided_ready", "degraded", "blocked"}
