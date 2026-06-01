import json
import re

from core_engine.deployment import (
    build_deployment_operator_api_view,
    build_deployment_operator_dashboard_view,
    build_deployment_operator_summary,
    calculate_readiness_score,
    deployment_summary_to_dict,
    export_deployment_operator_view,
    export_deployment_summary,
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


def _ready_inputs():
    return {
        "runtime_profile": {"record_type": "deployment_runtime_profile", "profile_name": "production"},
        "service_lifecycle": {"record_type": "service_lifecycle_preview_plan", "readiness_state": "ready"},
        "deployment_manifest": {"record_type": "deployment_manifest", "deployment_readiness": {"state": "ready"}},
        "upgrade_readiness": {"record_type": "upgrade_readiness_report", "readiness_state": "ready"},
        "backup_plan_set": {"record_type": "deployment_backup_plan_set", "plans": [{"backup_type": "configuration"}]},
        "restore_preview_set": {"record_type": "deployment_restore_preview_set", "previews": [{"restore_type": "config"}]},
        "cross_platform_validation": {"record_type": "cross_platform_validation_report", "state": "ready"},
    }


def test_complete_deployment_summary_composition_ready():
    summary = build_deployment_operator_summary(**_ready_inputs(), generated_at=FIXED_TIME)

    assert summary["deployment_state"] == "ready"
    assert summary["readiness_score"] == 100
    assert len(summary["supported_components"]) == 6
    assert summary["degraded_components"] == []
    assert summary["unavailable_components"] == []
    assert summary["dry_run_only"] is True
    assert summary["destructive_action"] is False
    assert summary["service_installed"] is False
    assert summary["backup_created"] is False


def test_empty_inputs_render_unknown_without_crashing():
    summary = build_deployment_operator_summary(
        runtime_profile={},
        service_lifecycle={},
        deployment_manifest={},
        upgrade_readiness={},
        backup_plan_set={},
        restore_preview_set={},
        cross_platform_validation={},
        generated_at=FIXED_TIME,
    )

    assert summary["deployment_state"] == "unknown"
    assert summary["readiness_score"] == 25
    assert summary["operator_required_actions"]
    assert summary["unavailable_components"]


def test_degraded_and_blocked_inputs_affect_score_and_state():
    degraded_inputs = _ready_inputs()
    degraded_inputs["service_lifecycle"] = {"readiness_state": "degraded"}
    degraded = build_deployment_operator_summary(**degraded_inputs, generated_at=FIXED_TIME)

    assert degraded["deployment_state"] == "degraded"
    assert 0 < degraded["readiness_score"] < 100
    assert "service_lifecycle_readiness" in degraded["degraded_components"]

    blocked_inputs = _ready_inputs()
    blocked_inputs["deployment_manifest"] = {"deployment_readiness": {"state": "unsupported"}}
    blocked = build_deployment_operator_summary(**blocked_inputs, generated_at=FIXED_TIME)

    assert blocked["deployment_state"] == "blocked"
    assert "deployment_manifests" in blocked["unavailable_components"]


def test_readiness_score_behavior_is_weighted():
    score = calculate_readiness_score(
        {
            "ready": {"state": "ready"},
            "degraded": {"state": "degraded"},
            "blocked": {"state": "blocked"},
            "unknown": {"state": "unknown"},
        }
    )

    assert score == 46


def test_release_checklist_and_operator_actions_are_generated():
    inputs = _ready_inputs()
    inputs["upgrade_readiness"] = {"readiness_state": "degraded"}
    summary = build_deployment_operator_summary(**inputs, generated_at=FIXED_TIME)

    checklist = {item["check_id"]: item for item in summary["release_readiness_checklist"]}
    assert checklist["upgrade_migration_readiness"]["complete"] is False
    assert any(action["component"] == "upgrade_migration_readiness" for action in summary["operator_required_actions"])
    assert any(warning["warning"] == "upgrade_migration_readiness_degraded" for warning in summary["safety_warnings"])


def test_dashboard_and_api_views_are_safe_and_include_rollups():
    summary = build_deployment_operator_summary(**_ready_inputs(), generated_at=FIXED_TIME)
    dashboard = build_deployment_operator_dashboard_view(deployment_summary=summary, generated_at=FIXED_TIME)
    api = build_deployment_operator_api_view(deployment_summary=summary, generated_at=FIXED_TIME)

    assert len(dashboard["summary_cards"]) == 4
    assert dashboard["backup_restore_readiness_rollup"]["state"] == "ready"
    assert dashboard["migration_readiness_rollup"]["state"] == "ready"
    assert dashboard["edge_raspberry_pi_readiness_rollup"]["platform_family"] == "raspberry-pi-linux-arm"
    assert set(dashboard["windows_macos_linux_readiness_rollup"]) == {"windows", "macos", "linux"}
    assert api["deployment_state"] == "ready"
    assert api["dry_run_only"] is True
    assert api["destructive_action"] is False


def test_summary_and_view_serialization_are_export_safe():
    summary = build_deployment_operator_summary(**_ready_inputs(), generated_at=FIXED_TIME)
    view = build_deployment_operator_dashboard_view(deployment_summary=summary, generated_at=FIXED_TIME)

    summary_text = export_deployment_summary(summary)
    view_text = export_deployment_operator_view(view)

    assert json.loads(summary_text) == deployment_summary_to_dict(summary)
    assert json.loads(summary_text)["raw_payload_stored"] is False
    assert json.loads(view_text)["credentials_stored"] is False
    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(summary_text)
        assert not pattern.search(view_text)


def test_malformed_input_states_are_unknown():
    summary = build_deployment_operator_summary(
        runtime_profile={"state": "not-a-real-state"},
        service_lifecycle={"state": "ready"},
        deployment_manifest={"deployment_readiness": {"state": "ready"}},
        upgrade_readiness={"readiness_state": "ready"},
        backup_plan_set={"plans": [{}]},
        restore_preview_set={"previews": [{}]},
        cross_platform_validation={"state": "ready"},
        generated_at=FIXED_TIME,
    )

    assert summary["deployment_state"] == "unknown"
    assert "production_runtime_profiles" in summary["unavailable_components"]
