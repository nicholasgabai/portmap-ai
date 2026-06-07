import json

import pytest

from core_engine.remediation import (
    AutonomyControlError,
    EnforcementModeError,
    autonomy_control_to_dict,
    build_autonomy_control_summary,
    build_autonomy_control_summary_report,
    build_enforcement_mode,
    build_enforcement_mode_summary,
    deterministic_autonomy_control_json,
    deterministic_enforcement_mode_json,
    enforcement_mode_to_dict,
)


NOW = "2026-06-07T12:00:00+00:00"


def test_monitor_mode_generation():
    mode = build_enforcement_mode("monitor", runtime_health_state="healthy", source_mode="fixture", now=NOW)
    exported = enforcement_mode_to_dict(mode)

    assert exported["mode_name"] == "monitor"
    assert exported["mode_state"] == "available"
    assert "observe" in exported["allowed_action_classes"]
    assert "containment_preview" in exported["blocked_action_classes"]
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["enforcement_active"] is False
    assert exported["containment_allowed"] is False
    assert exported["firewall_changes"] is False
    assert json.loads(deterministic_enforcement_mode_json(exported)) == exported


def test_supervised_mode_generation_with_degraded_prerequisites():
    mode = build_enforcement_mode(
        "supervised",
        approval_ready=False,
        guardrails_ready=True,
        rollback_ready=False,
        runtime_health_state="healthy",
        audit_ready=True,
        source_mode="fixture",
        now=NOW,
    )
    exported = enforcement_mode_to_dict(mode)

    assert exported["mode_name"] == "supervised"
    assert exported["mode_state"] == "degraded"
    assert "approval_path_missing" in exported["approval_requirements"]
    assert "rollback_preview_missing" in exported["rollback_requirements"]
    assert "escalation_preview" in exported["allowed_action_classes"]
    assert exported["containment_allowed"] is False


def test_autonomous_and_hardened_preview_modeling():
    autonomous = build_enforcement_mode(
        "autonomous_preview",
        approval_ready=True,
        guardrails_ready=True,
        rollback_ready=True,
        provider_ready=True,
        runtime_health_state="healthy",
        audit_ready=True,
        emergency_stop_ready=True,
        source_mode="fixture",
        now=NOW,
    )
    hardened = build_enforcement_mode(
        "hardened_preview",
        approval_ready=True,
        guardrails_ready=True,
        rollback_ready=True,
        provider_ready=False,
        runtime_health_state="healthy",
        audit_ready=True,
        emergency_stop_ready=True,
        source_mode="fixture",
        now=NOW,
    )

    assert autonomous.mode_state == "available"
    assert "containment_preview" in autonomous.allowed_action_classes
    assert autonomous.preview_only is True
    assert autonomous.destructive_action is False
    assert hardened.mode_state == "blocked"
    assert "provider_readiness_missing" in hardened.provider_requirements
    assert hardened.preview_only is True
    assert hardened.destructive_action is False


def test_approval_audit_guardrail_rollback_provider_runtime_and_emergency_requirements():
    mode = build_enforcement_mode(
        "autonomous_preview",
        approval_ready=False,
        guardrails_ready=False,
        rollback_ready=False,
        provider_ready=False,
        runtime_health_state="degraded",
        audit_ready=False,
        emergency_stop_ready=False,
        source_mode="fixture",
        now=NOW,
    )
    exported = enforcement_mode_to_dict(mode)

    assert exported["mode_state"] == "blocked"
    assert "approval_path_missing" in exported["approval_requirements"]
    assert "guardrail_summary_missing" in exported["safety_guardrails_required"]
    assert "rollback_preview_missing" in exported["rollback_requirements"]
    assert "provider_readiness_missing" in exported["provider_requirements"]
    assert "runtime_health_not_ready:degraded" in exported["runtime_health_requirements"]
    assert "emergency_stop_missing" in exported["runtime_health_requirements"]
    assert "audit_summary_missing" in exported["audit_requirements"]


def test_blocked_and_unavailable_runtime_states():
    blocked = build_enforcement_mode(
        "supervised",
        approval_ready=True,
        guardrails_ready=True,
        rollback_ready=True,
        runtime_health_state="blocked",
        audit_ready=True,
        source_mode="fixture",
        now=NOW,
    )

    assert blocked.mode_state == "blocked"
    assert "runtime_health:blocked" in blocked.runtime_health_requirements
    assert "containment_preview" in blocked.blocked_action_classes


def test_autonomy_control_summaries_keep_containment_disabled():
    mode = build_enforcement_mode(
        "autonomous_preview",
        approval_ready=True,
        guardrails_ready=True,
        rollback_ready=True,
        provider_ready=True,
        runtime_health_state="healthy",
        audit_ready=True,
        emergency_stop_ready=True,
        source_mode="fixture",
        now=NOW,
    )
    control = build_autonomy_control_summary(
        mode,
        emergency_stop_ready=True,
        audit_ready=True,
        source_mode="fixture",
        now=NOW,
    )
    exported = autonomy_control_to_dict(control)

    assert exported["selected_mode"] == "autonomous_preview"
    assert exported["autonomy_level"] == "autonomous_preview"
    assert exported["escalation_allowed"] is True
    assert exported["containment_allowed"] is False
    assert exported["approval_required"] is True
    assert exported["emergency_stop_required"] is True
    assert exported["audit_required"] is True
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["firewall_changes"] is False
    assert json.loads(deterministic_autonomy_control_json(exported)) == exported


def test_autonomy_controls_recommend_safer_mode_when_blocked():
    mode = build_enforcement_mode(
        "hardened_preview",
        approval_ready=True,
        guardrails_ready=True,
        rollback_ready=True,
        provider_ready=False,
        runtime_health_state="healthy",
        audit_ready=True,
        emergency_stop_ready=False,
        source_mode="fixture",
        now=NOW,
    )
    control = build_autonomy_control_summary(
        mode,
        guardrail_blockers=["blast_radius:critical"],
        emergency_stop_ready=False,
        audit_ready=True,
        source_mode="fixture",
        now=NOW,
    )

    assert control.readiness_state == "blocked"
    assert control.recommended_mode == "monitor"
    assert control.containment_allowed is False
    assert "blast_radius:critical" in control.safety_blockers
    assert "remain_in_monitor_mode" in control.operator_actions


def test_mode_and_control_summaries_export_safely():
    modes = [
        build_enforcement_mode("monitor", runtime_health_state="healthy", source_mode="fixture", now=NOW),
        build_enforcement_mode(
            "supervised",
            approval_ready=True,
            guardrails_ready=True,
            rollback_ready=True,
            runtime_health_state="healthy",
            audit_ready=True,
            source_mode="fixture",
            now=NOW,
        ),
    ]
    controls = [
        build_autonomy_control_summary(row, emergency_stop_ready=False, audit_ready=True, source_mode="fixture", now=NOW)
        for row in modes
    ]
    mode_summary = build_enforcement_mode_summary(modes)
    control_summary = build_autonomy_control_summary_report(controls)
    serialized = json.dumps(
        {
            "modes": [enforcement_mode_to_dict(row) for row in modes],
            "controls": [autonomy_control_to_dict(row) for row in controls],
            "mode_summary": mode_summary,
            "control_summary": control_summary,
        },
        sort_keys=True,
    )

    assert mode_summary["mode_count"] == 2
    assert mode_summary["preview_only"] is True
    assert mode_summary["containment_allowed"] is False
    assert control_summary["control_count"] == 2
    assert control_summary["containment_allowed"] is False
    assert control_summary["preview_only"] is True
    assert "192.168." not in serialized
    assert "/" + "Users/" not in serialized
    assert "PRIVATE" + " KEY" not in serialized


def test_malformed_mode_handling_and_direct_safety_validation():
    fallback = build_enforcement_mode("unsupported_mode", runtime_health_state="healthy", source_mode="fixture", now=NOW)
    control = build_autonomy_control_summary({"mode_name": "bad", "mode_state": "bad"}, source_mode="fixture", now=NOW)

    assert fallback.mode_name == "monitor"
    assert control.autonomy_level == "advisory"
    assert control.containment_allowed is False

    with pytest.raises(EnforcementModeError):
        fallback.__class__(
            mode_id="mode-bad",
            mode_name="monitor",
            mode_state="available",
            allowed_action_classes=["execute"],
        )
    with pytest.raises(AutonomyControlError):
        control.__class__(
            control_id="control-bad",
            selected_mode="autonomous_preview",
            autonomy_level="autonomous_preview",
            escalation_allowed=True,
            containment_allowed=True,
            approval_required=True,
            emergency_stop_required=True,
            audit_required=True,
        )


def test_cross_platform_compatibility_no_side_effects():
    mode = build_enforcement_mode(
        "supervised",
        approval_ready=True,
        guardrails_ready=True,
        rollback_ready=True,
        provider_ready=False,
        runtime_health_state="healthy",
        audit_ready=True,
        source_mode="fixture",
        now=NOW,
    )
    exported = enforcement_mode_to_dict(mode)

    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["enforcement_active"] is False
    assert exported["containment_allowed"] is False
    assert exported["automatic_changes"] is False
    assert exported["service_changes"] is False
    assert exported["process_changes"] is False
