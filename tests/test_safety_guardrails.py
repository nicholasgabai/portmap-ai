import json

import pytest

from core_engine.remediation import (
    RollbackSimulationError,
    SafetyGuardrailError,
    build_rollback_simulation,
    build_rollback_simulation_summary,
    build_safety_guardrail_summary,
    deterministic_rollback_simulation_json,
    deterministic_safety_guardrail_json,
    evaluate_guardrail,
    guardrail_to_dict,
    rollback_simulation_to_dict,
)


NOW = "2026-06-07T12:00:00+00:00"


def test_approval_gate_behavior():
    missing = evaluate_guardrail(
        guardrail_type="approval_gate",
        evaluated_action="block_port_preview",
        approval_available=False,
        confidence_score=0.8,
        source_mode="fixture",
        now=NOW,
    )
    approved = evaluate_guardrail(
        guardrail_type="approval_gate",
        evaluated_action="manual_review",
        approval_available=True,
        confidence_score=0.8,
        source_mode="fixture",
        now=NOW,
    )

    assert missing.guardrail_state == "requires_approval"
    assert missing.approval_required is True
    assert "operator_approval_missing" in missing.safety_blockers
    assert approved.guardrail_state == "allowed_preview"
    assert approved.preview_only is True
    assert approved.destructive_action is False


def test_rollback_gate_behavior():
    blocked = evaluate_guardrail(
        guardrail_type="rollback_gate",
        evaluated_action="quarantine_preview",
        rollback_available=False,
        rollback_confidence=0.0,
        source_mode="fixture",
        now=NOW,
    )
    degraded = evaluate_guardrail(
        guardrail_type="rollback_gate",
        evaluated_action="quarantine_preview",
        rollback_available=True,
        rollback_confidence=0.4,
        source_mode="fixture",
        now=NOW,
    )
    allowed = evaluate_guardrail(
        guardrail_type="rollback_gate",
        evaluated_action="quarantine_preview",
        rollback_available=True,
        rollback_confidence=0.8,
        source_mode="fixture",
        now=NOW,
    )

    assert blocked.guardrail_state == "blocked"
    assert "rollback_unavailable" in blocked.safety_blockers
    assert degraded.guardrail_state == "degraded"
    assert "rollback_confidence_low" in degraded.safety_blockers
    assert allowed.guardrail_state == "allowed_preview"
    assert all(row.rollback_required is True for row in [blocked, degraded, allowed])


def test_blast_radius_provider_confidence_runtime_policy_and_emergency_gates():
    blast = evaluate_guardrail(
        guardrail_type="blast_radius_gate",
        evaluated_action="isolate_node_preview",
        blast_radius_level="critical",
        source_mode="fixture",
        now=NOW,
    )
    provider = evaluate_guardrail(
        guardrail_type="provider_readiness_gate",
        evaluated_action="block_port_preview",
        provider_readiness_state="unavailable",
        source_mode="fixture",
        now=NOW,
    )
    confidence = evaluate_guardrail(
        guardrail_type="confidence_gate",
        evaluated_action="block_destination_preview",
        confidence_score=0.2,
        source_mode="fixture",
        now=NOW,
    )
    runtime = evaluate_guardrail(
        guardrail_type="runtime_health_gate",
        evaluated_action="block_port_preview",
        runtime_health_state="blocked",
        source_mode="fixture",
        now=NOW,
    )
    policy = evaluate_guardrail(
        guardrail_type="policy_scope_gate",
        evaluated_action="block_port_preview",
        policy_scope_state="out_of_scope",
        source_mode="fixture",
        now=NOW,
    )
    emergency = evaluate_guardrail(
        guardrail_type="emergency_stop_gate",
        evaluated_action="block_port_preview",
        emergency_stop_active=True,
        source_mode="fixture",
        now=NOW,
    )

    assert blast.guardrail_state == "blocked"
    assert "blast_radius:critical" in blast.safety_blockers
    assert provider.guardrail_state == "unavailable"
    assert "provider_state:unavailable" in provider.safety_blockers
    assert confidence.guardrail_state == "blocked"
    assert "confidence_too_low" in confidence.safety_blockers
    assert runtime.guardrail_state == "blocked"
    assert "runtime_health:blocked" in runtime.safety_blockers
    assert policy.guardrail_state == "blocked"
    assert "policy_scope:out_of_scope" in policy.safety_blockers
    assert emergency.guardrail_state == "blocked"
    assert "emergency_stop_active" in emergency.safety_blockers


def test_guardrail_export_safe_serialization_and_summary():
    guardrails = [
        evaluate_guardrail(
            guardrail_type="approval_gate",
            evaluated_action="manual_review",
            approval_available=True,
            confidence_score=0.9,
            source_mode="fixture",
            now=NOW,
        ),
        evaluate_guardrail(
            guardrail_type="confidence_gate",
            evaluated_action="rate_limit_preview",
            confidence_score=0.5,
            source_mode="fixture",
            now=NOW,
        ),
    ]
    exported = [guardrail_to_dict(row) for row in guardrails]
    summary = build_safety_guardrail_summary(guardrails)
    serialized = json.dumps({"guardrails": exported, "summary": summary}, sort_keys=True)

    assert exported[0]["preview_only"] is True
    assert exported[0]["destructive_action"] is False
    assert exported[0]["firewall_changes"] is False
    assert exported[0]["rollback_executed"] is False
    assert summary["guardrail_count"] == 2
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert "192.168." not in serialized
    assert "/" + "Users/" not in serialized
    assert "PRIVATE" + " KEY" not in serialized
    assert deterministic_safety_guardrail_json(exported[0])


def test_rollback_simulation_generation_and_states():
    ready = build_rollback_simulation(
        target_action="block_port_preview",
        rollback_available=True,
        rollback_confidence=0.85,
        required_backups=["config-export-fixture"],
        source_mode="fixture",
        now=NOW,
    )
    degraded = build_rollback_simulation(
        target_action="rate_limit_preview",
        rollback_available=True,
        rollback_confidence=0.5,
        required_backups=["policy-export-fixture"],
        source_mode="fixture",
        now=NOW,
    )
    blocked = build_rollback_simulation(
        target_action="quarantine_service_preview",
        rollback_available=True,
        rollback_confidence=0.2,
        required_backups=["service-state-fixture"],
        source_mode="fixture",
        now=NOW,
    )
    unavailable = build_rollback_simulation(
        target_action="isolate_node_preview",
        rollback_available=False,
        rollback_confidence=0.0,
        source_mode="fixture",
        now=NOW,
    )

    assert ready.simulation_state == "ready"
    assert degraded.simulation_state == "degraded"
    assert blocked.simulation_state == "blocked"
    assert "rollback_confidence_too_low" in blocked.failure_modes
    assert unavailable.simulation_state == "unavailable"
    assert "rollback_plan_missing" in unavailable.failure_modes


def test_rollback_simulation_export_summary_and_no_side_effects():
    simulations = [
        build_rollback_simulation(
            target_action="manual_review",
            rollback_available=True,
            rollback_confidence=0.9,
            required_backups=["operator-notes-fixture"],
            source_mode="fixture",
            now=NOW,
        )
    ]
    exported = rollback_simulation_to_dict(simulations[0])
    summary = build_rollback_simulation_summary(simulations)
    serialized = json.dumps({"simulation": exported, "summary": summary}, sort_keys=True)

    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["rollback_executed"] is False
    assert exported["backups_created"] is False
    assert exported["files_restored"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert summary["simulation_count"] == 1
    assert summary["ready_count"] == 1
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False
    assert "192.168." not in serialized
    assert "/" + "Users/" not in serialized
    assert deterministic_rollback_simulation_json(exported)


def test_malformed_input_handling_and_direct_safety_validation():
    guardrail = evaluate_guardrail(
        guardrail_type="unknown_gate",
        evaluated_action="manual_review",
        confidence_score="bad",
        blast_radius_level="invalid",
        source_mode="fixture",
        now=NOW,
    )
    simulation = build_rollback_simulation(
        target_action="manual_review",
        rollback_available=True,
        rollback_confidence="bad",
        source_mode="fixture",
        now=NOW,
    )

    assert guardrail.guardrail_type == "policy_scope_gate"
    assert guardrail.confidence_score == 0.0
    assert simulation.rollback_confidence == 0.0
    assert simulation.simulation_state == "blocked"

    with pytest.raises(SafetyGuardrailError):
        guardrail.__class__(
            guardrail_id="guardrail-bad",
            guardrail_type="approval_gate",
            guardrail_state="allowed_preview",
            evaluated_action="manual_review",
            action_class="response_preview",
            approval_required=False,
            rollback_required=False,
            blast_radius_level="low",
            preview_only=False,
        )
    with pytest.raises(RollbackSimulationError):
        simulation.__class__(
            rollback_simulation_id="rollback-bad",
            target_action="manual_review",
            rollback_available=True,
            rollback_confidence=0.8,
            simulation_state="ready",
            destructive_action=True,
        )


def test_cross_platform_guardrail_records_do_not_change_state():
    guardrail = evaluate_guardrail(
        guardrail_type="provider_readiness_gate",
        evaluated_action="block_port_preview",
        provider_readiness_state="degraded",
        confidence_score=0.8,
        source_mode="fixture",
        now=NOW,
    )
    exported = guardrail_to_dict(guardrail)

    assert exported["guardrail_state"] == "degraded"
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["automatic_changes"] is False
    assert exported["enforcement_executed"] is False
    assert exported["files_modified"] is False
