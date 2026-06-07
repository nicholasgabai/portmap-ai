import json

import pytest

from core_engine.remediation import (
    RemediationError,
    build_adaptive_recommendation,
    build_adaptive_recommendation_summary,
    build_escalation_summary,
    create_remediation_recommendation,
    deterministic_adaptive_remediation_json,
    deterministic_escalation_json,
    escalation_decision_to_dict,
    evaluate_escalation,
    recommendation_to_dict,
)


NOW = "2026-06-06T12:00:00+00:00"


def _policy_eval(**overrides):
    row = {
        "record_type": "policy_runtime_evaluation",
        "policy_id": "policy-flow-review",
        "matched": True,
        "confidence_score": 0.84,
        "approval_required": True,
        "enforcement_mode": "dry_run",
        "destructive_action": False,
        "preview_only": True,
    }
    row.update(overrides)
    return row


def _flow(**overrides):
    row = {
        "flow_reference": "flow-fixture-ssh",
        "session_reference": "session-fixture-ssh",
        "reconstruction_confidence": 0.78,
        "source_mode": "fixture",
    }
    row.update(overrides)
    return row


def _attribution(**overrides):
    row = {
        "attribution_id": "attr-fixture-ssh",
        "attribution_state": "unattributed",
        "attribution_confidence": 0.42,
    }
    row.update(overrides)
    return row


def _drift(**overrides):
    row = {
        "drift_id": "drift-fixture-flow",
        "drift_severity": "high",
        "confidence_score": 0.81,
    }
    row.update(overrides)
    return row


def _topology(**overrides):
    row = {
        "relationship_id": "rel-fixture-management",
        "topology_risk": 0.7,
        "relationship_confidence": 0.76,
    }
    row.update(overrides)
    return row


def test_adaptive_recommendation_generation_and_export_safety():
    recommendation = build_adaptive_recommendation(
        policy_evaluations=[_policy_eval()],
        risk_score=0.55,
        confidence_score=0.74,
        flow_context=[_flow()],
        attribution_context=[_attribution()],
        drift_context=[_drift()],
        topology_context=[_topology()],
        runtime_health={"health_state": "healthy"},
        source_mode="fixture",
        now=NOW,
    )
    exported = recommendation_to_dict(recommendation)

    assert exported["record_type"] == "adaptive_remediation_recommendation"
    assert exported["recommendation_type"] in {"rate_limit_preview", "block_preview", "quarantine_preview"}
    assert exported["approval_required"] is True
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert exported["process_changes"] is False
    assert exported["policy_references"] == ["policy-flow-review"]
    assert exported["flow_references"] == ["flow-fixture-ssh"]
    assert exported["attribution_references"] == ["attr-fixture-ssh"]
    assert exported["drift_references"] == ["drift-fixture-flow"]
    assert exported["topology_references"] == ["rel-fixture-management"]
    assert json.loads(deterministic_adaptive_remediation_json(exported)) == exported


def test_confidence_weighted_action_selection_keeps_low_confidence_in_review():
    recommendation = build_adaptive_recommendation(
        policy_evaluations=[_policy_eval(confidence_score=0.2)],
        risk_score=0.92,
        confidence_score=0.2,
        attribution_context=[_attribution(attribution_confidence=0.1)],
        runtime_health={"health_state": "healthy"},
        source_mode="live",
        now=NOW,
    )

    assert recommendation.recommendation_type in {"monitor", "review"}
    assert recommendation.approval_required is True
    assert recommendation.destructive_action is False
    assert any("Low confidence" in note for note in recommendation.advisory_notes)


def test_high_risk_still_requires_approval_and_rollback_preview():
    recommendation = build_adaptive_recommendation(
        policy_evaluations=[_policy_eval(policy_id="policy-a"), _policy_eval(policy_id="policy-b")],
        risk_score=0.88,
        confidence_score=0.91,
        drift_context=[_drift(drift_severity="critical")],
        topology_context=[_topology(topology_risk=0.9)],
        runtime_health={"health_state": "healthy"},
        source_mode="fixture",
        now=NOW,
    )

    exported = recommendation_to_dict(recommendation)
    assert exported["recommendation_type"] == "quarantine_preview"
    assert exported["approval_required"] is True
    assert exported["rollback_required"] is True
    assert exported["recommended_action"] == "preview_quarantine_plan"
    assert exported["automatic_changes"] is False


def test_unsafe_and_destructive_actions_are_rejected():
    with pytest.raises(RemediationError):
        create_remediation_recommendation(
            recommendation_id="rec-unsafe",
            recommendation_type="block_preview",
            recommended_action="modify_firewall_now",
            destructive_action=False,
        )
    with pytest.raises(RemediationError):
        create_remediation_recommendation(
            recommendation_id="rec-destructive",
            recommendation_type="review",
            recommended_action="operator_review",
            destructive_action=True,
        )
    with pytest.raises(RemediationError):
        create_remediation_recommendation(
            recommendation_id="rec-active",
            recommendation_type="review",
            recommended_action="operator_review",
            enforcement_mode="active",
        )


def test_escalation_state_transitions():
    none = evaluate_escalation(risk_score=0.1, confidence_score=0.9, source_mode="fixture", now=NOW)
    monitor = evaluate_escalation(risk_score=0.4, confidence_score=0.4, source_mode="fixture", now=NOW)
    approval = evaluate_escalation(
        policy_evaluations=[_policy_eval()],
        risk_score=0.7,
        confidence_score=0.9,
        drift_severity="high",
        topology_risk=0.6,
        attribution_state="attributed",
        source_mode="fixture",
        now=NOW,
    )
    blocked = evaluate_escalation(
        policy_evaluations=[_policy_eval()],
        risk_score=0.9,
        confidence_score=0.2,
        runtime_health_state="blocked",
        source_mode="fixture",
        now=NOW,
    )

    assert none.escalation_state == "none"
    assert monitor.escalation_state == "monitor"
    assert approval.escalation_state == "approval_required"
    assert blocked.escalation_state == "blocked_by_safety"
    assert blocked.destructive_action is False
    assert blocked.preview_only is True


def test_policy_flow_attribution_drift_topology_signals_are_included():
    recommendation = build_adaptive_recommendation(
        policy_evaluations=[_policy_eval(policy_id="policy-flow"), _policy_eval(policy_id="policy-topology")],
        risk_score=0.7,
        confidence_score=0.8,
        flow_context=[_flow(flow_reference="flow-one"), _flow(flow_reference="flow-two")],
        attribution_context=[_attribution(attribution_id="attr-one", attribution_state="conflicting")],
        drift_context=[_drift(drift_id="drift-one", drift_severity="medium")],
        topology_context=[_topology(relationship_id="rel-one")],
        runtime_health={"health_state": "degraded"},
        source_mode="fixture",
        now=NOW,
    )
    exported = recommendation_to_dict(recommendation)

    assert "matched_policies:2" in exported["supporting_signals"]
    assert "flow_signals:2" in exported["supporting_signals"]
    assert "attribution_states:conflicting" in exported["supporting_signals"]
    assert "drift_severity:medium" in exported["supporting_signals"]
    assert "runtime_health:degraded" in exported["supporting_signals"]
    assert exported["flow_references"] == ["flow-one", "flow-two"]


def test_preview_flags_summaries_and_serialization_are_safe():
    recommendation = build_adaptive_recommendation(
        policy_evaluations=[_policy_eval()],
        risk_score=0.6,
        confidence_score=0.7,
        source_mode="fixture",
        now=NOW,
    )
    escalation = evaluate_escalation(
        policy_evaluations=[_policy_eval()],
        risk_score=0.7,
        confidence_score=0.8,
        source_mode="fixture",
        now=NOW,
    )
    remediation_summary = build_adaptive_recommendation_summary([recommendation])
    escalation_summary = build_escalation_summary([escalation])
    serialized = json.dumps(
        {
            "recommendation": recommendation_to_dict(recommendation),
            "escalation": escalation_decision_to_dict(escalation),
            "remediation_summary": remediation_summary,
            "escalation_summary": escalation_summary,
        },
        sort_keys=True,
    )

    assert remediation_summary["recommendation_count"] == 1
    assert remediation_summary["preview_only"] is True
    assert remediation_summary["destructive_action"] is False
    assert escalation_summary["decision_count"] == 1
    assert escalation_summary["preview_only"] is True
    assert escalation_summary["destructive_action"] is False
    assert "192.168." not in serialized
    assert "/" + "Users/" not in serialized
    assert "PRIVATE" + " KEY" not in serialized
    assert deterministic_escalation_json(escalation_decision_to_dict(escalation))


def test_malformed_input_degrades_without_side_effects():
    recommendation = build_adaptive_recommendation(
        policy_evaluations=[None, {"matched": True, "policy_id": "policy-ok", "confidence_score": "bad"}],
        risk_score="bad",
        confidence_score="bad",
        flow_context=[None],
        attribution_context=[{"attribution_state": "unknown"}],
        drift_context=[{"severity": "nonsense"}],
        topology_context=[{"relationship_strength": "bad"}],
        runtime_health={"health_state": "healthy"},
        source_mode="unknown",
        now=NOW,
    )
    escalation = evaluate_escalation(
        policy_evaluations=[None, {"matched": True, "confidence_score": "bad"}],
        risk_score="bad",
        confidence_score="bad",
        topology_risk="bad",
        source_mode="unknown",
        now=NOW,
    )

    assert 0.0 <= recommendation.confidence_score <= 1.0
    assert 0.0 <= recommendation.risk_score <= 1.0
    assert recommendation.preview_only is True
    assert recommendation.destructive_action is False
    assert 0.0 <= escalation.confidence_score <= 1.0
    assert escalation.preview_only is True
    assert escalation.destructive_action is False


def test_cross_platform_context_does_not_change_host_state():
    recommendation = build_adaptive_recommendation(
        policy_evaluations=[_policy_eval(policy_id="policy-windows-fixture")],
        risk_score=0.66,
        confidence_score=0.8,
        runtime_health={"health_state": "healthy", "platform_family": "windows"},
        source_mode="fixture",
        now=NOW,
    )
    exported = recommendation_to_dict(recommendation)

    assert exported["source_mode"] == "fixture"
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert exported["process_changes"] is False
