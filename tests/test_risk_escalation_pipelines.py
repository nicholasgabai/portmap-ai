import json

import pytest

from core_engine.remediation import (
    IncidentCandidateError,
    RiskEscalationError,
    build_incident_candidate,
    build_incident_candidate_summary,
    build_incident_candidates,
    build_provider_readiness,
    build_risk_escalation,
    build_risk_escalation_summary,
    deterministic_incident_candidate_json,
    deterministic_risk_escalation_json,
    incident_candidate_to_dict,
    provider_readiness_to_dict,
    risk_escalation_to_dict,
)


NOW = "2026-06-07T12:00:00+00:00"


def _policy(**overrides):
    row = {
        "policy_id": "policy-exposed-service",
        "matched": True,
        "confidence_score": 0.82,
        "approval_required": True,
        "preview_only": True,
        "destructive_action": False,
    }
    row.update(overrides)
    return row


def _remediation(**overrides):
    row = {
        "recommendation_id": "remediation-review-fixture",
        "recommendation_type": "block_preview",
        "risk_score": 0.72,
        "confidence_score": 0.78,
        "approval_required": True,
        "preview_only": True,
        "destructive_action": False,
    }
    row.update(overrides)
    return row


def _flow(**overrides):
    row = {
        "flow_reference": "flow-fixture-management",
        "risk_score": 0.42,
        "reconstruction_confidence": 0.74,
    }
    row.update(overrides)
    return row


def _attribution(**overrides):
    row = {
        "attribution_id": "attr-fixture-unknown",
        "attribution_state": "unattributed",
        "attribution_confidence": 0.48,
    }
    row.update(overrides)
    return row


def _drift(**overrides):
    row = {
        "drift_id": "drift-fixture-service",
        "drift_severity": "high",
        "confidence_score": 0.8,
    }
    row.update(overrides)
    return row


def _topology(**overrides):
    row = {
        "relationship_id": "rel-fixture-service",
        "topology_risk": 0.66,
        "relationship_confidence": 0.76,
    }
    row.update(overrides)
    return row


def test_risk_escalation_generation_and_export_safety():
    provider = provider_readiness_to_dict(build_provider_readiness("linux_nftables", platform_family="linux", now=NOW))
    record = build_risk_escalation(
        policy_evaluations=[_policy()],
        remediation_recommendations=[_remediation()],
        flow_signals=[_flow()],
        attribution_signals=[_attribution()],
        drift_signals=[_drift()],
        topology_signals=[_topology()],
        runtime_health_signals=[{"health_id": "health-fixture", "health_state": "healthy", "confidence_score": 0.9}],
        provider_readiness_signals=[provider],
        source_mode="fixture",
        now=NOW,
    )
    exported = risk_escalation_to_dict(record)

    assert exported["record_type"] == "risk_escalation_pipeline"
    assert exported["escalation_state"] == "approval_required"
    assert exported["severity_level"] in {"high", "critical"}
    assert exported["policy_matches"] == ["policy-exposed-service"]
    assert exported["remediation_recommendations"] == ["remediation-review-fixture"]
    assert exported["attribution_signals"] == ["attr-fixture-unknown"]
    assert exported["drift_signals"] == ["drift-fixture-service"]
    assert exported["topology_signals"] == ["rel-fixture-service"]
    assert exported["provider_readiness_signals"] == ["linux_nftables"]
    assert exported["candidate_only"] is True
    assert "final_threat_verdict" not in exported
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert json.loads(deterministic_risk_escalation_json(exported)) == exported


def test_multi_signal_risk_aggregation_and_low_risk_monitoring():
    low = build_risk_escalation(
        flow_signals=[{"flow_reference": "flow-low", "risk_score": 0.1, "confidence_score": 0.9}],
        runtime_health_signals=[{"health_state": "healthy"}],
        source_mode="fixture",
        now=NOW,
    )
    investigate = build_risk_escalation(
        remediation_recommendations=[_remediation(risk_score=0.42, confidence_score=0.7, approval_required=False)],
        flow_signals=[_flow(risk_score=0.3)],
        attribution_signals=[_attribution(attribution_state="partially_attributed")],
        source_mode="fixture",
        now=NOW,
    )

    assert low.escalation_state in {"none", "monitor"}
    assert low.combined_risk_score < 0.45
    assert investigate.escalation_state in {"investigate", "review_required"}
    assert investigate.combined_risk_score > low.combined_risk_score


def test_high_risk_becomes_review_or_approval_required():
    record = build_risk_escalation(
        policy_evaluations=[_policy(), _policy(policy_id="policy-drift")],
        remediation_recommendations=[_remediation(risk_score=0.9, recommendation_type="quarantine_preview")],
        drift_signals=[_drift(drift_severity="critical")],
        topology_signals=[_topology(topology_risk=0.9)],
        runtime_health_signals=[{"health_state": "degraded", "confidence_score": 0.8}],
        source_mode="fixture",
        now=NOW,
    )

    assert record.escalation_state == "approval_required"
    assert record.severity_level == "critical"
    assert record.preview_only is True
    assert record.destructive_action is False


def test_safety_blockers_override_escalation_and_provider_unavailable_blocks():
    unavailable_provider = provider_readiness_to_dict(
        build_provider_readiness("windows_defender_firewall", platform_family="macos", now=NOW)
    )
    record = build_risk_escalation(
        policy_evaluations=[_policy()],
        remediation_recommendations=[_remediation(risk_score=0.9)],
        runtime_health_signals=[{"health_state": "healthy"}],
        provider_readiness_signals=[unavailable_provider],
        source_mode="fixture",
        now=NOW,
    )
    unsafe = build_risk_escalation(
        remediation_recommendations=[_remediation(destructive_action=True)],
        runtime_health_signals=[{"health_state": "healthy"}],
        source_mode="fixture",
        now=NOW,
    )

    assert record.escalation_state == "blocked_by_safety"
    assert "provider_state:unavailable" in record.safety_blockers
    assert unsafe.escalation_state == "blocked_by_safety"
    assert "unsafe_remediation_record" in unsafe.safety_blockers


def test_incident_candidate_generation_and_type_mapping():
    topology_record = build_risk_escalation(
        policy_evaluations=[_policy()],
        remediation_recommendations=[_remediation()],
        topology_signals=[_topology()],
        source_mode="fixture",
        now=NOW,
    )
    drift_record = build_risk_escalation(
        drift_signals=[_drift(drift_severity="medium")],
        source_mode="fixture",
        now=NOW,
    )
    provider_record = build_risk_escalation(
        provider_readiness_signals=[
            provider_readiness_to_dict(build_provider_readiness("generic_manual_operator", platform_family="unknown", now=NOW))
        ],
        source_mode="fixture",
        now=NOW,
    )
    candidates = build_incident_candidates([topology_record, drift_record, provider_record], source_mode="fixture", now=NOW)
    exported = [incident_candidate_to_dict(row) for row in candidates]

    assert exported[0]["candidate_type"] == "topology_risk_review"
    assert exported[1]["candidate_type"] == "drift_review"
    assert exported[2]["candidate_type"] == "containment_readiness_review"
    assert all(row["candidate_only"] is True for row in exported)
    assert all("final_threat_verdict" not in row for row in exported)
    assert all(row["preview_only"] is True for row in exported)
    assert all(row["destructive_action"] is False for row in exported)


def test_incident_candidate_summary_and_serialization_are_safe():
    record = build_risk_escalation(
        policy_evaluations=[_policy()],
        remediation_recommendations=[_remediation()],
        flow_signals=[_flow()],
        source_mode="fixture",
        now=NOW,
    )
    candidate = build_incident_candidate(record, source_mode="fixture", now=NOW)
    exported = incident_candidate_to_dict(candidate)
    summary = build_incident_candidate_summary([candidate])
    risk_summary = build_risk_escalation_summary([record])
    serialized = json.dumps({"candidate": exported, "summary": summary, "risk": risk_summary}, sort_keys=True)

    assert exported["candidate_state"] in {"candidate", "needs_review"}
    assert exported["related_escalation_ids"] == [record.escalation_pipeline_id]
    assert summary["candidate_count"] == 1
    assert summary["preview_only"] is True
    assert "final_threat_verdict" not in summary
    assert risk_summary["pipeline_count"] == 1
    assert risk_summary["candidate_only"] is True
    assert "final_threat_verdict" not in risk_summary
    assert "verdict_status" not in serialized
    assert "threat_verdict" not in serialized
    assert "192.168." not in serialized
    assert "/" + "Users/" not in serialized
    assert "PRIVATE" + " KEY" not in serialized
    assert deterministic_incident_candidate_json(exported)


def test_malformed_input_handling_and_cross_platform_compatibility():
    record = build_risk_escalation(
        policy_evaluations=[None, {"matched": True, "policy_id": "policy-fixture", "confidence_score": "bad"}],
        remediation_recommendations=[{"recommendation_id": "rec-fixture", "risk_score": "bad", "preview_only": True}],
        flow_signals=[None],
        attribution_signals=[{"attribution_state": "unknown"}],
        drift_signals=[{"drift_severity": "nonsense"}],
        topology_signals=[{"topology_risk": "bad"}],
        runtime_health_signals=[{"health_state": "healthy", "platform_family": "windows"}],
        provider_readiness_signals=[{"provider_name": "windows_defender_firewall", "readiness_state": "ready"}],
        source_mode="fixture",
        now=NOW,
    )
    exported = risk_escalation_to_dict(record)

    assert 0.0 <= exported["combined_risk_score"] <= 1.0
    assert 0.0 <= exported["confidence_score"] <= 1.0
    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert exported["process_changes"] is False


def test_record_validators_reject_unsafe_direct_construction():
    record = build_risk_escalation(policy_evaluations=[_policy()], source_mode="fixture", now=NOW)
    candidate = build_incident_candidate(record, source_mode="fixture", now=NOW)

    with pytest.raises(RiskEscalationError):
        record.__class__(
            escalation_pipeline_id="risk-bad",
            escalation_state="approval_required",
            input_signal_count=1,
            combined_risk_score=0.8,
            confidence_score=0.8,
            severity_level="high",
            escalation_reason="bad",
            preview_only=False,
        )
    with pytest.raises(IncidentCandidateError):
        candidate.__class__(
            candidate_id="candidate-bad",
            candidate_type="drift_review",
            candidate_state="needs_review",
            severity_level="high",
            confidence_score=0.8,
            preview_only=False,
        )
