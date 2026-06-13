from __future__ import annotations

import json

from core_engine.governance import (
    build_audit_event,
    build_compliance_profile,
    build_data_classification,
    build_data_governance_summary,
    build_operator_accountability_summary,
    build_operator_action,
    deterministic_operator_accountability_json,
    deterministic_operator_action_json,
    empty_operator_accountability_summary,
    normalize_accountability_state,
    normalize_action_category,
    normalize_approval_state,
    normalize_operator_action,
    normalize_operator_action_state,
    sanitize_operator_reference,
    summarize_audit_events,
    summarize_operator_actions,
)


def test_operator_action_creation():
    action = build_operator_action(
        action_type="export_review",
        action_category="export",
        actor_reference="role-export-operator",
        reviewer_reference="reviewer-governance",
        approval_state="approved",
        evidence_references=["evidence-export-summary"],
        governance_references=["governance-summary"],
        audit_references=["audit-event"],
        source_mode="fixture",
    ).to_dict()

    assert action["record_type"] == "operator_action_record"
    assert action["action_type"] == "export_review"
    assert action["action_category"] == "export"
    assert action["actor_reference"] == "role-export-operator"
    assert action["reviewer_reference"] == "reviewer-governance"
    assert action["approval_state"] == "approved"
    assert action["action_state"] == "recorded"
    assert action["source_mode"] == "fixture"
    assert action["preview_only"] is True
    assert action["destructive_action"] is False


def test_action_category_approval_and_state_validation():
    assert normalize_action_category("policy_review") == "policy_review"
    assert normalize_action_category("bad") == "unknown"
    assert normalize_approval_state("review_required") == "review_required"
    assert normalize_approval_state("bad") == "unknown"
    assert normalize_operator_action_state("advisory") == "advisory"
    assert normalize_operator_action_state("bad") == "unknown"
    assert normalize_accountability_state("approval_required") == "approval_required"
    assert normalize_accountability_state("bad") == "unknown"

    action = build_operator_action(
        action_category="bad",
        approval_state="bad",
        action_state="bad",
    ).to_dict()

    assert action["action_category"] == "unknown"
    assert action["approval_state"] == "unknown"
    assert action["action_state"] == "unknown"


def test_actor_and_reviewer_sanitization():
    action = build_operator_action(
        actor_reference="plain-person-reference",
        reviewer_reference="plain-user-name",
    ).to_dict()

    assert "person" not in action["actor_reference"]
    assert "plain-user-name" not in action["reviewer_reference"]
    assert action["actor_reference"].startswith("actor-ref-")
    assert action["reviewer_reference"].startswith("reviewer-ref-")
    assert sanitize_operator_reference("role-governance-reviewer", default="actor-unknown") == "role-governance-reviewer"


def test_accountability_summary_generation():
    summary = build_operator_accountability_summary(
        generated_at="2026-06-12T12:00:00Z",
        operator_actions=[
            build_operator_action(
                action_category="governance_review",
                actor_reference="role-governance-operator",
                reviewer_reference="reviewer-governance",
                approval_state="approved",
            )
        ],
    ).to_dict()

    assert summary["record_type"] == "operator_accountability_summary"
    assert summary["generated_at"] == "2026-06-12T12:00:00Z"
    assert summary["accountability_state"] == "ready"
    assert summary["operator_action_summary"]["action_count"] == 1
    assert summary["approval_summary"]["approval_counts"]["approved"] == 1
    assert summary["reviewer_chain_summary"]["unique_reviewer_reference_count"] == 1
    assert summary["role_mapping_summary"]["role_assignment_performed"] is False


def test_audit_integration():
    audit_summary = summarize_audit_events(
        [
            build_audit_event(event_category="operator_action", event_type="operator_review"),
            build_audit_event(event_category="export", event_type="export_summary"),
        ]
    )
    summary = build_operator_accountability_summary(
        operator_actions=[build_operator_action(action_category="export", audit_references=["audit-event"])],
        audit_summary=audit_summary,
    ).to_dict()

    assert summary["audit_summary"]["audit_event_count"] == 2
    assert summary["audit_summary"]["category_counts"]["operator_action"] == 1
    assert summary["evidence_summary"]["audit_reference_count"] == 1


def test_compliance_integration():
    profile = build_compliance_profile(profile_type="enterprise_readiness")
    summary = build_operator_accountability_summary(
        operator_actions=[build_operator_action(action_category="compliance_review", approval_state="approved")],
        compliance_profiles=[profile],
    ).to_dict()

    assert summary["compliance_summary"]["profile_count"] == 1
    assert summary["compliance_summary"]["type_counts"]["enterprise_readiness"] == 1
    assert summary["compliance_summary"]["certification_claimed"] is False


def test_governance_integration():
    governance = build_data_governance_summary(
        classifications=[build_data_classification(data_category="operator_action_metadata")]
    )
    summary = build_operator_accountability_summary(
        operator_actions=[build_operator_action(action_category="governance_review", governance_references=["governance-summary"])],
        governance_summaries=[governance],
    ).to_dict()

    assert summary["governance_summary"]["governance_summary_count"] == 1
    assert summary["governance_summary"]["state_counts"]["review_recommended"] == 1
    assert summary["evidence_summary"]["governance_reference_count"] == 1


def test_approval_summaries_and_state_mapping():
    summary = build_operator_accountability_summary(
        operator_actions=[
            build_operator_action(action_category="policy_review", approval_state="pending"),
            build_operator_action(action_category="security_review", approval_state="review_required"),
        ]
    ).to_dict()

    assert summary["accountability_state"] == "approval_required"
    assert summary["approval_summary"]["approval_required_count"] == 2
    assert summary["approval_summary"]["authorization_performed"] is False
    assert summary["approval_summary"]["permissions_enforced"] is False


def test_reviewer_chain_summaries():
    summary = build_operator_accountability_summary(
        operator_actions=[
            build_operator_action(reviewer_reference="reviewer-governance", approval_state="approved"),
            build_operator_action(reviewer_reference="", approval_state="approved"),
        ]
    ).to_dict()

    chain = summary["reviewer_chain_summary"]
    assert chain["reviewer_reference_count"] == 1
    assert chain["missing_reviewer_count"] == 1
    assert summary["accountability_state"] == "review_recommended"
    assert chain["identity_stored"] is False


def test_role_mapping_and_evidence_summaries():
    summary = build_operator_accountability_summary(
        operator_actions=[
            build_operator_action(
                action_category="remediation_preview",
                evidence_references=["remediation-preview"],
                approval_state="approved",
            ),
            build_operator_action(
                action_category="packaging_review",
                evidence_references=["packaging-preview"],
                approval_state="approved",
            ),
        ]
    ).to_dict()

    role_mapping = summary["role_mapping_summary"]
    evidence = summary["evidence_summary"]
    assert "remediation_reviewer" in role_mapping["mapped_scopes"]
    assert "packaging_reviewer" in role_mapping["mapped_scopes"]
    assert role_mapping["role_assignment_performed"] is False
    assert evidence["action_evidence_reference_count"] == 2
    assert evidence["identity_stored"] is False


def test_malformed_input_handling():
    action = normalize_operator_action(object()).to_dict()
    summary = build_operator_accountability_summary(operator_actions=[object()]).to_dict()
    empty = empty_operator_accountability_summary(generated_at="2026-06-12T12:00:00Z").to_dict()

    assert action["action_state"] == "degraded"
    assert action["approval_state"] == "unknown"
    assert summary["accountability_state"] == "degraded"
    assert empty["accountability_state"] == "unavailable"
    assert empty["operator_action_summary"]["action_count"] == 0


def test_preview_and_destructive_flags_are_fixed():
    action = build_operator_action().to_dict()
    summary = build_operator_accountability_summary(operator_actions=[action]).to_dict()

    for record in (action, summary):
        assert record["preview_only"] is True
        assert record["destructive_action"] is False
        assert record["export_safe"] is True
        assert record["authorization_performed"] is False
        assert record["permissions_enforced"] is False
        assert record["role_assigned"] is False
        assert record["identity_stored"] is False


def test_no_authorization_identity_or_file_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    action = build_operator_action(actor_reference="operator-person-reference").to_dict()
    summary = build_operator_accountability_summary(operator_actions=[action]).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert "operator" not in action["actor_reference"]
    assert summary["authorization_performed"] is False
    assert summary["permissions_enforced"] is False
    assert summary["filesystem_written"] is False
    assert summary["file_read_performed"] is False
    assert summary["private_export_read"] is False


def test_export_safe_serialization():
    action = build_operator_action(action_category="security_review")
    summary = build_operator_accountability_summary(operator_actions=[action])

    json.loads(deterministic_operator_action_json(action))
    json.loads(deterministic_operator_accountability_json(summary))
    json.dumps(action.to_dict(), sort_keys=True)
    json.dumps(summary.to_dict(), sort_keys=True)


def test_operator_action_summary_counts():
    summary = summarize_operator_actions(
        [
            build_operator_action(action_category="export", approval_state="approved"),
            build_operator_action(action_category="export", approval_state="pending"),
            build_operator_action(action_category="security_review", action_state="advisory"),
        ]
    )

    assert summary["action_count"] == 3
    assert summary["category_counts"]["export"] == 2
    assert summary["approval_counts"]["pending"] == 1
    assert summary["state_counts"]["advisory"] == 1


def test_cross_platform_compatibility():
    for category in [
        "export",
        "policy_review",
        "remediation_preview",
        "configuration_review",
        "packaging_review",
        "governance_review",
        "security_review",
        "compliance_review",
        "unknown",
    ]:
        action = build_operator_action(action_category=category, source_mode="fixture").to_dict()
        assert action["action_category"] == category
        assert action["source_mode"] == "fixture"

    summary = build_operator_accountability_summary(
        operator_actions=[
            build_operator_action(action_category="export", source_mode="macos"),
            build_operator_action(action_category="security_review", source_mode="linux_arm"),
        ]
    ).to_dict()
    assert summary["preview_only"] is True
    assert summary["export_safe"] is True
