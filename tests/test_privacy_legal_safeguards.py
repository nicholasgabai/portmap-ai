from __future__ import annotations

import json

from core_engine.governance import (
    build_audit_event,
    build_compliance_profile,
    build_data_classification,
    build_data_governance_summary,
    build_operator_accountability_summary,
    build_operator_action,
    build_privacy_review,
    build_privacy_safeguard_summary,
    build_security_framework_summary,
    build_security_review,
    deterministic_privacy_review_json,
    deterministic_privacy_safeguard_json,
    empty_privacy_safeguard_summary,
    normalize_privacy_review,
    normalize_privacy_review_category,
    normalize_privacy_review_state,
    normalize_privacy_safeguard_state,
    summarize_audit_events,
    summarize_privacy_reviews,
)


def test_privacy_review_creation():
    review = build_privacy_review(
        review_type="export_notice",
        review_category="export_privacy",
        privacy_scope="export_bundle",
        governance_references=["governance-summary"],
        source_mode="fixture",
    ).to_dict()

    assert review["record_type"] == "privacy_review_record"
    assert review["review_type"] == "export_notice"
    assert review["review_category"] == "export_privacy"
    assert review["review_state"] == "review_required"
    assert review["privacy_scope"] == "export_bundle"
    assert review["redaction_requirements"]["redaction_required"] is True
    assert review["export_requirements"]["export_review_required"] is True
    assert review["legal_advice_provided"] is False
    assert review["preview_only"] is True
    assert review["destructive_action"] is False


def test_category_state_and_safeguard_validation():
    assert normalize_privacy_review_category("audit_privacy") == "audit_privacy"
    assert normalize_privacy_review_category("bad") == "unknown"
    assert normalize_privacy_review_state("incomplete") == "incomplete"
    assert normalize_privacy_review_state("bad") == "unknown"
    assert normalize_privacy_safeguard_state("restricted") == "restricted"
    assert normalize_privacy_safeguard_state("bad") == "unknown"

    review = build_privacy_review(review_category="bad", review_state="bad").to_dict()

    assert review["review_category"] == "unknown"
    assert review["review_state"] == "unknown"


def test_redaction_summaries():
    governance = build_data_governance_summary(
        classifications=[build_data_classification(data_category="topology_metadata")]
    )
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[build_privacy_review(review_category="export_privacy")],
        governance_summaries=[governance],
    ).to_dict()

    redaction = summary["redaction_summary"]
    assert redaction["review_redaction_required_count"] == 1
    assert redaction["governance_redaction_required_count"] >= 1
    assert redaction["redaction_review_recommended"] is True
    assert redaction["private_identifier_export_allowed"] is False


def test_export_privacy_summaries():
    governance = build_data_governance_summary(
        classifications=[build_data_classification(data_category="configuration_metadata")]
    )
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[build_privacy_review(review_category="export_privacy")],
        governance_summaries=[governance],
    ).to_dict()

    export_summary = summary["export_privacy_summary"]
    assert export_summary["export_review_required_count"] == 1
    assert export_summary["governance_export_restricted_count"] >= 1
    assert export_summary["private_export_read_by_default"] is False
    assert export_summary["sensitive_data_scan_expected"] is True


def test_consent_notice_summaries():
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[
            build_privacy_review(review_category="deployment_privacy"),
            build_privacy_review(review_category="runtime_privacy"),
        ]
    ).to_dict()

    consent_notice = summary["consent_notice_summary"]
    assert consent_notice["notice_required_count"] == 2
    assert consent_notice["consent_review_required_count"] == 2
    assert consent_notice["notice_records_created"] is False
    assert consent_notice["consent_records_created"] is False


def test_governance_integration():
    governance = build_data_governance_summary(
        classifications=[build_data_classification(data_category="configuration_metadata")]
    )
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[build_privacy_review(review_category="governance_privacy")],
        governance_summaries=[governance],
    ).to_dict()

    assert summary["safeguard_state"] == "restricted"
    assert summary["governance_summary"]["governance_summary_count"] == 1
    assert summary["governance_summary"]["state_counts"]["restricted"] == 1


def test_accountability_integration():
    accountability = build_operator_accountability_summary(
        operator_actions=[
            build_operator_action(action_category="governance_review", approval_state="approved", reviewer_reference="reviewer-privacy")
        ]
    )
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[build_privacy_review(review_category="operator_privacy")],
        accountability_summaries=[accountability],
    ).to_dict()

    assert summary["accountability_summary"]["accountability_summary_count"] == 1
    assert summary["accountability_summary"]["state_counts"]["ready"] == 1
    assert summary["accountability_summary"]["identity_stored"] is False


def test_security_review_integration():
    security = build_security_framework_summary(
        security_reviews=[
            build_security_review(
                review_category="privacy",
                checklist_items=[{"item_id": "privacy", "item_label": "privacy reviewed", "item_state": "ready"}],
            )
        ]
    )
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[build_privacy_review(review_category="documentation_privacy")],
        security_framework_summaries=[security],
    ).to_dict()

    assert summary["security_review_summary"]["security_framework_summary_count"] == 1
    assert summary["security_review_summary"]["state_counts"]["ready"] == 1
    assert summary["security_review_summary"]["security_scan_performed"] is False


def test_audit_and_compliance_integration():
    audit_summary = summarize_audit_events(
        [
            build_audit_event(event_category="export", event_type="privacy_export"),
            build_audit_event(event_category="security_review", event_type="privacy_review"),
        ]
    )
    profile = build_compliance_profile(profile_type="privacy_review")
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[build_privacy_review(review_category="audit_privacy")],
        audit_summary=audit_summary,
        compliance_profiles=[profile],
    ).to_dict()

    assert summary["privacy_summary"]["audit_event_count"] == 2
    assert summary["privacy_summary"]["compliance_profile_count"] == 1
    assert summary["privacy_summary"]["certification_claimed"] is False


def test_malformed_input_handling():
    review = normalize_privacy_review(object()).to_dict()
    summary = build_privacy_safeguard_summary(privacy_reviews=[object()]).to_dict()
    empty = empty_privacy_safeguard_summary(generated_at="2026-06-14T12:00:00Z").to_dict()

    assert review["review_state"] == "degraded"
    assert summary["safeguard_state"] == "degraded"
    assert empty["safeguard_state"] == "unavailable"
    assert empty["privacy_review_summary"]["review_count"] == 0


def test_legal_and_certification_flags_are_always_false():
    review = build_privacy_review().to_dict()
    summary = build_privacy_safeguard_summary(
        privacy_reviews=[build_privacy_review()],
        legal_safeguard_notes=["advisory safeguard boundary only"],
    ).to_dict()

    assert review["legal_advice_provided"] is False
    assert review["legal_analysis_performed"] is False
    assert summary["legal_advice_provided"] is False
    assert summary["certification_claimed"] is False
    assert summary["legal_analysis_performed"] is False


def test_preview_and_destructive_flags_are_fixed():
    review = build_privacy_review(review_category="runtime_privacy").to_dict()
    summary = build_privacy_safeguard_summary(privacy_reviews=[review]).to_dict()

    for record in (review, summary):
        assert record["preview_only"] is True
        assert record["destructive_action"] is False
        assert record["export_safe"] is True
        assert record["privacy_control_enforced"] is False
        assert record["data_deleted"] is False
        assert record["filesystem_written"] is False


def test_export_safe_serialization():
    review = build_privacy_review(review_category="documentation_privacy")
    summary = build_privacy_safeguard_summary(privacy_reviews=[review])

    json.loads(deterministic_privacy_review_json(review))
    json.loads(deterministic_privacy_safeguard_json(summary))
    json.dumps(review.to_dict(), sort_keys=True)
    json.dumps(summary.to_dict(), sort_keys=True)


def test_no_enforcement_or_file_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    review = build_privacy_review(review_category="runtime_privacy").to_dict()
    summary = build_privacy_safeguard_summary(privacy_reviews=[review]).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["privacy_control_enforced"] is False
    assert summary["control_enforced"] is False
    assert summary["data_deleted"] is False
    assert summary["file_read_performed"] is False
    assert summary["filesystem_written"] is False
    assert summary["private_export_read"] is False


def test_privacy_review_summary_counts():
    summary = summarize_privacy_reviews(
        [
            build_privacy_review(review_category="export_privacy"),
            build_privacy_review(review_category="runtime_privacy"),
            build_privacy_review(review_category="documentation_privacy", review_state="ready"),
        ]
    )

    assert summary["review_count"] == 3
    assert summary["category_counts"]["export_privacy"] == 1
    assert summary["state_counts"]["review_required"] == 2
    assert summary["state_counts"]["ready"] == 1
    assert summary["legal_advice_provided"] is False
    assert summary["certification_claimed"] is False


def test_cross_platform_compatibility():
    for category in [
        "export_privacy",
        "audit_privacy",
        "governance_privacy",
        "operator_privacy",
        "deployment_privacy",
        "runtime_privacy",
        "documentation_privacy",
        "unknown",
    ]:
        review = build_privacy_review(review_category=category, source_mode="fixture").to_dict()
        assert review["review_category"] == category
        assert review["source_mode"] == "fixture"

    summary = build_privacy_safeguard_summary(
        privacy_reviews=[
            build_privacy_review(review_category="export_privacy", source_mode="macos"),
            build_privacy_review(review_category="runtime_privacy", source_mode="linux_arm"),
        ]
    ).to_dict()

    assert summary["preview_only"] is True
    assert summary["export_safe"] is True
