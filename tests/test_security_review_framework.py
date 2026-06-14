from __future__ import annotations

import json

from core_engine.governance import (
    build_audit_event,
    build_compliance_profile,
    build_data_classification,
    build_data_governance_summary,
    build_operator_accountability_summary,
    build_operator_action,
    build_security_framework_summary,
    build_security_review,
    deterministic_security_framework_json,
    deterministic_security_review_json,
    empty_security_framework_summary,
    normalize_checklist_state,
    normalize_security_framework_state,
    normalize_security_review,
    normalize_security_review_category,
    normalize_security_review_state,
    summarize_audit_events,
    summarize_security_reviews,
)


def _ready_check(item_id: str) -> dict[str, object]:
    return {"item_id": item_id, "item_label": f"{item_id} reviewed", "item_state": "ready", "required": True}


def test_security_review_creation():
    review = build_security_review(
        review_type="runtime_readiness",
        review_category="runtime",
        review_scope="runtime",
        checklist_items=[_ready_check("runtime-check")],
        evidence_references=["runtime-summary"],
        source_mode="fixture",
    ).to_dict()

    assert review["record_type"] == "security_review_record"
    assert review["review_type"] == "runtime_readiness"
    assert review["review_category"] == "runtime"
    assert review["review_state"] == "ready"
    assert review["review_scope"] == "runtime"
    assert review["source_mode"] == "fixture"
    assert review["preview_only"] is True
    assert review["destructive_action"] is False
    assert review["security_scan_performed"] is False


def test_category_state_and_checklist_validation():
    assert normalize_security_review_category("deployment") == "deployment"
    assert normalize_security_review_category("bad") == "unknown"
    assert normalize_security_review_state("review_required") == "review_required"
    assert normalize_security_review_state("bad") == "unknown"
    assert normalize_checklist_state("incomplete") == "incomplete"
    assert normalize_checklist_state("bad") == "unknown"
    assert normalize_security_framework_state("review_recommended") == "review_recommended"
    assert normalize_security_framework_state("bad") == "unknown"

    review = build_security_review(
        review_category="bad",
        review_state="bad",
        checklist_items=[{"item_id": "bad-check", "item_state": "bad"}],
    ).to_dict()

    assert review["review_category"] == "unknown"
    assert review["review_state"] == "unknown"
    assert review["checklist_items"][0]["item_state"] == "unknown"


def test_checklist_summaries():
    summary = build_security_framework_summary(
        security_reviews=[
            build_security_review(
                review_category="deployment",
                checklist_items=[
                    _ready_check("deployment-ready"),
                    {"item_id": "deployment-review", "item_label": "deployment review", "item_state": "review_required"},
                ],
            )
        ]
    ).to_dict()

    checklist = summary["checklist_summary"]
    assert checklist["checklist_item_count"] == 2
    assert checklist["required_item_count"] == 2
    assert checklist["state_counts"]["ready"] == 1
    assert checklist["review_required_count"] == 1
    assert summary["framework_state"] == "review_recommended"


def test_runtime_deployment_and_packaging_reviews():
    summary = build_security_framework_summary(
        security_reviews=[
            build_security_review(review_category="runtime", checklist_items=[_ready_check("runtime")]),
            build_security_review(review_category="deployment", checklist_items=[_ready_check("deployment")]),
            build_security_review(review_category="packaging", checklist_items=[_ready_check("packaging")]),
        ]
    ).to_dict()

    assert summary["framework_state"] == "ready"
    assert summary["runtime_review_summary"]["review_count"] == 1
    assert summary["deployment_review_summary"]["review_count"] == 1
    assert summary["packaging_review_summary"]["review_count"] == 1


def test_governance_integration():
    governance = build_data_governance_summary(
        classifications=[build_data_classification(data_category="configuration_metadata")]
    )
    summary = build_security_framework_summary(
        security_reviews=[build_security_review(review_category="governance", governance_references=["governance-summary"])],
        governance_summaries=[governance],
    ).to_dict()

    assert summary["governance_review_summary"]["review_count"] == 1
    assert summary["governance_review_summary"]["governance_summary_count"] == 1
    assert summary["governance_review_summary"]["governance_state_counts"]["restricted"] == 1


def test_accountability_integration():
    accountability = build_operator_accountability_summary(
        operator_actions=[
            build_operator_action(action_category="security_review", approval_state="approved", reviewer_reference="reviewer-security")
        ]
    )
    summary = build_security_framework_summary(
        security_reviews=[build_security_review(review_category="governance", accountability_references=["accountability-summary"])],
        accountability_summaries=[accountability],
    ).to_dict()

    assert summary["accountability_review_summary"]["accountability_summary_count"] == 1
    assert summary["accountability_review_summary"]["accountability_state_counts"]["ready"] == 1
    assert summary["accountability_review_summary"]["accountability_reference_count"] == 1


def test_compliance_and_audit_integration():
    audit_summary = summarize_audit_events(
        [
            build_audit_event(event_category="security_review", event_type="review_recorded"),
            build_audit_event(event_category="export", event_type="export_validated"),
        ]
    )
    profile = build_compliance_profile(profile_type="security_review")
    summary = build_security_framework_summary(
        security_reviews=[build_security_review(review_category="compliance")],
        audit_summary=audit_summary,
        compliance_profiles=[profile],
    ).to_dict()

    compliance = summary["compliance_review_summary"]
    assert compliance["review_count"] == 1
    assert compliance["profile_count"] == 1
    assert compliance["profile_type_counts"]["security_review"] == 1
    assert compliance["audit_event_count"] == 2
    assert compliance["certification_claimed"] is False


def test_malformed_input_handling():
    review = normalize_security_review(object()).to_dict()
    summary = build_security_framework_summary(security_reviews=[object()]).to_dict()
    empty = empty_security_framework_summary(generated_at="2026-06-14T12:00:00Z").to_dict()

    assert review["review_state"] == "degraded"
    assert summary["framework_state"] == "degraded"
    assert empty["framework_state"] == "unavailable"
    assert empty["security_review_summary"]["review_count"] == 0


def test_preview_and_destructive_flags_are_fixed():
    review = build_security_review(review_category="export").to_dict()
    summary = build_security_framework_summary(security_reviews=[review]).to_dict()

    for record in (review, summary):
        assert record["preview_only"] is True
        assert record["destructive_action"] is False
        assert record["export_safe"] is True
        assert record["security_scan_performed"] is False
        assert record["vulnerability_detection_performed"] is False
        assert record["control_enforced"] is False
        assert record["filesystem_written"] is False


def test_export_safe_serialization():
    review = build_security_review(review_category="privacy")
    summary = build_security_framework_summary(security_reviews=[review])

    json.loads(deterministic_security_review_json(review))
    json.loads(deterministic_security_framework_json(summary))
    json.dumps(review.to_dict(), sort_keys=True)
    json.dumps(summary.to_dict(), sort_keys=True)


def test_no_scanning_or_file_side_effects(tmp_path, monkeypatch):
    before = sorted(path.name for path in tmp_path.iterdir())
    monkeypatch.chdir(tmp_path)

    review = build_security_review(review_category="infrastructure").to_dict()
    summary = build_security_framework_summary(security_reviews=[review]).to_dict()

    after = sorted(path.name for path in tmp_path.iterdir())
    assert before == after
    assert summary["security_scan_performed"] is False
    assert summary["vulnerability_detection_performed"] is False
    assert summary["file_read_performed"] is False
    assert summary["filesystem_written"] is False
    assert summary["system_modified"] is False


def test_security_review_summary_counts():
    summary = summarize_security_reviews(
        [
            build_security_review(review_category="runtime", checklist_items=[_ready_check("runtime")]),
            build_security_review(review_category="runtime"),
            build_security_review(review_category="privacy", review_state="incomplete"),
        ]
    )

    assert summary["review_count"] == 3
    assert summary["category_counts"]["runtime"] == 2
    assert summary["state_counts"]["ready"] == 1
    assert summary["state_counts"]["review_required"] == 1
    assert summary["state_counts"]["incomplete"] == 1


def test_cross_platform_compatibility():
    for category in [
        "runtime",
        "packaging",
        "deployment",
        "governance",
        "compliance",
        "privacy",
        "export",
        "infrastructure",
        "unknown",
    ]:
        review = build_security_review(review_category=category, source_mode="fixture").to_dict()
        assert review["review_category"] == category
        assert review["source_mode"] == "fixture"

    summary = build_security_framework_summary(
        security_reviews=[
            build_security_review(review_category="runtime", source_mode="macos"),
            build_security_review(review_category="deployment", source_mode="linux_arm"),
        ]
    ).to_dict()

    assert summary["preview_only"] is True
    assert summary["export_safe"] is True
