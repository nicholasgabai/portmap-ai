import re

import pytest

from core_engine.policy import (
    PolicyError,
    ReviewQueue,
    build_review_record,
    create_policy,
    evaluate_delta_against_policies,
    evaluate_event_against_policies,
    evaluate_finding_against_policies,
)


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _policy():
    return create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review medium and higher local findings.",
        severity_threshold="medium",
        categories=["policy_review_required", "finding", "service_added"],
        now="sample-created-at",
    )


def test_policy_creation():
    policy = _policy()

    assert policy.policy_id == "policy-sample"
    assert policy.enabled is True
    assert policy.required_review is True
    assert policy.matches(category="finding", severity="medium") is True
    assert policy.matches(category="finding", severity="low") is False
    assert policy.to_dict()["automatic_changes"] is False


def test_invalid_severity_rejection():
    with pytest.raises(PolicyError):
        create_policy(name="Bad", description="Bad severity", severity_threshold="urgent")


def test_event_to_review_generation():
    reviews = evaluate_event_against_policies(
        {
            "event_id": "event-sample",
            "event_type": "policy_review_required",
            "severity": "high",
            "message": "Sample policy review required",
            "asset_ref": "asset-sample",
        },
        [_policy()],
    )

    assert len(reviews) == 1
    review = reviews[0]
    assert review.review_id.startswith("review-")
    assert review.source_ref == "event:event-sample"
    assert review.category == "policy_review_required"
    assert review.approval_required is True
    assert review.automatic_changes is False
    assert review.administrator_controlled is True
    assert review.raw_payload_stored is False


def test_finding_to_review_generation():
    reviews = evaluate_finding_against_policies(
        {
            "finding_id": "finding-sample",
            "finding_type": "finding",
            "severity": "medium",
            "message": "Sample advisory finding",
            "evidence_refs": ["asset:asset-sample"],
        },
        [_policy()],
    )

    assert len(reviews) == 1
    assert reviews[0].source_ref == "finding:finding-sample"
    assert reviews[0].evidence_refs == ["asset:asset-sample"]


def test_delta_to_review_generation():
    reviews = evaluate_delta_against_policies(
        {
            "delta_id": "delta-sample",
            "type": "service_added",
            "severity": "high",
            "target": "asset-sample",
            "evidence": {"asset_id": "asset-sample", "service": "HTTPS"},
        },
        [_policy()],
    )

    assert len(reviews) == 1
    assert reviews[0].source_ref == "delta:delta-sample"
    assert reviews[0].category == "service_added"
    assert "asset_id:asset-sample" in reviews[0].evidence_refs


def test_review_queue_add_list_get_and_filters():
    review = build_review_record(
        policy=_policy(),
        source_ref="event:event-sample",
        category="policy_review_required",
        severity="high",
        title="Sample Review",
        summary="Sample review summary",
        evidence_refs=["asset:asset-sample"],
        now="sample-created-at",
    )
    queue = ReviewQueue()

    queue.add_review(review)

    assert queue.get_review(review.review_id) == review
    assert queue.list_reviews() == [review]
    assert queue.list_reviews(status="open") == [review]
    assert queue.list_reviews(severity="high") == [review]
    assert queue.list_reviews(category="policy_review_required") == [review]
    assert queue.local_only is True


def test_review_status_transitions_and_invalid_transition():
    review = build_review_record(
        policy=_policy(),
        source_ref="event:event-sample",
        category="policy_review_required",
        severity="high",
        title="Sample Review",
        summary="Sample review summary",
    )
    queue = ReviewQueue([review])

    approved = queue.update_status(review.review_id, "approved", reviewed_by="operator-sample", review_note="Sample approval")
    assert approved.status == "approved"
    assert approved.reviewed_by == "operator-sample"
    assert approved.review_note == "Sample approval"
    assert approved.automatic_changes is False

    with pytest.raises(PolicyError):
        queue.update_status(review.review_id, "running")
    queue.update_status(review.review_id, "resolved")
    with pytest.raises(PolicyError):
        queue.update_status(review.review_id, "open")


def test_summary_counts_and_default_safety_flags():
    policy = _policy()
    first = build_review_record(
        policy=policy,
        source_ref="event:event-a",
        category="policy_review_required",
        severity="high",
        title="First",
        summary="First summary",
    )
    second = build_review_record(
        policy=policy,
        source_ref="finding:finding-b",
        category="finding",
        severity="medium",
        title="Second",
        summary="Second summary",
    )
    queue = ReviewQueue([first, second])
    queue.update_status(second.review_id, "deferred")
    summary = queue.summarize_reviews()

    assert summary["review_count"] == 2
    assert summary["by_status"]["open"] == 1
    assert summary["by_status"]["deferred"] == 1
    assert summary["by_severity"] == {"high": 1, "medium": 1}
    assert summary["approval_required_count"] == 2
    assert summary["automatic_changes"] is False
    assert summary["administrator_controlled"] is True
    assert summary["raw_payload_stored"] is False


def test_no_private_identifiers_in_examples_or_output():
    reviews = evaluate_event_against_policies(
        {
            "event_id": "event-sample",
            "event_type": "policy_review_required",
            "severity": "high",
            "message": "Sample policy review required",
            "asset_ref": "asset-sample",
        },
        [_policy()],
    )
    output = repr([review.to_dict() for review in reviews])

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(output)
