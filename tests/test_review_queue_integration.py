import json
import re

import pytest

from core_engine.policy import PersistentReviewStore, PolicyError, build_review_record, create_policy
from core_engine.policy.history import (
    build_finding_status_record,
    build_review_transition_record,
    export_review_records,
    import_review_records,
    review_from_storage_record,
    review_to_storage_record,
)
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _repository(tmp_path):
    return LocalStorageRepository(SQLiteStore(tmp_path / "reviews.db"))


def _policy():
    return create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review advisory findings.",
        severity_threshold="medium",
        categories=[],
        now="2026-01-01T00:00:00+00:00",
    )


def _review(index="a", *, severity="high", category="policy_review_required", source_ref=None):
    return build_review_record(
        policy=_policy(),
        source_ref=source_ref or f"finding:finding-{index}",
        category=category,
        severity=severity,
        title=f"Sample Review {index}",
        summary=f"Sample review summary {index}",
        evidence_refs=[f"asset:asset-{index}"],
        now=f"2026-01-01T00:00:0{0 if index == 'a' else 1}+00:00",
    )


def test_review_storage_record_round_trip():
    review = _review()
    record = review_to_storage_record(review)
    loaded = review_from_storage_record(record)

    assert record["record_type"] == "operator_review_record"
    assert record["finding_id"] == review.review_id
    assert loaded.to_dict() == review.to_dict()
    assert record["automatic_changes"] is False
    assert record["administrator_controlled"] is True
    assert record["raw_payload_stored"] is False


def test_persistent_review_store_add_list_get_and_filters(tmp_path):
    store = PersistentReviewStore(_repository(tmp_path))
    first = _review("a", severity="high", category="policy_review_required", source_ref="event:event-a")
    second = _review("b", severity="medium", category="finding", source_ref="finding:finding-b")

    store.add_reviews([first, second])

    assert store.get_review(first.review_id).review_id == first.review_id
    assert [review.review_id for review in store.list_reviews(status="open")] == [first.review_id, second.review_id]
    assert [review.review_id for review in store.list_reviews(severity="high")] == [first.review_id]
    assert [review.review_id for review in store.list_reviews(category="finding")] == [second.review_id]
    assert [review.review_id for review in store.list_reviews(source_ref="event:event-a")] == [first.review_id]
    assert store.local_only is True


def test_review_state_history_and_transition_records(tmp_path):
    store = PersistentReviewStore(_repository(tmp_path))
    review = _review()
    store.add_review(review)

    updated = store.update_status(
        review.review_id,
        "approved",
        reviewed_by="operator-sample",
        review_note="Sample approval note",
        now="2026-01-02T00:00:00+00:00",
    )
    history = store.list_review_history(review.review_id)
    current = store.get_review(review.review_id)

    assert updated.status == "approved"
    assert current.status == "approved"
    assert current.reviewed_by == "operator-sample"
    assert len(history) == 1
    assert history[0]["previous_status"] == "open"
    assert history[0]["new_status"] == "approved"
    assert history[0]["automatic_changes"] is False


def test_invalid_review_transition_is_rejected(tmp_path):
    store = PersistentReviewStore(_repository(tmp_path))
    review = _review()
    store.add_review(review)

    with pytest.raises(PolicyError):
        store.update_status(review.review_id, "running")
    with pytest.raises(PolicyError):
        store.update_status("review-missing", "approved")


def test_closed_review_cannot_be_reopened(tmp_path):
    store = PersistentReviewStore(_repository(tmp_path))
    review = _review()
    store.add_review(review)
    store.update_status(review.review_id, "resolved", now="2026-01-02T00:00:00+00:00")

    with pytest.raises(PolicyError):
        store.update_status(review.review_id, "open", now="2026-01-03T00:00:00+00:00")


def test_finding_status_tracking(tmp_path):
    store = PersistentReviewStore(_repository(tmp_path))

    record = store.set_finding_status(
        "finding:finding-sample",
        "deferred",
        source_ref="review:review-sample",
        reviewed_by="operator-sample",
        review_note="Sample defer note",
        now="2026-01-02T00:00:00+00:00",
    )
    rows = store.list_finding_statuses(finding_ref="finding:finding-sample")

    assert record["record_type"] == "operator_finding_status"
    assert rows == [record]
    assert rows[0]["status"] == "deferred"


def test_review_summary_counts_include_history_and_finding_statuses(tmp_path):
    store = PersistentReviewStore(_repository(tmp_path))
    first = _review("a", severity="high")
    second = _review("b", severity="medium")
    store.add_reviews([first, second])
    store.update_status(second.review_id, "dismissed", now="2026-01-02T00:00:00+00:00")
    store.set_finding_status("finding:finding-sample", "resolved", now="2026-01-02T00:00:00+00:00")

    summary = store.summarize_reviews()

    assert summary["review_count"] == 2
    assert summary["by_status"]["open"] == 1
    assert summary["by_status"]["dismissed"] == 1
    assert summary["history_count"] == 1
    assert summary["finding_status_count"] == 1
    assert summary["automatic_changes"] is False


def test_review_json_export_import_round_trip(tmp_path):
    review = _review()
    exported = export_review_records([review], generated_at="2026-01-03T00:00:00+00:00")
    imported = import_review_records(exported)
    store = PersistentReviewStore(_repository(tmp_path))

    row_ids = store.import_reviews(exported)

    assert exported["export_type"] == "operator_review_records"
    assert exported["count"] == 1
    assert imported[0].to_dict() == review.to_dict()
    assert row_ids == [1]
    assert store.export_reviews(generated_at="2026-01-03T00:00:00+00:00")["count"] == 1


def test_history_builders_validate_inputs():
    review = _review()
    transition = build_review_transition_record(
        review,
        previous_status="open",
        new_status="deferred",
        transitioned_at="2026-01-02T00:00:00+00:00",
    )
    status = build_finding_status_record("finding:finding-sample", status="resolved", updated_at="2026-01-02T00:00:00+00:00")

    assert transition["record_type"] == "operator_review_transition"
    assert status["record_type"] == "operator_finding_status"
    with pytest.raises(PolicyError):
        build_review_transition_record(review, previous_status="open", new_status="running")
    with pytest.raises(PolicyError):
        build_finding_status_record("finding:finding-sample", status="running")


def test_review_integration_output_has_no_private_identifiers(tmp_path):
    store = PersistentReviewStore(_repository(tmp_path))
    review = _review()
    store.add_review(review)
    store.update_status(review.review_id, "approved", reviewed_by="operator-sample", now="2026-01-02T00:00:00+00:00")
    payload = json.dumps(
        {
            "reviews": [item.to_dict() for item in store.list_reviews()],
            "history": store.list_review_history(),
            "summary": store.summarize_reviews(),
        },
        sort_keys=True,
    )

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
