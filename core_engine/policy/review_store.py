from __future__ import annotations

from typing import Any, Iterable

from core_engine.policy.history import (
    FINDING_STATUS_RECORD_TYPE,
    REVIEW_RECORD_TYPE,
    REVIEW_TRANSITION_RECORD_TYPE,
    apply_review_history,
    build_finding_status_record,
    build_review_transition_record,
    export_review_records,
    import_review_records,
    review_from_storage_record,
    review_to_storage_record,
)
from core_engine.policy.models import PolicyError, REVIEW_STATES, ReviewRecord
from core_engine.policy.review_queue import ReviewQueue
from core_engine.storage.repositories import LocalStorageRepository


class PersistentReviewStore:
    """Persist advisory review records through the existing local repository."""

    def __init__(self, repository: LocalStorageRepository) -> None:
        if not isinstance(repository, LocalStorageRepository):
            raise PolicyError("PersistentReviewStore requires a LocalStorageRepository")
        self.repository = repository

    @property
    def local_only(self) -> bool:
        return True

    def add_review(self, review: ReviewRecord) -> int:
        return self.repository.insert_finding(review_to_storage_record(review))

    def add_reviews(self, reviews: Iterable[ReviewRecord]) -> list[int]:
        return [self.add_review(review) for review in reviews]

    def list_reviews(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
        source_ref: str | None = None,
    ) -> list[ReviewRecord]:
        reviews = [apply_review_history(review, self._transitions_for(review.review_id)) for review in self._base_reviews()]
        if status is not None:
            _validate_status(status)
            reviews = [review for review in reviews if review.status == status]
        if severity is not None:
            reviews = [review for review in reviews if review.severity == severity]
        if category is not None:
            reviews = [review for review in reviews if review.category == category]
        if source_ref is not None:
            reviews = [review for review in reviews if review.source_ref == source_ref]
        return sorted(reviews, key=lambda item: (item.created_at, item.review_id))

    def get_review(self, review_id: str) -> ReviewRecord | None:
        for review in self.list_reviews():
            if review.review_id == review_id:
                return review
        return None

    def update_status(
        self,
        review_id: str,
        status: str,
        *,
        reviewed_by: str | None = None,
        review_note: str | None = None,
        now: str | None = None,
    ) -> ReviewRecord:
        _validate_status(status)
        current = self.get_review(review_id)
        if current is None:
            raise PolicyError(f"review not found: {review_id}")
        previous_status = current.status
        queue = ReviewQueue([current])
        updated = queue.update_status(
            review_id,
            status,
            reviewed_by=reviewed_by,
            review_note=review_note,
            now=now,
        )
        transition = build_review_transition_record(
            current,
            previous_status=previous_status,
            new_status=updated.status,
            reviewed_by=reviewed_by,
            review_note=review_note,
            transitioned_at=updated.updated_at,
        )
        self.repository.insert_finding(transition)
        return updated

    def list_review_history(self, review_id: str | None = None) -> list[dict[str, Any]]:
        rows = [row for row in self.repository.list_findings() if row.get("record_type") == REVIEW_TRANSITION_RECORD_TYPE]
        if review_id is not None:
            rows = [row for row in rows if row.get("review_id") == review_id]
        return sorted(rows, key=lambda item: (str(item.get("transitioned_at") or ""), str(item.get("transition_id") or "")))

    def set_finding_status(
        self,
        finding_ref: str,
        status: str,
        *,
        source_ref: str | None = None,
        reviewed_by: str | None = None,
        review_note: str | None = None,
        now: str | None = None,
    ) -> dict[str, Any]:
        record = build_finding_status_record(
            finding_ref,
            status=status,
            source_ref=source_ref,
            reviewed_by=reviewed_by,
            review_note=review_note,
            updated_at=now,
        )
        self.repository.insert_finding(record)
        return record

    def list_finding_statuses(self, *, finding_ref: str | None = None) -> list[dict[str, Any]]:
        rows = [row for row in self.repository.list_findings() if row.get("record_type") == FINDING_STATUS_RECORD_TYPE]
        if finding_ref is not None:
            rows = [row for row in rows if row.get("finding_ref") == finding_ref]
        return sorted(rows, key=lambda item: (str(item.get("updated_at") or ""), str(item.get("status_record_id") or "")))

    def summarize_reviews(self) -> dict[str, Any]:
        queue = ReviewQueue(self.list_reviews())
        summary = queue.summarize_reviews()
        summary["history_count"] = len(self.list_review_history())
        summary["finding_status_count"] = len(self.list_finding_statuses())
        return summary

    def export_reviews(self, *, generated_at: str | None = None) -> dict[str, Any]:
        return export_review_records(self.list_reviews(), generated_at=generated_at)

    def import_reviews(self, payload: dict[str, Any] | list[dict[str, Any]]) -> list[int]:
        return self.add_reviews(import_review_records(payload))

    def _base_reviews(self) -> list[ReviewRecord]:
        rows = [row for row in self.repository.list_findings() if row.get("record_type") == REVIEW_RECORD_TYPE]
        return [review_from_storage_record(row) for row in rows]

    def _transitions_for(self, review_id: str) -> list[dict[str, Any]]:
        return self.list_review_history(review_id)


def _validate_status(status: str) -> None:
    if status not in REVIEW_STATES:
        raise PolicyError(f"unsupported review status: {status}")
