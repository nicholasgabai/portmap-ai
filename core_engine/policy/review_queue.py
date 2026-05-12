from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Iterable

from core_engine.policy.models import REVIEW_STATES, PolicyError, ReviewRecord


class ReviewQueue:
    """In-memory local queue for advisory operator review records."""

    def __init__(self, reviews: Iterable[ReviewRecord] | None = None) -> None:
        self._reviews: dict[str, ReviewRecord] = {}
        for review in reviews or []:
            self.add_review(review)

    @property
    def local_only(self) -> bool:
        return True

    def add_review(self, review: ReviewRecord) -> ReviewRecord:
        if not isinstance(review, ReviewRecord):
            raise PolicyError("add_review requires a ReviewRecord")
        if review.review_id in self._reviews:
            raise PolicyError(f"review already exists: {review.review_id}")
        self._reviews[review.review_id] = review
        return review

    def list_reviews(
        self,
        *,
        status: str | None = None,
        severity: str | None = None,
        category: str | None = None,
    ) -> list[ReviewRecord]:
        rows = list(self._reviews.values())
        if status is not None:
            rows = [review for review in rows if review.status == status]
        if severity is not None:
            rows = [review for review in rows if review.severity == severity]
        if category is not None:
            rows = [review for review in rows if review.category == category]
        return sorted(rows, key=lambda item: (item.created_at, item.review_id))

    def get_review(self, review_id: str) -> ReviewRecord | None:
        return self._reviews.get(review_id)

    def update_status(
        self,
        review_id: str,
        status: str,
        *,
        reviewed_by: str | None = None,
        review_note: str | None = None,
        now: str | None = None,
    ) -> ReviewRecord:
        if status not in REVIEW_STATES:
            raise PolicyError(f"unsupported review status: {status}")
        review = self._reviews.get(review_id)
        if review is None:
            raise PolicyError(f"review not found: {review_id}")
        if review.status != status and review.status in {"dismissed", "resolved"} and status == "open":
            raise PolicyError("closed reviews cannot be reopened by this queue")
        review.status = status
        review.updated_at = now or _now()
        review.reviewed_by = reviewed_by
        review.review_note = review_note
        review.automatic_changes = False
        review.administrator_controlled = True
        review.raw_payload_stored = False
        return review

    def summarize_reviews(self) -> dict[str, Any]:
        reviews = list(self._reviews.values())
        by_status: dict[str, int] = {state: 0 for state in sorted(REVIEW_STATES)}
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        approval_required_count = 0
        for review in reviews:
            by_status[review.status] += 1
            by_severity[review.severity] = by_severity.get(review.severity, 0) + 1
            by_category[review.category] = by_category.get(review.category, 0) + 1
            if review.approval_required:
                approval_required_count += 1
        return {
            "status": "ok",
            "review_count": len(reviews),
            "by_status": by_status,
            "by_severity": dict(sorted(by_severity.items())),
            "by_category": dict(sorted(by_category.items())),
            "approval_required_count": approval_required_count,
            "automatic_changes": False,
            "administrator_controlled": True,
            "raw_payload_stored": False,
            "local_only": True,
        }


def _now() -> str:
    return datetime.now(UTC).isoformat()
