from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.policy.models import REVIEW_STATES, PolicyError, ReviewRecord


REVIEW_RECORD_TYPE = "operator_review_record"
REVIEW_TRANSITION_RECORD_TYPE = "operator_review_transition"
FINDING_STATUS_RECORD_TYPE = "operator_finding_status"


def review_to_storage_record(review: ReviewRecord | dict[str, Any]) -> dict[str, Any]:
    payload = review.to_dict() if isinstance(review, ReviewRecord) else dict(review)
    review_id = _required(payload, "review_id")
    return {
        "finding_id": review_id,
        "finding_type": REVIEW_RECORD_TYPE,
        "record_type": REVIEW_RECORD_TYPE,
        "severity": str(payload.get("severity") or "info"),
        "review": _clean_review_payload(payload),
        "status": str(payload.get("status") or "open"),
        "source_ref": str(payload.get("source_ref") or ""),
        "category": str(payload.get("category") or ""),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def review_from_storage_record(record: dict[str, Any]) -> ReviewRecord:
    payload = record.get("review") if isinstance(record.get("review"), dict) else record
    return ReviewRecord(**_review_constructor_payload(payload))


def build_review_transition_record(
    review: ReviewRecord | dict[str, Any],
    *,
    previous_status: str,
    new_status: str,
    reviewed_by: str | None = None,
    review_note: str | None = None,
    transitioned_at: str | None = None,
) -> dict[str, Any]:
    payload = review.to_dict() if isinstance(review, ReviewRecord) else dict(review)
    review_id = _required(payload, "review_id")
    if previous_status not in REVIEW_STATES:
        raise PolicyError(f"unsupported previous_status: {previous_status}")
    if new_status not in REVIEW_STATES:
        raise PolicyError(f"unsupported new_status: {new_status}")
    timestamp = transitioned_at or _now()
    material = json.dumps(
        [review_id, previous_status, new_status, reviewed_by, review_note, timestamp],
        sort_keys=True,
        default=str,
        separators=(",", ":"),
    )
    transition_id = "review-transition-" + sha256(material.encode("utf-8")).hexdigest()[:16]
    return {
        "finding_id": transition_id,
        "transition_id": transition_id,
        "finding_type": REVIEW_TRANSITION_RECORD_TYPE,
        "record_type": REVIEW_TRANSITION_RECORD_TYPE,
        "review_id": review_id,
        "previous_status": previous_status,
        "new_status": new_status,
        "reviewed_by": reviewed_by,
        "review_note": review_note,
        "transitioned_at": timestamp,
        "severity": str(payload.get("severity") or "info"),
        "source_ref": str(payload.get("source_ref") or ""),
        "category": str(payload.get("category") or ""),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def apply_review_history(
    review: ReviewRecord,
    transitions: Iterable[dict[str, Any]],
) -> ReviewRecord:
    current = ReviewRecord(**_review_constructor_payload(review.to_dict()))
    rows = sorted(_transition_rows(transitions), key=lambda item: (str(item.get("transitioned_at") or ""), str(item.get("transition_id") or "")))
    for row in rows:
        new_status = str(row.get("new_status") or "")
        if new_status not in REVIEW_STATES:
            continue
        current.status = new_status
        current.updated_at = str(row.get("transitioned_at") or current.updated_at)
        current.reviewed_by = row.get("reviewed_by")
        current.review_note = row.get("review_note")
        current.automatic_changes = False
        current.administrator_controlled = True
        current.raw_payload_stored = False
    return current


def build_finding_status_record(
    finding_ref: str,
    *,
    status: str,
    source_ref: str | None = None,
    reviewed_by: str | None = None,
    review_note: str | None = None,
    updated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(finding_ref, str) or not finding_ref.strip():
        raise PolicyError("finding_ref must be a non-empty string")
    if status not in REVIEW_STATES:
        raise PolicyError(f"unsupported finding status: {status}")
    timestamp = updated_at or _now()
    material = json.dumps([finding_ref, status, source_ref, reviewed_by, review_note, timestamp], sort_keys=True, default=str)
    status_id = "finding-status-" + sha256(material.encode("utf-8")).hexdigest()[:16]
    return {
        "finding_id": status_id,
        "status_record_id": status_id,
        "finding_type": FINDING_STATUS_RECORD_TYPE,
        "record_type": FINDING_STATUS_RECORD_TYPE,
        "finding_ref": finding_ref,
        "status": status,
        "source_ref": source_ref or finding_ref,
        "reviewed_by": reviewed_by,
        "review_note": review_note,
        "updated_at": timestamp,
        "severity": "info",
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def export_review_records(reviews: Iterable[ReviewRecord | dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [_clean_review_payload(review.to_dict() if isinstance(review, ReviewRecord) else dict(review)) for review in reviews]
    return {
        "export_type": "operator_review_records",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "items": sorted(rows, key=lambda item: str(item.get("review_id") or "")),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def import_review_records(payload: dict[str, Any] | list[dict[str, Any]]) -> list[ReviewRecord]:
    rows = payload.get("items") if isinstance(payload, dict) else payload
    if not isinstance(rows, list):
        raise PolicyError("review import payload must include an items list")
    return [review_from_storage_record(row) for row in rows if isinstance(row, dict)]


def _transition_rows(rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in rows if isinstance(row, dict) and row.get("record_type") == REVIEW_TRANSITION_RECORD_TYPE]


def _clean_review_payload(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = set(ReviewRecord.__dataclass_fields__) | {"local_only"}
    return {key: value for key, value in payload.items() if key in allowed}


def _review_constructor_payload(payload: dict[str, Any]) -> dict[str, Any]:
    allowed = set(ReviewRecord.__dataclass_fields__)
    return {key: value for key, value in payload.items() if key in allowed}


def _required(payload: dict[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{field_name} must be a non-empty string")
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
