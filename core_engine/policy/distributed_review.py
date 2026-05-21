from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.policy.history import export_review_records, review_from_storage_record
from core_engine.policy.models import REVIEW_STATES, ReviewRecord
from core_engine.policy.review_queue import ReviewQueue
from core_engine.runtime.distributed_state import SAFETY_FLAGS


DISTRIBUTED_REVIEW_RECORD_VERSION = 1
DISTRIBUTED_REVIEW_POLICY_ID = "policy-distributed-review"


class DistributedReviewError(ValueError):
    """Raised when trusted-node review summary input is malformed."""


def build_distributed_review_summary(
    node_summaries: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    repeated_category_threshold: int = 2,
) -> dict[str, Any]:
    """Aggregate advisory review records from trusted local node summaries."""
    timestamp = generated_at or _now()
    nodes, malformed = normalize_node_review_summaries(node_summaries, generated_at=timestamp)
    reviews = sorted(
        [review for node in nodes for review in node["reviews"]],
        key=lambda item: (str(item.get("source_node_id") or ""), str(item.get("review_id") or "")),
    )
    duplicates = detect_duplicate_reviews(reviews)
    finding_statuses = summarize_cross_node_finding_statuses(nodes)
    repeated_categories = detect_repeated_review_categories(reviews, threshold=repeated_category_threshold)
    recommended_reviews = build_recommended_operator_review_records(
        duplicates=duplicates,
        repeated_categories=repeated_categories,
        generated_at=timestamp,
    )
    node_counts = summarize_distributed_review_nodes(nodes, malformed_nodes=malformed)
    export_ready = build_export_ready_review_aggregation(
        nodes,
        reviews=reviews,
        duplicates=duplicates,
        finding_statuses=finding_statuses,
        generated_at=timestamp,
    )
    summary = {
        "node_count": len(nodes),
        "malformed_node_count": len(malformed),
        "review_count": len(reviews),
        "duplicate_review_count": len(duplicates),
        "repeated_category_count": len(repeated_categories),
        "recommended_review_count": len(recommended_reviews),
        "finding_status_count": int(finding_statuses["status_record_count"]),
        "export_ready": bool(export_ready["export_ready"]),
        "administrator_review_required": bool(duplicates or repeated_categories or malformed),
        **SAFETY_FLAGS,
    }
    dashboard_panel = build_distributed_review_dashboard_panel(
        summary=summary,
        node_counts=node_counts,
        duplicates=duplicates,
        repeated_categories=repeated_categories,
    )
    return {
        "record_type": "distributed_review_summary",
        "record_version": DISTRIBUTED_REVIEW_RECORD_VERSION,
        "distributed_review_id": _stable_id("distributed-review", timestamp, summary, node_counts),
        "generated_at": timestamp,
        "node_summaries": nodes,
        "malformed_node_summaries": malformed,
        "reviews": reviews,
        "duplicates": duplicates,
        "repeated_categories": repeated_categories,
        "finding_statuses": finding_statuses,
        "recommended_reviews": [review.to_dict() for review in recommended_reviews],
        "export_ready": export_ready,
        "dashboard_panel": dashboard_panel,
        "summary": summary,
        **SAFETY_FLAGS,
    }


def normalize_node_review_summaries(
    node_summaries: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    timestamp = generated_at or _now()
    nodes: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    for index, summary in enumerate(node_summaries):
        try:
            nodes.append(normalize_node_review_summary(summary, generated_at=timestamp))
        except Exception as exc:
            malformed.append(_malformed_node_summary(index=index, error=str(exc), generated_at=timestamp))
    return sorted(nodes, key=lambda item: item["node_id"]), malformed


def normalize_node_review_summary(summary: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    if not isinstance(summary, dict):
        raise DistributedReviewError("node review summary must be an object")
    timestamp = generated_at or _now()
    node_id = _required_str(summary.get("node_id") or summary.get("source_node_id"), "node_id")
    role = str(summary.get("role") or "worker")
    source_refs = _source_refs(summary, node_id=node_id)
    reviews = [
        enrich_review_with_node_ownership(review.to_dict(), node_id=node_id, role=role, source_refs=source_refs)
        for review in import_review_drafts_from_node_summary(summary)
    ]
    finding_statuses = [
        _enrich_status_with_node_ownership(row, node_id=node_id, role=role, source_refs=source_refs)
        for row in _finding_status_rows(summary)
    ]
    history = [
        _enrich_status_with_node_ownership(row, node_id=node_id, role=role, source_refs=source_refs)
        for row in _history_rows(summary)
    ]
    return {
        "record_type": "distributed_node_review_summary",
        "record_version": DISTRIBUTED_REVIEW_RECORD_VERSION,
        "node_review_summary_id": _stable_id("node-review-summary", node_id, reviews, finding_statuses, timestamp),
        "node_id": node_id,
        "node_label": str(summary.get("node_label") or summary.get("label") or node_id),
        "role": role,
        "generated_at": timestamp,
        "source_refs": source_refs,
        "reviews": reviews,
        "review_history": history,
        "finding_statuses": finding_statuses,
        "summary": summarize_node_reviews(reviews, finding_statuses=finding_statuses),
        **SAFETY_FLAGS,
    }


def import_review_drafts_from_node_summary(summary: dict[str, Any]) -> list[ReviewRecord]:
    """Load sanitized review drafts from a trusted node summary."""
    rows = _review_rows(summary)
    reviews: list[ReviewRecord] = []
    for row in rows:
        review = review_from_storage_record(row)
        review.automatic_changes = False
        review.administrator_controlled = True
        review.raw_payload_stored = False
        reviews.append(review)
    return sorted(reviews, key=lambda item: item.review_id)


def enrich_review_with_node_ownership(
    review: ReviewRecord | dict[str, Any],
    *,
    node_id: str,
    role: str = "worker",
    source_refs: Iterable[str] | None = None,
) -> dict[str, Any]:
    payload = review.to_dict() if isinstance(review, ReviewRecord) else dict(review)
    review_id = _required_str(payload.get("review_id"), "review_id")
    refs = sorted(set([*list(source_refs or []), *[str(item) for item in payload.get("evidence_refs") or [] if str(item).strip()]]))
    return {
        **payload,
        "review_id": review_id,
        "source_node_id": node_id,
        "source_node_role": role,
        "source_node_ids": [node_id],
        "source_refs": refs or [f"node:{node_id}"],
        "node_owned": True,
        "remote_state_changes_enabled": False,
        **SAFETY_FLAGS,
    }


def summarize_node_reviews(
    reviews: Iterable[ReviewRecord | dict[str, Any]],
    *,
    finding_statuses: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    review_objects = [review if isinstance(review, ReviewRecord) else review_from_storage_record(review) for review in reviews]
    queue = ReviewQueue(review_objects)
    summary = queue.summarize_reviews()
    summary["finding_status_count"] = len(list(finding_statuses or []))
    return {**summary, **SAFETY_FLAGS}


def summarize_distributed_review_nodes(
    node_summaries: Iterable[dict[str, Any]],
    *,
    malformed_nodes: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    nodes = list(node_summaries)
    malformed = list(malformed_nodes or [])
    by_node = {
        node["node_id"]: {
            "node_id": node["node_id"],
            "role": node["role"],
            "review_count": int(node["summary"].get("review_count") or 0),
            "by_status": dict(node["summary"].get("by_status") or {}),
            "by_severity": dict(node["summary"].get("by_severity") or {}),
            "by_category": dict(node["summary"].get("by_category") or {}),
            "finding_status_count": int(node["summary"].get("finding_status_count") or 0),
            **SAFETY_FLAGS,
        }
        for node in nodes
    }
    by_role: dict[str, int] = {}
    for node in nodes:
        role = str(node.get("role") or "worker")
        by_role[role] = by_role.get(role, 0) + 1
    return {
        "node_count": len(nodes),
        "malformed_node_count": len(malformed),
        "by_node": dict(sorted(by_node.items())),
        "by_role": dict(sorted(by_role.items())),
        **SAFETY_FLAGS,
    }


def detect_duplicate_reviews(reviews: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = list(reviews)
    duplicate_groups: list[dict[str, Any]] = []
    duplicate_groups.extend(_duplicate_groups(rows, key_fields=("review_id",), conflict_type="duplicate_review_id"))
    duplicate_groups.extend(_duplicate_groups(rows, key_fields=("source_ref", "category"), conflict_type="duplicate_review_source"))
    unique: dict[str, dict[str, Any]] = {}
    for group in duplicate_groups:
        unique[group["duplicate_id"]] = group
    return sorted(unique.values(), key=lambda item: (item["conflict_type"], item["affected_ref"]))


def detect_repeated_review_categories(reviews: Iterable[dict[str, Any]], *, threshold: int = 2) -> list[dict[str, Any]]:
    by_category: dict[str, list[dict[str, Any]]] = {}
    for review in reviews:
        category = str(review.get("category") or "")
        if category:
            by_category.setdefault(category, []).append(review)
    repeated: list[dict[str, Any]] = []
    for category, rows in sorted(by_category.items()):
        source_nodes = sorted({str(row.get("source_node_id") or "") for row in rows if row.get("source_node_id")})
        if len(rows) < threshold and len(source_nodes) < threshold:
            continue
        repeated.append(
            {
                "record_type": "distributed_review_repeated_category",
                "category": category,
                "review_count": len(rows),
                "source_node_ids": source_nodes,
                "review_ids": sorted(str(row.get("review_id") or "") for row in rows),
                "recommended_review": True,
                "repeated_category_id": _stable_id("repeated-review-category", category, source_nodes, len(rows)),
                **SAFETY_FLAGS,
            }
        )
    return repeated


def summarize_cross_node_finding_statuses(node_summaries: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = [status for node in node_summaries for status in node.get("finding_statuses") or []]
    by_finding: dict[str, dict[str, Any]] = {}
    for row in rows:
        finding_ref = str(row.get("finding_ref") or row.get("source_ref") or "finding:unknown")
        status = str(row.get("status") or "open")
        source_node_id = str(row.get("source_node_id") or "node-unknown")
        entry = by_finding.setdefault(
            finding_ref,
            {
                "finding_ref": finding_ref,
                "status_count": 0,
                "by_status": {},
                "source_node_ids": set(),
                **SAFETY_FLAGS,
            },
        )
        entry["status_count"] += 1
        entry["by_status"][status] = entry["by_status"].get(status, 0) + 1
        entry["source_node_ids"].add(source_node_id)
    normalized = []
    for entry in by_finding.values():
        normalized.append(
            {
                **entry,
                "by_status": dict(sorted(entry["by_status"].items())),
                "source_node_ids": sorted(entry["source_node_ids"]),
            }
        )
    return {
        "status_record_count": len(rows),
        "finding_count": len(normalized),
        "findings": sorted(normalized, key=lambda item: item["finding_ref"]),
        **SAFETY_FLAGS,
    }


def build_recommended_operator_review_records(
    *,
    duplicates: Iterable[dict[str, Any]],
    repeated_categories: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> list[ReviewRecord]:
    timestamp = generated_at or _now()
    records: list[ReviewRecord] = []
    for duplicate in duplicates:
        records.append(
            _recommended_review(
                source_ref=f"distributed-review:{duplicate['duplicate_id']}",
                category="distributed_review_duplicate",
                severity="high",
                title="Distributed Review Duplicate",
                summary=f"Duplicate review records require operator reconciliation for {duplicate['affected_ref']}.",
                evidence_refs=duplicate.get("review_ids") or [],
                now=timestamp,
            )
        )
    for repeated in repeated_categories:
        records.append(
            _recommended_review(
                source_ref=f"distributed-review:{repeated['repeated_category_id']}",
                category="distributed_review_repeated_category",
                severity="medium",
                title="Distributed Review Repeated Category",
                summary=f"Repeated review category {repeated['category']} appears across trusted nodes.",
                evidence_refs=repeated.get("review_ids") or [],
                now=timestamp,
            )
        )
    return sorted(records, key=lambda item: item.review_id)


def build_export_ready_review_aggregation(
    node_summaries: Iterable[dict[str, Any]],
    *,
    reviews: Iterable[dict[str, Any]] | None = None,
    duplicates: Iterable[dict[str, Any]] | None = None,
    finding_statuses: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    nodes = list(node_summaries)
    rows = list(reviews or [review for node in nodes for review in node.get("reviews") or []])
    base_export = export_review_records(rows, generated_at=timestamp)
    return {
        "export_type": "distributed_operator_review_records",
        "generated_at": timestamp,
        "export_ready": bool(rows or nodes),
        "review_count": len(rows),
        "node_count": len(nodes),
        "duplicate_review_count": len(list(duplicates or [])),
        "finding_status_count": int((finding_statuses or {}).get("status_record_count") or 0),
        "source_node_ids": sorted({str(node.get("node_id") or "") for node in nodes if node.get("node_id")}),
        "review_export": base_export,
        "items": sorted(rows, key=lambda item: (str(item.get("source_node_id") or ""), str(item.get("review_id") or ""))),
        **SAFETY_FLAGS,
    }


def build_distributed_review_dashboard_panel(
    *,
    summary: dict[str, Any],
    node_counts: dict[str, Any],
    duplicates: Iterable[dict[str, Any]],
    repeated_categories: Iterable[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "panel": "distributed_review_queue",
        "status": "review_required" if summary.get("administrator_review_required") else "ok",
        "metrics": {
            "node_count": int(summary.get("node_count") or 0),
            "review_count": int(summary.get("review_count") or 0),
            "duplicate_review_count": int(summary.get("duplicate_review_count") or 0),
            "repeated_category_count": int(summary.get("repeated_category_count") or 0),
            "recommended_review_count": int(summary.get("recommended_review_count") or 0),
        },
        "node_counts": node_counts,
        "duplicate_count": len(list(duplicates)),
        "repeated_categories": [str(row.get("category") or "") for row in repeated_categories],
        "remote_state_changes_enabled": False,
        **SAFETY_FLAGS,
    }


def _duplicate_groups(rows: list[dict[str, Any]], *, key_fields: tuple[str, ...], conflict_type: str) -> list[dict[str, Any]]:
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = {}
    for row in rows:
        key = tuple(str(row.get(field) or "") for field in key_fields)
        if all(key):
            groups.setdefault(key, []).append(row)
    duplicates: list[dict[str, Any]] = []
    for key, group in groups.items():
        source_nodes = sorted({str(row.get("source_node_id") or "") for row in group if row.get("source_node_id")})
        review_ids = sorted({str(row.get("review_id") or "") for row in group if row.get("review_id")})
        if len(group) < 2 or (len(source_nodes) < 2 and len(review_ids) < 2):
            continue
        affected_ref = "|".join(key)
        duplicates.append(
            {
                "record_type": "distributed_review_duplicate",
                "conflict_type": conflict_type,
                "affected_ref": affected_ref,
                "source_node_ids": source_nodes,
                "review_ids": review_ids,
                "review_count": len(group),
                "recommended_review": True,
                "duplicate_id": _stable_id("distributed-review-duplicate", conflict_type, affected_ref, source_nodes, review_ids),
                **SAFETY_FLAGS,
            }
        )
    return duplicates


def _recommended_review(
    *,
    source_ref: str,
    category: str,
    severity: str,
    title: str,
    summary: str,
    evidence_refs: list[str],
    now: str,
) -> ReviewRecord:
    return ReviewRecord(
        review_id="review-" + _stable_id("distributed-review-recommendation", source_ref, category, severity)[len("distributed-review-recommendation-") :],
        policy_id=DISTRIBUTED_REVIEW_POLICY_ID,
        source_ref=source_ref,
        category=category,
        severity=severity,
        title=title,
        summary=summary,
        evidence_refs=sorted(set(str(item) for item in evidence_refs if str(item).strip())),
        recommended_action="operator_review",
        status="open",
        approval_required=True,
        automatic_changes=False,
        administrator_controlled=True,
        raw_payload_stored=False,
        created_at=now,
        updated_at=now,
    )


def _review_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    candidates = []
    for key in ("reviews", "review_records", "review_drafts"):
        value = summary.get(key)
        if isinstance(value, list):
            candidates.extend(row for row in value if isinstance(row, dict))
    export_payload = summary.get("review_export") or summary.get("export")
    if isinstance(export_payload, dict) and isinstance(export_payload.get("items"), list):
        candidates.extend(row for row in export_payload["items"] if isinstance(row, dict))
    if not candidates and isinstance(summary.get("items"), list):
        candidates.extend(row for row in summary["items"] if isinstance(row, dict))
    return candidates


def _finding_status_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = summary.get("finding_statuses") or summary.get("finding_status_records") or []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _history_rows(summary: dict[str, Any]) -> list[dict[str, Any]]:
    rows = summary.get("review_history") or summary.get("history") or []
    return [dict(row) for row in rows if isinstance(row, dict)]


def _enrich_status_with_node_ownership(
    row: dict[str, Any],
    *,
    node_id: str,
    role: str,
    source_refs: Iterable[str],
) -> dict[str, Any]:
    return {
        **dict(row),
        "source_node_id": node_id,
        "source_node_role": role,
        "source_node_ids": [node_id],
        "source_refs": sorted(set(str(item) for item in source_refs if str(item).strip())),
        "remote_state_changes_enabled": False,
        **SAFETY_FLAGS,
    }


def _malformed_node_summary(*, index: int, error: str, generated_at: str) -> dict[str, Any]:
    node_id = f"malformed-review-node-{index}"
    return {
        "record_type": "distributed_node_review_summary",
        "node_id": node_id,
        "node_label": node_id,
        "role": "unknown",
        "generated_at": generated_at,
        "status": "malformed",
        "error": error,
        "reviews": [],
        "finding_statuses": [],
        "summary": {
            "review_count": 0,
            "by_status": {state: 0 for state in sorted(REVIEW_STATES)},
            "by_severity": {},
            "by_category": {},
            "finding_status_count": 0,
            **SAFETY_FLAGS,
        },
        **SAFETY_FLAGS,
    }


def _source_refs(summary: dict[str, Any], *, node_id: str) -> list[str]:
    refs = [str(item) for item in summary.get("source_refs") or [] if str(item).strip()]
    if not refs:
        refs.append(f"node:{node_id}")
    return sorted(set(refs))


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DistributedReviewError(f"{field_name} must be a non-empty string")
    return value


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
