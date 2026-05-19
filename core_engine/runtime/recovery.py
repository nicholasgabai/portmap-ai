from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.policy.review_queue import ReviewQueue
from core_engine.policy.review_store import PersistentReviewStore
from core_engine.runtime.checkpoints import summarize_runtime_checkpoints
from core_engine.runtime.session import RuntimeSessionManager
from core_engine.runtime.session_state import SAFETY_FLAGS, summarize_runtime_session
from core_engine.storage.repositories import LocalStorageRepository


def build_runtime_recovery_summary(
    *,
    checkpoints: Iterable[dict[str, Any]] | None = None,
    sessions: Iterable[dict[str, Any] | Any] | RuntimeSessionManager | None = None,
    pipeline_results: Iterable[dict[str, Any]] | None = None,
    repository: LocalStorageRepository | None = None,
    review_store: PersistentReviewStore | ReviewQueue | None = None,
    export_bundles: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    checkpoint_rows = _rows(checkpoints)
    session_rows = _session_rows(sessions)
    pipeline_rows = _rows(pipeline_results)
    review_summary = _review_summary(review_store, checkpoint_rows)
    storage_summary = _storage_summary(repository, checkpoint_rows)
    export_summary = _export_summary(export_bundles, checkpoint_rows)
    failed_steps = detect_failed_steps(checkpoint_rows=checkpoint_rows, pipeline_results=pipeline_rows)
    incomplete_workflows = detect_incomplete_workflows(checkpoint_rows=checkpoint_rows, session_rows=session_rows, pipeline_results=pipeline_rows)
    pending_reviews = detect_pending_reviews(review_summary)
    export_ready = detect_export_ready_records(storage_summary, review_summary, export_summary)
    recommendations = build_recovery_recommendations(
        incomplete_workflows=incomplete_workflows,
        pending_reviews=pending_reviews,
        failed_steps=failed_steps,
        export_ready=export_ready,
        generated_at=timestamp,
    )
    return {
        "status": "needs_review" if recommendations else "ok",
        "generated_at": timestamp,
        "checkpoint_summary": summarize_runtime_checkpoints(checkpoint_rows),
        "last_known_session": _last_session(session_rows),
        "incomplete_workflows": incomplete_workflows,
        "pending_reviews": pending_reviews,
        "failed_steps": failed_steps,
        "export_ready": export_ready,
        "storage_summary": storage_summary,
        "review_summary": review_summary,
        "export_summary": export_summary,
        "recommendations": recommendations,
        "recommendation_count": len(recommendations),
        **SAFETY_FLAGS,
    }


def detect_incomplete_workflows(
    *,
    checkpoint_rows: Iterable[dict[str, Any]] | None = None,
    session_rows: Iterable[dict[str, Any]] | None = None,
    pipeline_results: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for checkpoint in _rows(checkpoint_rows):
        if checkpoint.get("status") in {"incomplete", "failed"}:
            records.append(_workflow_record("checkpoint", checkpoint.get("checkpoint_id"), checkpoint.get("status"), checkpoint.get("created_at")))
    for session in _rows(session_rows):
        if session.get("status") in {"running", "failed"}:
            records.append(_workflow_record("session", session.get("session_id"), session.get("status"), session.get("started_at")))
    for index, result in enumerate(_rows(pipeline_results)):
        if result.get("status") in {"partial", "failed"} or not result.get("ok", True):
            records.append(_workflow_record("pipeline", result.get("workflow_id") or f"pipeline-{index}", result.get("status") or "partial", result.get("generated_at")))
    return _dedupe(records, "workflow_id")


def detect_failed_steps(
    *,
    checkpoint_rows: Iterable[dict[str, Any]] | None = None,
    pipeline_results: Iterable[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    sources: list[tuple[str, dict[str, Any]]] = []
    sources.extend((str(row.get("checkpoint_id") or "checkpoint"), row.get("pipeline_result") or {}) for row in _rows(checkpoint_rows))
    sources.extend((str(row.get("workflow_id") or row.get("generated_at") or "pipeline"), row) for row in _rows(pipeline_results))
    for source_ref, result in sources:
        for step in _rows(result.get("step_results")):
            if step.get("ok") is False or step.get("status") == "failed":
                records.append(
                    {
                        "failed_step_id": _stable_id("failed-step", source_ref, step),
                        "source_ref": source_ref,
                        "step": str(step.get("step") or ""),
                        "status": str(step.get("status") or "failed"),
                        "error": str(step.get("error") or ""),
                        **SAFETY_FLAGS,
                    }
                )
    return _dedupe(records, "failed_step_id")


def detect_pending_reviews(review_summary: dict[str, Any]) -> dict[str, Any]:
    by_status = dict(review_summary.get("by_status") or {})
    open_count = int(by_status.get("open") or review_summary.get("open_review_count") or 0)
    deferred_count = int(by_status.get("deferred") or 0)
    approval_required_count = int(review_summary.get("approval_required_count") or 0)
    return {
        "pending_review_count": open_count + deferred_count,
        "open_review_count": open_count,
        "deferred_review_count": deferred_count,
        "approval_required_count": approval_required_count,
        "requires_operator_review": bool(open_count or deferred_count or approval_required_count),
        **SAFETY_FLAGS,
    }


def detect_export_ready_records(storage_summary: dict[str, Any], review_summary: dict[str, Any], export_summary: dict[str, Any]) -> dict[str, Any]:
    record_count = (
        int(storage_summary.get("event_count") or 0)
        + int(storage_summary.get("snapshot_count") or 0)
        + int(storage_summary.get("finding_count") or 0)
        + int(review_summary.get("review_count") or 0)
    )
    completed_exports = int(export_summary.get("completed_export_count") or 0)
    return {
        "export_ready": record_count > 0 and completed_exports == 0,
        "record_count": record_count,
        "completed_export_count": completed_exports,
        **SAFETY_FLAGS,
    }


def build_recovery_recommendations(
    *,
    incomplete_workflows: Iterable[dict[str, Any]],
    pending_reviews: dict[str, Any],
    failed_steps: Iterable[dict[str, Any]],
    export_ready: dict[str, Any],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    recommendations: list[dict[str, Any]] = []
    if list(incomplete_workflows):
        recommendations.append(_recommendation("resume_or_review_workflow", "medium", "Review incomplete runtime workflow", "Inspect the last runtime checkpoint before resuming local workflows.", timestamp))
    if list(failed_steps):
        recommendations.append(_recommendation("inspect_failed_steps", "medium", "Inspect failed runtime steps", "Review failed step records before running the workflow again.", timestamp))
    if pending_reviews.get("requires_operator_review"):
        recommendations.append(_recommendation("review_pending_items", "medium", "Review pending operator items", "Open or deferred review records require operator attention.", timestamp))
    if export_ready.get("export_ready"):
        recommendations.append(_recommendation("prepare_local_export", "low", "Prepare local export bundle", "Local evidence records are available for an operator-controlled export bundle.", timestamp))
    return recommendations


def build_recovery_checkpoint_from_repository(
    repository: LocalStorageRepository,
    *,
    session_summary: dict[str, Any] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    from core_engine.export.bundle import build_operational_export_bundle

    bundle = build_operational_export_bundle(repository=repository, generated_at=generated_at or _now())
    manifest = bundle.get("manifest") if isinstance(bundle.get("manifest"), dict) else {}
    return {
        "session_summary": dict(session_summary or {}),
        "storage_summary": {
            "event_count": len(repository.list_events()),
            "snapshot_count": len(repository.list_snapshots()),
            "asset_count": len(repository.list_assets()),
            "service_count": len(repository.list_services()),
            "topology_edge_count": len(repository.list_topology_edges()),
            "finding_count": len(repository.list_findings()),
            **SAFETY_FLAGS,
        },
        "export_summary": {
            "bundle_ready": True,
            "record_counts": dict(manifest.get("record_counts") or {}),
            "completed_export_count": 0,
            **SAFETY_FLAGS,
        },
        **SAFETY_FLAGS,
    }


def _review_summary(review_store: PersistentReviewStore | ReviewQueue | None, checkpoints: list[dict[str, Any]]) -> dict[str, Any]:
    if review_store is not None:
        return dict(review_store.summarize_reviews())
    for checkpoint in reversed(checkpoints):
        summary = checkpoint.get("review_summary")
        if isinstance(summary, dict) and summary:
            return dict(summary)
    return {
        "review_count": 0,
        "by_status": {},
        "approval_required_count": 0,
        **SAFETY_FLAGS,
    }


def _storage_summary(repository: LocalStorageRepository | None, checkpoints: list[dict[str, Any]]) -> dict[str, Any]:
    if repository is not None:
        return {
            "event_count": len(repository.list_events()),
            "snapshot_count": len(repository.list_snapshots()),
            "asset_count": len(repository.list_assets()),
            "service_count": len(repository.list_services()),
            "topology_edge_count": len(repository.list_topology_edges()),
            "finding_count": len(repository.list_findings()),
            **SAFETY_FLAGS,
        }
    for checkpoint in reversed(checkpoints):
        summary = checkpoint.get("storage_summary")
        if isinstance(summary, dict) and summary:
            return dict(summary)
    return {
        "event_count": 0,
        "snapshot_count": 0,
        "asset_count": 0,
        "service_count": 0,
        "topology_edge_count": 0,
        "finding_count": 0,
        **SAFETY_FLAGS,
    }


def _export_summary(export_bundles: Iterable[dict[str, Any]] | None, checkpoints: list[dict[str, Any]]) -> dict[str, Any]:
    rows = _rows(export_bundles)
    if rows:
        return {
            "completed_export_count": len(rows),
            "latest_digest": str((rows[-1].get("manifest") or {}).get("digest") or ""),
            **SAFETY_FLAGS,
        }
    for checkpoint in reversed(checkpoints):
        summary = checkpoint.get("export_summary")
        if isinstance(summary, dict) and summary:
            return dict(summary)
    return {
        "completed_export_count": 0,
        **SAFETY_FLAGS,
    }


def _session_rows(sessions: Iterable[dict[str, Any] | Any] | RuntimeSessionManager | None) -> list[dict[str, Any]]:
    if sessions is None:
        return []
    if isinstance(sessions, RuntimeSessionManager):
        return [summarize_runtime_session(session) for session in sessions.list_sessions()]
    return [summarize_runtime_session(session) for session in sessions]


def _last_session(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {}
    sorted_rows = sorted(rows, key=lambda row: (str(row.get("started_at") or ""), str(row.get("session_id") or "")))
    return sorted_rows[-1]


def _workflow_record(source_type: str, source_id: Any, status: Any, timestamp: Any) -> dict[str, Any]:
    return {
        "workflow_id": _stable_id("workflow", source_type, source_id, status, timestamp),
        "source_type": source_type,
        "source_id": str(source_id or ""),
        "status": str(status or "unknown"),
        "timestamp": str(timestamp or ""),
        "requires_operator_review": True,
        **SAFETY_FLAGS,
    }


def _recommendation(recommendation_type: str, severity: str, title: str, summary: str, timestamp: str) -> dict[str, Any]:
    return {
        "recommendation_id": _stable_id("recovery-recommendation", recommendation_type, title, summary, timestamp),
        "recommendation_type": recommendation_type,
        "severity": severity,
        "title": title,
        "summary": summary,
        "recommended_action": "operator_review",
        "operator_review_required": True,
        "created_at": timestamp,
        **SAFETY_FLAGS,
    }


def _dedupe(rows: Iterable[dict[str, Any]], key_name: str) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(_rows(rows)):
        key = str(row.get(key_name) or _stable_id(key_name, row, index))
        by_key.setdefault(key, row)
    return [by_key[key] for key in sorted(by_key)]


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
