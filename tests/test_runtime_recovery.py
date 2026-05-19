import json
import re

import pytest

from core_engine.policy import PersistentReviewStore, build_review_record, create_policy
from core_engine.runtime import (
    RuntimeCheckpointError,
    RuntimeSessionManager,
    build_runtime_checkpoint,
    build_runtime_recovery_summary,
    detect_failed_steps,
    detect_incomplete_workflows,
    load_runtime_checkpoint,
    runtime_checkpoint_from_json,
    runtime_checkpoint_to_json,
    validate_runtime_checkpoint,
    write_runtime_checkpoint,
)
from core_engine.runtime.pipeline import run_runtime_pipeline
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
    return LocalStorageRepository(SQLiteStore(tmp_path / "recovery.db"))


def _review_store(repository):
    store = PersistentReviewStore(repository)
    policy = create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review advisory findings.",
        now="2026-01-01T00:00:00+00:00",
    )
    review = build_review_record(
        policy=policy,
        source_ref="finding:finding-sample",
        category="policy_review_required",
        severity="high",
        title="Sample Review",
        summary="Sample review summary.",
        now="2026-01-01T00:00:00+00:00",
    )
    store.add_review(review)
    return store


def _partial_pipeline_result():
    return run_runtime_pipeline(
        assets=[{"asset_id": "asset-alpha", "label": "Asset Alpha"}],
        services=[{"service_id": "service-alpha", "asset_id": "asset-alpha", "service": "https"}],
        dry_run=False,
        write_local=True,
        generated_at="2026-01-02T00:00:00+00:00",
    )


def test_checkpoint_record_creation_and_validation():
    checkpoint = build_runtime_checkpoint(
        checkpoint_id="checkpoint-alpha",
        session_summary={"session_id": "session-alpha", "status": "running"},
        pipeline_result=_partial_pipeline_result(),
        created_at="2026-01-02T00:00:00+00:00",
    )

    assert checkpoint["checkpoint_id"] == "checkpoint-alpha"
    assert checkpoint["record_type"] == "runtime_checkpoint"
    assert checkpoint["status"] == "incomplete"
    assert validate_runtime_checkpoint(checkpoint)["ok"] is True
    assert checkpoint["automatic_changes"] is False
    assert checkpoint["administrator_controlled"] is True
    assert checkpoint["raw_payload_stored"] is False


def test_checkpoint_json_round_trip_and_file_helpers(tmp_path):
    checkpoint = build_runtime_checkpoint(
        checkpoint_id="checkpoint-json",
        session_summary={"session_id": "session-json", "status": "stopped"},
        created_at="2026-01-02T00:00:00+00:00",
    )
    text = runtime_checkpoint_to_json(checkpoint)
    loaded = runtime_checkpoint_from_json(text)
    write_result = write_runtime_checkpoint(tmp_path / "checkpoints" / "checkpoint.json", checkpoint)
    load_result = load_runtime_checkpoint(tmp_path / "checkpoints" / "checkpoint.json")

    assert loaded == checkpoint
    assert write_result["status"] == "written"
    assert write_result["path_stored"] is False
    assert load_result["ok"] is True
    assert load_result["checkpoint"] == checkpoint


def test_malformed_checkpoint_handling(tmp_path):
    bad = tmp_path / "bad-checkpoint.json"
    bad.write_text("{bad", encoding="utf-8")

    result = load_runtime_checkpoint(bad)

    assert result["ok"] is False
    assert result["status"] == "invalid"
    assert result["checkpoint"] is None
    with pytest.raises(RuntimeCheckpointError):
        runtime_checkpoint_from_json("{}")


def test_incomplete_workflow_detection_from_sessions_and_pipeline():
    manager = RuntimeSessionManager()
    manager.start_session(session_id="session-running", started_at="2026-01-01T00:00:00+00:00")
    pipeline = _partial_pipeline_result()

    workflows = detect_incomplete_workflows(
        session_rows=manager.summarize_sessions()["items"],
        pipeline_results=[pipeline],
    )

    assert {item["source_type"] for item in workflows} == {"pipeline", "session"}
    assert all(item["requires_operator_review"] is True for item in workflows)


def test_failed_step_detection_from_pipeline_results():
    pipeline = _partial_pipeline_result()

    failed_steps = detect_failed_steps(pipeline_results=[pipeline])

    assert len(failed_steps) == 1
    assert failed_steps[0]["step"] == "storage"
    assert "LocalStorageRepository" in failed_steps[0]["error"]


def test_recovery_summary_detects_pending_reviews_failed_steps_and_export_ready(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_event(
        {
            "event_id": "event-sample",
            "event_type": "system_notice",
            "severity": "info",
            "source": "runtime.test",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "message": "Sample event.",
        }
    )
    review_store = _review_store(repository)
    pipeline = _partial_pipeline_result()
    checkpoint = build_runtime_checkpoint(
        checkpoint_id="checkpoint-summary",
        session_summary={"session_id": "session-summary", "status": "running"},
        pipeline_result=pipeline,
        review_summary=review_store.summarize_reviews(),
        storage_summary={"event_count": 1, "snapshot_count": 0, "finding_count": 1},
        created_at="2026-01-02T00:00:00+00:00",
    )

    summary = build_runtime_recovery_summary(
        checkpoints=[checkpoint],
        pipeline_results=[pipeline],
        repository=repository,
        review_store=review_store,
        generated_at="2026-01-03T00:00:00+00:00",
    )

    assert summary["status"] == "needs_review"
    assert summary["checkpoint_summary"]["checkpoint_count"] == 1
    assert summary["pending_reviews"]["pending_review_count"] == 1
    assert summary["failed_steps"]
    assert summary["export_ready"]["export_ready"] is True
    assert {item["recommendation_type"] for item in summary["recommendations"]} >= {
        "resume_or_review_workflow",
        "inspect_failed_steps",
        "review_pending_items",
        "prepare_local_export",
    }


def test_recovery_summary_ok_for_empty_state():
    summary = build_runtime_recovery_summary(generated_at="2026-01-03T00:00:00+00:00")

    assert summary["status"] == "ok"
    assert summary["recommendation_count"] == 0
    assert summary["checkpoint_summary"]["checkpoint_count"] == 0


def test_runtime_recovery_output_has_no_private_identifiers(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_finding({"finding_id": "finding-sample", "finding_type": "sample", "severity": "medium"})
    summary = build_runtime_recovery_summary(
        repository=repository,
        generated_at="2026-01-03T00:00:00+00:00",
    )
    payload = json.dumps(summary, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
