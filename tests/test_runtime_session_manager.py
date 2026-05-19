import json
import re

import pytest

from core_engine.runtime import (
    RuntimeSessionError,
    RuntimeSessionManager,
    create_runtime_session,
    summarize_runtime_session,
)
from core_engine.runtime.pipeline import run_runtime_pipeline


PRIVATE_IDENTIFIER_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def test_create_runtime_session_with_safety_defaults():
    session = create_runtime_session(
        session_id="session-alpha",
        mode="dry-run",
        started_at="2026-01-01T00:00:00+00:00",
        enabled_components=["pipeline", "storage"],
    )
    summary = summarize_runtime_session(session)

    assert summary["session_id"] == "session-alpha"
    assert summary["mode"] == "dry-run"
    assert summary["status"] == "running"
    assert summary["started_at"] == "2026-01-01T00:00:00+00:00"
    assert list(summary["enabled_components"]) == ["pipeline", "storage"]
    assert summary["local_only"] is True
    assert summary["raw_payload_stored"] is False
    assert summary["automatic_changes"] is False
    assert summary["administrator_controlled"] is True


def test_invalid_session_mode_is_rejected():
    with pytest.raises(RuntimeSessionError):
        create_runtime_session(session_id="session-invalid", mode="external-sync")


def test_session_stop_records_timestamp_and_status():
    session = create_runtime_session(session_id="session-stop", started_at="2026-01-01T00:00:00+00:00")

    session.stop(stopped_at="2026-01-01T00:05:00+00:00")

    summary = session.to_dict()
    assert summary["status"] == "stopped"
    assert summary["stopped_at"] == "2026-01-01T00:05:00+00:00"


def test_runtime_session_manager_start_stop_list_and_remove():
    manager = RuntimeSessionManager()
    first = manager.start_session(session_id="session-b", enabled_components=["events"])
    second = manager.start_session(session_id="session-a", enabled_components=["storage"])

    assert [session.session_id for session in manager.list_sessions()] == ["session-a", "session-b"]
    assert manager.get_session(first.session_id) is first
    assert manager.stop_session(second.session_id, stopped_at="2026-01-01T00:10:00+00:00") is True
    assert second.status == "stopped"
    assert manager.remove_session("session-b") is True
    assert manager.remove_session("missing") is False
    assert manager.local_only is True


def test_attach_pipeline_result_and_status_references():
    manager = RuntimeSessionManager()
    session = manager.start_session(
        session_id="session-pipeline",
        enabled_components=["pipeline", "events", "storage", "reviews", "export"],
    )
    pipeline_result = run_runtime_pipeline(
        assets=[{"asset_id": "asset-alpha", "label": "Asset Alpha"}],
        services=[{"service_id": "service-alpha", "asset_id": "asset-alpha", "service": "https"}],
        generated_at="2026-01-02T00:00:00+00:00",
    )

    summary = manager.attach_pipeline_result(session.session_id, pipeline_result)
    manager.attach_event_summary(session.session_id, {"event_count": pipeline_result["summary"]["event_count"]})
    manager.attach_storage_summary(session.session_id, {"storage_write_count": 0, "dry_run": True})
    manager.attach_review_summary(session.session_id, {"open_review_count": 0})
    final_summary = manager.attach_export_summary(session.session_id, {"bundle_ready": False})

    assert summary["pipeline_summary"]["status"] == "ok"
    assert final_summary["event_summary"]["event_count"] == pipeline_result["summary"]["event_count"]
    assert final_summary["storage_summary"]["storage_write_count"] == 0
    assert final_summary["review_summary"]["open_review_count"] == 0
    assert final_summary["export_summary"]["bundle_ready"] is False
    assert sorted(final_summary["status_references"]) == ["events", "export", "pipeline", "reviews", "storage"]


def test_warning_and_error_summaries_are_recorded():
    session = create_runtime_session(session_id="session-warning")

    session.record_warning("sample warning")
    session.record_error("sample error")

    summary = summarize_runtime_session(session)
    assert summary["status"] == "failed"
    assert summary["warning_count"] == 1
    assert summary["error_count"] == 1
    assert summary["last_warning"] == "sample warning"
    assert summary["last_error"] == "sample error"


def test_manager_summary_is_deterministic():
    manager = RuntimeSessionManager()
    manager.start_session(session_id="session-c", mode="service-preview")
    manager.start_session(session_id="session-a", mode="dry-run")
    manager.start_session(session_id="session-b", mode="dry-run")
    manager.stop_session("session-c", status="stopped", stopped_at="2026-01-01T00:00:00+00:00")

    summary = manager.summarize_sessions()

    assert [item["session_id"] for item in summary["items"]] == ["session-a", "session-b", "session-c"]
    assert summary["session_count"] == 3
    assert summary["sessions_by_mode"] == {"dry-run": 2, "service-preview": 1}
    assert summary["sessions_by_status"] == {"running": 2, "stopped": 1}


def test_unknown_session_reference_is_rejected():
    manager = RuntimeSessionManager()

    with pytest.raises(RuntimeSessionError):
        manager.attach_event_summary("missing", {"event_count": 0})


def test_runtime_session_output_does_not_contain_private_identifiers():
    manager = RuntimeSessionManager()
    manager.start_session(
        session_id="session-sanitized",
        mode="dry-run",
        enabled_components=["pipeline", "storage"],
        metadata={"operator_note": "sanitized fixture"},
    )
    payload = json.dumps(manager.summarize_sessions(), sort_keys=True)

    for pattern in PRIVATE_IDENTIFIER_PATTERNS:
        assert not pattern.search(payload)
