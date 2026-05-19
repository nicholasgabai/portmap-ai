import json
import re

from core_engine.events import LocalEvent
from core_engine.events.queue import LocalEventQueue
from core_engine.policy import PersistentReviewStore, build_review_record, create_policy
from core_engine.runtime import (
    LocalRuntimeScheduler,
    RuntimeSessionManager,
    build_runtime_health_summary,
    create_runtime_job,
    default_runtime_profile,
    event_queue_health_check,
    export_readiness_health_check,
    scheduler_health_check,
)
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore
from gui.web.providers import StaticDashboardProvider


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.\d+\."),
    re.compile(r"172\.(1[6-9]|2\d|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
]


def _repository(tmp_path):
    return LocalStorageRepository(SQLiteStore(tmp_path / "health.db"))


def _review_store(repository):
    store = PersistentReviewStore(repository)
    policy = create_policy(
        policy_id="policy-sample",
        name="Sample Review Policy",
        description="Review advisory findings.",
        now="2026-01-01T00:00:00+00:00",
    )
    store.add_review(
        build_review_record(
            policy=policy,
            source_ref="finding:finding-sample",
            category="policy_review_required",
            severity="high",
            title="Sample Review",
            summary="Sample review summary.",
            now="2026-01-01T00:00:00+00:00",
        )
    )
    return store


def test_event_queue_health_uses_depth_thresholds():
    queue = LocalEventQueue()
    for index in range(3):
        queue.enqueue(
            LocalEvent(
                event_type="system_notice",
                severity="info",
                source="test",
                message=f"Sample event {index}",
                timestamp="2026-01-01T00:00:00+00:00",
            )
        )

    check = event_queue_health_check(queue, budgets={"event_queue_warning_depth": 2, "event_queue_critical_depth": 10})

    assert check["name"] == "event_queue"
    assert check["status"] == "degraded"
    assert check["severity"] == "medium"
    assert check["details"]["queue_depth"] == 3


def test_scheduler_health_reports_failed_jobs_without_crashing():
    scheduler = LocalRuntimeScheduler(time_fn=lambda: 100.0)
    scheduler.add_job(create_runtime_job("health_check", interval_seconds=60, job_id="job-health"))
    scheduler.state.record_job_failure()

    check = scheduler_health_check(scheduler)

    assert check["name"] == "scheduler"
    assert check["status"] == "degraded"
    assert check["details"]["failed_job_count"] == 1


def test_runtime_health_summary_combines_components(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_event(
        {
            "event_id": "event-sample",
            "event_type": "system_notice",
            "severity": "info",
            "source": "runtime.health.test",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "message": "Sample event.",
        }
    )
    review_store = _review_store(repository)
    manager = RuntimeSessionManager()
    manager.start_session(session_id="session-health", started_at="2026-01-01T00:00:00+00:00")
    provider = StaticDashboardProvider({"health": {"status": "ok", "count": 0, "items": []}}, generated_at=lambda: "2026-01-01T00:00:00+00:00")

    summary = build_runtime_health_summary(
        profile=default_runtime_profile(generated_at="2026-01-01T00:00:00+00:00"),
        scheduler={"scheduler_status": "running", "failed_job_count": 0, "executed_job_count": 1},
        event_queue=[],
        repository=repository,
        review_store=review_store,
        dashboard_provider=provider,
        sessions=manager,
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert summary["generated_at"] == "2026-01-02T00:00:00+00:00"
    assert summary["summary"]["check_count"] == 7
    assert any(check["name"] == "storage" for check in summary["checks"])
    assert summary["health_event"]["event_type"] == "runtime_health"
    assert summary["health_event"]["raw_payload_stored"] is False
    assert summary["automatic_changes"] is False


def test_export_readiness_check_reports_ready_records(tmp_path):
    repository = _repository(tmp_path)
    repository.insert_finding({"finding_id": "finding-sample", "finding_type": "sample", "severity": "medium"})

    check = export_readiness_health_check(repository=repository)

    assert check["name"] == "export_readiness"
    assert check["severity"] == "low"
    assert check["details"]["export_ready"] is True
    assert check["details"]["bundle_digest"].startswith("sha256:")


def test_dashboard_provider_failure_is_degraded():
    class FailingProvider:
        def get(self, _path):
            raise RuntimeError("sample provider failure")

    summary = build_runtime_health_summary(dashboard_provider=FailingProvider(), generated_at="2026-01-02T00:00:00+00:00")

    dashboard = [check for check in summary["checks"] if check["name"] == "dashboard_provider"][0]
    assert dashboard["status"] == "degraded"
    assert "sample provider failure" in dashboard["details"]["error"]


def test_edge_device_thresholds_are_more_conservative():
    summary = build_runtime_health_summary(
        event_queue=[object()] * 300,
        edge_device=True,
        generated_at="2026-01-02T00:00:00+00:00",
    )

    event_queue = [check for check in summary["checks"] if check["name"] == "event_queue"][0]
    assert event_queue["status"] == "degraded"
    assert summary["resource_budgets"]["event_queue_warning_depth"] == 250


def test_runtime_health_output_has_no_private_identifiers(tmp_path):
    summary = build_runtime_health_summary(
        repository=_repository(tmp_path),
        generated_at="2026-01-02T00:00:00+00:00",
    )
    payload = json.dumps(summary, sort_keys=True)

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(payload)
