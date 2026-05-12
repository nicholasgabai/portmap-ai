import threading

import pytest

from core_engine.runtime import LocalRuntimeScheduler, RuntimeJobError, create_runtime_job


class Clock:
    def __init__(self, value=1000.0):
        self.value = value

    def now(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


def test_job_creation_and_next_run_calculation():
    job = create_runtime_job("health_check", interval_seconds=30, job_id="job-health", start_at=10.0)

    assert job.job_id == "job-health"
    assert job.name == "health_check"
    assert job.enabled is True
    assert job.next_run_at == 10.0
    assert job.is_due(10.0) is True
    job.schedule_next(10.0)
    assert job.next_run_at == 40.0
    assert job.local_only is True


def test_invalid_job_name_is_rejected():
    with pytest.raises(RuntimeJobError):
        create_runtime_job("external_sync", interval_seconds=30)


def test_add_remove_and_list_jobs():
    scheduler = LocalRuntimeScheduler()
    first = create_runtime_job("health_check", interval_seconds=30, job_id="job-a")
    second = create_runtime_job("snapshot_refresh", interval_seconds=60, job_id="job-b")

    scheduler.add_job(second)
    scheduler.add_job(first)

    assert [job.job_id for job in scheduler.list_jobs()] == ["job-a", "job-b"]
    assert scheduler.remove_job("job-a") is True
    assert scheduler.remove_job("missing") is False
    assert [job.job_id for job in scheduler.list_jobs()] == ["job-b"]


def test_enable_disable_job():
    clock = Clock()
    scheduler = LocalRuntimeScheduler(time_fn=clock.now)
    job = create_runtime_job("event_flush", interval_seconds=45, job_id="job-flush")
    scheduler.add_job(job)

    assert scheduler.disable_job("job-flush") is True
    assert job.enabled is False
    assert job.status == "disabled"
    assert scheduler.enable_job("job-flush") is True
    assert job.enabled is True
    assert job.status == "pending"
    assert job.next_run_at == 0.0
    assert scheduler.enable_job("missing") is False


def test_run_due_jobs_once_updates_counts_and_next_run():
    clock = Clock()
    calls = []
    scheduler = LocalRuntimeScheduler(time_fn=clock.now)
    job = create_runtime_job("policy_review_refresh", interval_seconds=20, job_id="job-policy", start_at=clock.now())

    scheduler.add_job(job, handler=lambda item: calls.append(item.job_id) or {"ok": True})
    results = scheduler.run_due_jobs_once()

    assert results == [{"job_id": "job-policy", "name": "policy_review_refresh", "ok": True, "result": {"ok": True}}]
    assert calls == ["job-policy"]
    assert job.status == "success"
    assert job.run_count == 1
    assert job.failure_count == 0
    assert job.next_run_at == 1020.0
    assert scheduler.status()["executed_job_count"] == 1
    assert scheduler.run_due_jobs_once() == []


def test_failed_job_isolation_allows_other_jobs_to_run():
    clock = Clock()
    successful = []
    scheduler = LocalRuntimeScheduler(time_fn=clock.now)
    failing_job = create_runtime_job("health_check", interval_seconds=10, job_id="job-fail", start_at=clock.now())
    ok_job = create_runtime_job("snapshot_refresh", interval_seconds=10, job_id="job-ok", start_at=clock.now())

    def fail(_job):
        raise RuntimeError("sample failure")

    scheduler.add_job(failing_job, handler=fail)
    scheduler.add_job(ok_job, handler=lambda job: successful.append(job.job_id))
    results = scheduler.run_due_jobs_once()

    assert [result["ok"] for result in results] == [False, True]
    assert "sample failure" in results[0]["error"]
    assert successful == ["job-ok"]
    assert failing_job.status == "failed"
    assert failing_job.failure_count == 1
    assert scheduler.status()["executed_job_count"] == 2
    assert scheduler.status()["failed_job_count"] == 1


def test_runtime_state_start_stop_and_uptime():
    clock = Clock()
    scheduler = LocalRuntimeScheduler(time_fn=clock.now, sleep_fn=lambda _seconds: None)

    scheduler.state.mark_started(clock.now())
    clock.advance(5)
    assert scheduler.status()["scheduler_status"] == "running"
    assert scheduler.status()["uptime_seconds"] == 5.0
    scheduler.state.record_job_success()
    scheduler.state.record_job_failure()
    assert scheduler.status()["executed_job_count"] == 2
    assert scheduler.status()["failed_job_count"] == 1
    scheduler.state.mark_stopped(clock.now())
    clock.advance(5)
    assert scheduler.status()["scheduler_status"] == "stopped"
    assert scheduler.status()["uptime_seconds"] == 5.0


def test_clean_start_stop_behavior():
    ran = threading.Event()

    def sleep_once(_seconds):
        ran.set()

    scheduler = LocalRuntimeScheduler(poll_interval=0.01, sleep_fn=sleep_once)
    scheduler.start()
    assert scheduler.status()["scheduler_status"] == "running"
    assert ran.wait(timeout=1.0)
    scheduler.stop()
    assert scheduler.status()["scheduler_status"] == "stopped"
    assert scheduler.state.stop_time is not None
    assert scheduler.local_only is True


def test_disabled_job_is_not_run():
    clock = Clock()
    scheduler = LocalRuntimeScheduler(time_fn=clock.now)
    job = create_runtime_job("health_check", interval_seconds=30, job_id="job-disabled", enabled=False)
    scheduler.add_job(job, handler=lambda _job: pytest.fail("disabled job should not run"))

    assert scheduler.run_due_jobs_once() == []
    assert job.run_count == 0
