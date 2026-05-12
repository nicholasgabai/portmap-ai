from __future__ import annotations

import threading
import time
from typing import Any, Callable

from core_engine.runtime.jobs import RuntimeJob, RuntimeJobError
from core_engine.runtime.runtime_state import RuntimeState


JobHandler = Callable[[RuntimeJob], Any]


class LocalRuntimeScheduler:
    """Local-only lightweight scheduler for operator-controlled runtime jobs."""

    def __init__(
        self,
        *,
        poll_interval: float = 1.0,
        time_fn: Callable[[], float] | None = None,
        sleep_fn: Callable[[float], None] | None = None,
    ) -> None:
        if poll_interval <= 0:
            raise ValueError("poll_interval must be greater than zero")
        self.poll_interval = poll_interval
        self._time = time_fn or time.time
        self._sleep = sleep_fn or time.sleep
        self._jobs: dict[str, RuntimeJob] = {}
        self._handlers: dict[str, JobHandler] = {}
        self._state = RuntimeState()
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def local_only(self) -> bool:
        return True

    @property
    def state(self) -> RuntimeState:
        return self._state

    def add_job(self, job: RuntimeJob, handler: JobHandler | None = None) -> RuntimeJob:
        if not isinstance(job, RuntimeJob):
            raise RuntimeJobError("add_job requires a RuntimeJob")
        if handler is not None and not callable(handler):
            raise RuntimeJobError("handler must be callable")
        with self._lock:
            if job.job_id in self._jobs:
                raise RuntimeJobError(f"job already exists: {job.job_id}")
            self._jobs[job.job_id] = job
            self._handlers[job.job_id] = handler or _default_handler
        return job

    def remove_job(self, job_id: str) -> bool:
        with self._lock:
            existed = self._jobs.pop(job_id, None) is not None
            self._handlers.pop(job_id, None)
            return existed

    def enable_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            job.mark_enabled(self._time())
            return True

    def disable_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return False
            job.mark_disabled()
            return True

    def list_jobs(self) -> list[RuntimeJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda item: item.job_id)

    def run_due_jobs_once(self) -> list[dict[str, Any]]:
        now = self._time()
        with self._lock:
            due = [(job, self._handlers[job.job_id]) for job in self._jobs.values() if job.is_due(now)]
        results: list[dict[str, Any]] = []
        for job, handler in sorted(due, key=lambda item: item[0].job_id):
            results.append(self._run_job(job, handler))
        return results

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._state.mark_started(self._time())
            self._thread = threading.Thread(target=self._run_loop, name="portmap-local-runtime-scheduler", daemon=True)
            self._thread.start()

    def stop(self, *, timeout: float = 2.0) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=timeout)
        with self._lock:
            self._state.mark_stopped(self._time())
            self._thread = None

    def status(self) -> dict[str, Any]:
        return self._state.to_dict(now=self._time())

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            self.run_due_jobs_once()
            self._sleep(self.poll_interval)

    def _run_job(self, job: RuntimeJob, handler: JobHandler) -> dict[str, Any]:
        now = self._time()
        with self._lock:
            job.status = "running"
            job.last_run_at = now
            job.run_count += 1
        try:
            output = handler(job)
        except Exception as exc:  # Job failures must not crash the scheduler.
            with self._lock:
                job.status = "failed"
                job.last_error = str(exc)
                job.failure_count += 1
                job.schedule_next(self._time())
                self._state.record_job_failure()
            return {"job_id": job.job_id, "name": job.name, "ok": False, "error": str(exc)}
        with self._lock:
            job.status = "success"
            job.last_error = None
            job.schedule_next(self._time())
            self._state.record_job_success()
        return {"job_id": job.job_id, "name": job.name, "ok": True, "result": output}


def _default_handler(job: RuntimeJob) -> dict[str, Any]:
    return {
        "job_id": job.job_id,
        "name": job.name,
        "local_only": True,
        "automatic_changes": False,
    }
