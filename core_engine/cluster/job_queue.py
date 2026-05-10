from __future__ import annotations

import time
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable


JOB_STATUSES = {"queued", "planned", "running", "completed", "partial", "failed", "cancelled"}
TASK_STATUSES = {"queued", "planned", "assigned", "running", "completed", "failed", "retry"}


@dataclass
class ClusterTask:
    task_id: str
    job_id: str
    targets: list[dict[str, Any]]
    ports: list[int]
    scan_type: str = "tcp_connect"
    status: str = "queued"
    assigned_worker: str | None = None
    attempts: int = 0
    max_retries: int = 1
    result: dict[str, Any] | None = None
    error: str | None = None

    @property
    def total_probes(self) -> int:
        return len(self.targets) * len(self.ports)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "job_id": self.job_id,
            "targets": list(self.targets),
            "ports": list(self.ports),
            "scan_type": self.scan_type,
            "status": self.status,
            "assigned_worker": self.assigned_worker,
            "attempts": self.attempts,
            "max_retries": self.max_retries,
            "total_probes": self.total_probes,
            "result": self.result,
            "error": self.error,
        }


@dataclass
class ClusterJob:
    job_id: str
    scan_type: str = "tcp_connect"
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    tasks: list[ClusterTask] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_probes(self) -> int:
        return sum(task.total_probes for task in self.tasks)

    @property
    def completed_tasks(self) -> int:
        return sum(1 for task in self.tasks if task.status == "completed")

    @property
    def failed_tasks(self) -> int:
        return sum(1 for task in self.tasks if task.status == "failed")

    @property
    def queued_tasks(self) -> int:
        return sum(1 for task in self.tasks if task.status in {"queued", "retry"})

    def refresh_status(self) -> str:
        if not self.tasks:
            self.status = "queued"
        elif self.completed_tasks == len(self.tasks):
            self.status = "completed"
        elif self.failed_tasks and self.completed_tasks:
            self.status = "partial"
        elif self.failed_tasks == len(self.tasks):
            self.status = "failed"
        elif all(task.status == "planned" for task in self.tasks):
            self.status = "planned"
        elif any(task.status in {"assigned", "running"} for task in self.tasks):
            self.status = "running"
        else:
            self.status = "queued"
        return self.status

    def to_dict(self) -> dict[str, Any]:
        self.refresh_status()
        return {
            "job_id": self.job_id,
            "scan_type": self.scan_type,
            "status": self.status,
            "created_at": self.created_at,
            "task_count": len(self.tasks),
            "completed_tasks": self.completed_tasks,
            "failed_tasks": self.failed_tasks,
            "queued_tasks": self.queued_tasks,
            "total_probes": self.total_probes,
            "warnings": list(self.warnings),
            "metadata": dict(self.metadata),
            "tasks": [task.to_dict() for task in self.tasks],
            "raw_payload_stored": False,
            "automatic_changes": False,
        }


class JobQueue:
    """Small in-memory queue for distributed scan jobs and task outcomes."""

    def __init__(self, jobs: Iterable[ClusterJob] | None = None):
        self._jobs: dict[str, ClusterJob] = {}
        for job in jobs or []:
            self.submit(job)

    def submit(self, job: ClusterJob) -> ClusterJob:
        if job.job_id in self._jobs:
            raise ValueError(f"job already exists: {job.job_id}")
        self._jobs[job.job_id] = job
        return job

    def get(self, job_id: str) -> ClusterJob | None:
        return self._jobs.get(job_id)

    def list_jobs(self) -> list[dict[str, Any]]:
        return [job.to_dict() for job in sorted(self._jobs.values(), key=lambda item: item.created_at)]

    def assign_next(self, worker_id: str, *, scan_type: str = "tcp_connect") -> ClusterTask | None:
        for job in sorted(self._jobs.values(), key=lambda item: item.created_at):
            if job.scan_type != scan_type:
                continue
            for task in job.tasks:
                if task.status not in {"queued", "retry"}:
                    continue
                task.status = "assigned"
                task.assigned_worker = worker_id
                task.attempts += 1
                job.refresh_status()
                return task
        return None

    def record_result(
        self,
        task_id: str,
        *,
        success: bool,
        result: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> ClusterTask:
        task = self._find_task(task_id)
        task.result = result or {}
        task.error = error
        if success:
            task.status = "completed"
        elif task.attempts <= task.max_retries:
            task.status = "retry"
        else:
            task.status = "failed"
        job = self._jobs[task.job_id]
        job.refresh_status()
        return task

    def aggregate_results(self, job_id: str) -> dict[str, Any]:
        job = self._require_job(job_id)
        rows = []
        errors = []
        for task in job.tasks:
            if isinstance(task.result, dict) and isinstance(task.result.get("rows"), list):
                rows.extend(row for row in task.result["rows"] if isinstance(row, dict))
            elif isinstance(task.result, dict) and task.result:
                rows.append(task.result)
            if task.error:
                errors.append({"task_id": task.task_id, "worker": task.assigned_worker, "error": task.error})
        return {
            "ok": job.failed_tasks == 0,
            "job_id": job.job_id,
            "status": job.refresh_status(),
            "result_count": len(rows),
            "results": rows,
            "errors": errors,
            "raw_payload_stored": False,
            "automatic_changes": False,
        }

    def _require_job(self, job_id: str) -> ClusterJob:
        job = self._jobs.get(job_id)
        if job is None:
            raise KeyError(f"unknown cluster job: {job_id}")
        return job

    def _find_task(self, task_id: str) -> ClusterTask:
        for job in self._jobs.values():
            for task in job.tasks:
                if task.task_id == task_id:
                    return task
        raise KeyError(f"unknown cluster task: {task_id}")


def make_job_id(scan_type: str, targets: Iterable[dict[str, Any]], ports: Iterable[int]) -> str:
    material = repr((scan_type, list(targets), list(ports), round(time.time(), 3))).encode("utf-8")
    return "job-" + sha256(material).hexdigest()[:16]


def make_task_id(job_id: str, index: int, targets: Iterable[dict[str, Any]], ports: Iterable[int]) -> str:
    material = repr((job_id, index, list(targets), list(ports))).encode("utf-8")
    return "task-" + sha256(material).hexdigest()[:16]


__all__ = [
    "JOB_STATUSES",
    "TASK_STATUSES",
    "ClusterJob",
    "ClusterTask",
    "JobQueue",
    "make_job_id",
    "make_task_id",
]
