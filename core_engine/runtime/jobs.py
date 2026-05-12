from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


BUILT_IN_JOB_TYPES = frozenset(
    {
        "health_check",
        "snapshot_refresh",
        "event_flush",
        "policy_review_refresh",
    }
)

JOB_STATUSES = frozenset({"pending", "disabled", "running", "success", "failed"})


class RuntimeJobError(ValueError):
    """Raised when a runtime job definition is invalid."""


@dataclass(slots=True)
class RuntimeJob:
    job_id: str
    name: str
    interval_seconds: float
    enabled: bool = True
    last_run_at: float | None = None
    next_run_at: float | None = None
    status: str = "pending"
    last_error: str | None = None
    run_count: int = 0
    failure_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _validate_job(self)
        if self.next_run_at is None:
            self.next_run_at = 0.0
        if not self.enabled:
            self.status = "disabled"

    @property
    def local_only(self) -> bool:
        return True

    def is_due(self, now: float) -> bool:
        return self.enabled and (self.next_run_at is None or self.next_run_at <= now)

    def schedule_next(self, now: float) -> None:
        self.next_run_at = now + self.interval_seconds

    def mark_enabled(self, now: float) -> None:
        self.enabled = True
        self.status = "pending"
        self.last_error = None
        if self.next_run_at is None:
            self.next_run_at = now

    def mark_disabled(self) -> None:
        self.enabled = False
        self.status = "disabled"

    def to_dict(self) -> dict[str, Any]:
        return {
            "job_id": self.job_id,
            "name": self.name,
            "interval_seconds": self.interval_seconds,
            "enabled": self.enabled,
            "last_run_at": self.last_run_at,
            "next_run_at": self.next_run_at,
            "status": self.status,
            "last_error": self.last_error,
            "run_count": self.run_count,
            "failure_count": self.failure_count,
            "metadata": dict(self.metadata),
            "local_only": self.local_only,
        }


def create_runtime_job(
    name: str,
    *,
    interval_seconds: float,
    job_id: str | None = None,
    enabled: bool = True,
    start_at: float | None = None,
    metadata: dict[str, Any] | None = None,
) -> RuntimeJob:
    """Create a validated built-in local runtime job."""
    return RuntimeJob(
        job_id=job_id or f"job-{uuid4().hex}",
        name=name,
        interval_seconds=interval_seconds,
        enabled=enabled,
        next_run_at=start_at,
        metadata=metadata or {},
    )


def _validate_job(job: RuntimeJob) -> None:
    if not isinstance(job.job_id, str) or not job.job_id.strip():
        raise RuntimeJobError("job_id must be a non-empty string")
    if job.name not in BUILT_IN_JOB_TYPES:
        raise RuntimeJobError(f"unsupported job name: {job.name}")
    if not isinstance(job.interval_seconds, (int, float)) or job.interval_seconds <= 0:
        raise RuntimeJobError("interval_seconds must be greater than zero")
    if not isinstance(job.enabled, bool):
        raise RuntimeJobError("enabled must be boolean")
    if job.status not in JOB_STATUSES:
        raise RuntimeJobError(f"unsupported job status: {job.status}")
    if not isinstance(job.run_count, int) or job.run_count < 0:
        raise RuntimeJobError("run_count must be a non-negative integer")
    if not isinstance(job.failure_count, int) or job.failure_count < 0:
        raise RuntimeJobError("failure_count must be a non-negative integer")
    if not isinstance(job.metadata, dict):
        raise RuntimeJobError("metadata must be an object")
