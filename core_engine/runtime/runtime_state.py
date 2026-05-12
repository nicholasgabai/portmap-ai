from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class RuntimeState:
    scheduler_status: str = "stopped"
    start_time: float | None = None
    stop_time: float | None = None
    executed_job_count: int = 0
    failed_job_count: int = 0

    def mark_started(self, now: float) -> None:
        self.scheduler_status = "running"
        self.start_time = now
        self.stop_time = None

    def mark_stopped(self, now: float) -> None:
        self.scheduler_status = "stopped"
        self.stop_time = now

    def record_job_success(self) -> None:
        self.executed_job_count += 1

    def record_job_failure(self) -> None:
        self.executed_job_count += 1
        self.failed_job_count += 1

    def uptime_seconds(self, now: float) -> float:
        if self.start_time is None:
            return 0.0
        end = self.stop_time if self.stop_time is not None else now
        return max(0.0, end - self.start_time)

    def to_dict(self, *, now: float) -> dict[str, float | int | str | None]:
        return {
            "scheduler_status": self.scheduler_status,
            "start_time": self.start_time,
            "stop_time": self.stop_time,
            "uptime_seconds": self.uptime_seconds(now),
            "executed_job_count": self.executed_job_count,
            "failed_job_count": self.failed_job_count,
            "local_only": True,
            "automatic_changes": False,
        }
