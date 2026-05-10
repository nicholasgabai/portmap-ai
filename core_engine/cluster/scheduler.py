from __future__ import annotations

from typing import Any, Iterable

from core_engine.cluster.job_queue import ClusterJob, ClusterTask, make_job_id, make_task_id
from core_engine.cluster.worker_registry import ClusterWorker, WorkerRegistry
from core_engine.modules.scan_scheduler import (
    DEFAULT_CONCURRENCY,
    DEFAULT_MAX_PORTS,
    DEFAULT_MAX_TARGETS,
    DEFAULT_RATE_PER_SECOND,
    build_scan_plan,
)


DEFAULT_TARGET_CHUNK_SIZE = 16
DEFAULT_PORT_CHUNK_SIZE = 64


def plan_distributed_scan(
    targets: str | Iterable[str],
    ports: Iterable[int],
    *,
    workers: Iterable[ClusterWorker | dict[str, Any]] | None = None,
    ip_version: str | int | None = "auto",
    timeout: float = 1.0,
    concurrency: int = DEFAULT_CONCURRENCY,
    rate_per_second: float = DEFAULT_RATE_PER_SECOND,
    max_targets: int = DEFAULT_MAX_TARGETS,
    max_ports: int = DEFAULT_MAX_PORTS,
    target_chunk_size: int = DEFAULT_TARGET_CHUNK_SIZE,
    port_chunk_size: int = DEFAULT_PORT_CHUNK_SIZE,
    aggressive: bool = False,
) -> dict[str, Any]:
    """Build a dry-run distributed scan plan without executing probes."""
    if target_chunk_size <= 0:
        raise ValueError("target_chunk_size must be greater than 0")
    if port_chunk_size <= 0:
        raise ValueError("port_chunk_size must be greater than 0")
    scan_plan = build_scan_plan(
        targets,
        ports,
        ip_version=ip_version,
        timeout=timeout,
        concurrency=concurrency,
        rate_per_second=rate_per_second,
        max_targets=max_targets,
        max_ports=max_ports,
        aggressive=aggressive,
    )
    registry = WorkerRegistry(workers or [_default_local_worker()])
    available = registry.available_workers(scan_type="tcp_connect")
    warnings = list(scan_plan.warnings)
    if not available:
        warnings.append("no available workers; tasks remain queued until a worker is online")

    job = _build_job(scan_plan.to_dict(), target_chunk_size=target_chunk_size, port_chunk_size=port_chunk_size)
    assignments = _plan_assignments(job, available)
    worker_rows = [worker.to_dict() for worker in available] if available else registry.list_workers()
    return {
        "ok": True,
        "mode": "dry_run",
        "job": job.to_dict(),
        "workers": worker_rows,
        "assignments": assignments,
        "summary": {
            "worker_count": len(worker_rows),
            "available_workers": len(available),
            "task_count": len(job.tasks),
            "assigned_tasks": len(assignments),
            "queued_tasks": job.queued_tasks,
            "total_probes": job.total_probes,
            "target_count": len(scan_plan.targets),
            "port_count": len(scan_plan.ports),
            "timeout": scan_plan.timeout,
            "concurrency": scan_plan.concurrency,
            "rate_per_second": scan_plan.rate_per_second,
        },
        "warnings": warnings,
        "raw_payload_stored": False,
        "automatic_changes": False,
    }


def _build_job(scan_plan: dict[str, Any], *, target_chunk_size: int, port_chunk_size: int) -> ClusterJob:
    targets = list(scan_plan.get("targets") or [])
    ports = [int(port) for port in scan_plan.get("ports") or []]
    job_id = make_job_id("tcp_connect", targets, ports)
    tasks: list[ClusterTask] = []
    index = 0
    for target_chunk in _chunks(targets, target_chunk_size):
        for port_chunk in _chunks(ports, port_chunk_size):
            tasks.append(
                ClusterTask(
                    task_id=make_task_id(job_id, index, target_chunk, port_chunk),
                    job_id=job_id,
                    targets=target_chunk,
                    ports=port_chunk,
                    scan_type="tcp_connect",
                )
            )
            index += 1
    return ClusterJob(
        job_id=job_id,
        scan_type="tcp_connect",
        tasks=tasks,
        warnings=list(scan_plan.get("warnings") or []),
        metadata={
            "scan_plan": {
                "timeout": scan_plan.get("timeout"),
                "concurrency": scan_plan.get("concurrency"),
                "rate_per_second": scan_plan.get("rate_per_second"),
                "aggressive": scan_plan.get("aggressive", False),
            }
        },
    )


def _plan_assignments(job: ClusterJob, workers: list[ClusterWorker]) -> list[dict[str, Any]]:
    assignments: list[dict[str, Any]] = []
    if not workers:
        return assignments
    worker_slots = []
    for worker in workers:
        worker_slots.extend([worker.node_id] * max(worker.available_capacity, 1))
    queued_tasks = [task for task in job.tasks if task.status == "queued"]
    for index, task in enumerate(queued_tasks):
        worker_id = worker_slots[index % len(worker_slots)]
        task.status = "planned"
        task.assigned_worker = worker_id
        assignments.append(
            {
                "worker_id": worker_id,
                "task_id": task.task_id,
                "target_count": len(task.targets),
                "port_count": len(task.ports),
                "total_probes": task.total_probes,
            }
        )
    job.refresh_status()
    return assignments


def _chunks(items: list[Any], size: int) -> list[list[Any]]:
    return [items[index : index + size] for index in range(0, len(items), size)]


def _default_local_worker() -> ClusterWorker:
    return ClusterWorker(
        node_id="local-worker",
        address="127.0.0.1",
        status="available",
        capabilities={"scan_types": ["tcp_connect"], "source": "local_default"},
        max_concurrency=1,
    )


__all__ = [
    "DEFAULT_PORT_CHUNK_SIZE",
    "DEFAULT_TARGET_CHUNK_SIZE",
    "plan_distributed_scan",
]
