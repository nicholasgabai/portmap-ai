from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Iterable


AVAILABLE_STATUSES = {"available", "online", "ready", "registered", "idle"}
BUSY_STATUSES = {"busy", "running", "scanning"}
OFFLINE_STATUSES = {"offline", "stale", "unreachable", "disabled"}


@dataclass
class ClusterWorker:
    node_id: str
    address: str = ""
    status: str = "available"
    role: str = "worker"
    last_seen: float = 0.0
    capabilities: dict[str, Any] = field(default_factory=dict)
    max_concurrency: int = 1
    active_jobs: int = 0

    @property
    def health(self) -> str:
        normalized = self.status.lower()
        if normalized in OFFLINE_STATUSES:
            return "offline"
        if normalized in BUSY_STATUSES or self.active_jobs >= self.max_concurrency:
            return "busy"
        if normalized in AVAILABLE_STATUSES:
            return "available"
        return "unknown"

    @property
    def available_capacity(self) -> int:
        return max(int(self.max_concurrency) - int(self.active_jobs), 0)

    def supports(self, scan_type: str) -> bool:
        supported = self.capabilities.get("scan_types")
        if supported is None:
            return True
        if isinstance(supported, str):
            supported = [item.strip() for item in supported.split(",")]
        if not isinstance(supported, list):
            return True
        return scan_type in {str(item).lower() for item in supported}

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "address": self.address,
            "status": self.status,
            "health": self.health,
            "role": self.role,
            "last_seen": self.last_seen,
            "capabilities": dict(self.capabilities),
            "max_concurrency": self.max_concurrency,
            "active_jobs": self.active_jobs,
            "available_capacity": self.available_capacity,
        }


class WorkerRegistry:
    """In-memory view of cluster workers and their scheduling health."""

    def __init__(self, workers: Iterable[ClusterWorker | dict[str, Any]] | None = None, *, stale_after_seconds: float = 120.0):
        self.stale_after_seconds = float(stale_after_seconds)
        self._workers: dict[str, ClusterWorker] = {}
        for worker in workers or []:
            self.register(worker)

    def register(self, worker: ClusterWorker | dict[str, Any]) -> ClusterWorker:
        normalized = worker if isinstance(worker, ClusterWorker) else worker_from_dict(worker)
        if not normalized.node_id:
            raise ValueError("worker node_id is required")
        self._workers[normalized.node_id] = normalized
        return normalized

    def heartbeat(self, node_id: str, *, status: str = "available", metadata: dict[str, Any] | None = None) -> ClusterWorker:
        worker = self._workers.get(node_id)
        if worker is None:
            worker = ClusterWorker(node_id=node_id)
            self._workers[node_id] = worker
        worker.status = status
        worker.last_seen = time.time()
        if metadata:
            worker.capabilities.update(metadata.get("capabilities") or {})
            if metadata.get("max_concurrency") is not None:
                worker.max_concurrency = _positive_int(metadata.get("max_concurrency"), default=worker.max_concurrency)
        return worker

    def mark_stale(self, *, now: float | None = None) -> int:
        if self.stale_after_seconds <= 0:
            return 0
        current = now if now is not None else time.time()
        changed = 0
        for worker in self._workers.values():
            if worker.last_seen and current - worker.last_seen > self.stale_after_seconds and worker.status.lower() not in OFFLINE_STATUSES:
                worker.status = "stale"
                changed += 1
        return changed

    def list_workers(self, *, include_offline: bool = True) -> list[dict[str, Any]]:
        self.mark_stale()
        workers = list(self._workers.values())
        if not include_offline:
            workers = [worker for worker in workers if worker.health != "offline"]
        return [worker.to_dict() for worker in sorted(workers, key=lambda item: item.node_id)]

    def available_workers(self, *, scan_type: str = "tcp_connect") -> list[ClusterWorker]:
        self.mark_stale()
        workers = [
            worker
            for worker in self._workers.values()
            if worker.health == "available" and worker.available_capacity > 0 and worker.supports(scan_type)
        ]
        return sorted(workers, key=lambda item: (-item.available_capacity, item.node_id))


def worker_from_dict(payload: dict[str, Any]) -> ClusterWorker:
    meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
    capabilities = payload.get("capabilities") if isinstance(payload.get("capabilities"), dict) else {}
    if isinstance(meta.get("capabilities"), dict):
        capabilities = {**capabilities, **meta["capabilities"]}
    max_concurrency = payload.get("max_concurrency", meta.get("max_concurrency", capabilities.get("max_concurrency", 1)))
    return ClusterWorker(
        node_id=str(payload.get("node_id") or payload.get("id") or ""),
        address=str(payload.get("address") or ""),
        status=str(payload.get("status") or "available"),
        role=str(payload.get("role") or "worker"),
        last_seen=float(payload.get("last_seen") or 0.0),
        capabilities=dict(capabilities),
        max_concurrency=_positive_int(max_concurrency, default=1),
        active_jobs=max(_positive_int(payload.get("active_jobs"), default=0), 0),
    )


def workers_from_orchestrator_nodes(nodes: Iterable[dict[str, Any]]) -> list[ClusterWorker]:
    workers = []
    for node in nodes:
        if str(node.get("role") or "").lower() != "worker":
            continue
        workers.append(worker_from_dict(node))
    return workers


def _positive_int(value: Any, *, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default


__all__ = [
    "AVAILABLE_STATUSES",
    "BUSY_STATUSES",
    "OFFLINE_STATUSES",
    "ClusterWorker",
    "WorkerRegistry",
    "worker_from_dict",
    "workers_from_orchestrator_nodes",
]
