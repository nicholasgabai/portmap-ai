from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable, Protocol

from core_engine.policy.review_queue import ReviewQueue
from core_engine.policy.review_store import PersistentReviewStore
from core_engine.runtime.runtime_state import RuntimeState
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.topology.graph import build_topology_graph, summarize_topology
from core_engine.topology.state import build_topology_state


GeneratedAt = Callable[[], str]


class DashboardProvider(Protocol):
    """Minimal provider interface used by the local web dashboard."""

    def get(self, path: str) -> dict[str, Any] | tuple[int, dict[str, Any]]:
        ...


class StaticDashboardProvider:
    """Read-only provider for API-compatible dictionaries."""

    def __init__(self, data: dict[str, Any] | None = None, *, generated_at: GeneratedAt | None = None) -> None:
        self.data = dict(data or {})
        self.generated_at = generated_at or _now

    @property
    def local_only(self) -> bool:
        return True

    def get(self, path: str) -> tuple[int, dict[str, Any]]:
        key = _path_key(path)
        return 200, _response_from_value(self.data.get(key), generated_at=self.generated_at())


class StorageDashboardProvider:
    """Build dashboard API payloads from existing local storage repositories."""

    def __init__(
        self,
        repository: LocalStorageRepository,
        *,
        runtime_state: RuntimeState | dict[str, Any] | None = None,
        review_store: PersistentReviewStore | None = None,
        diagnostics: list[dict[str, Any]] | None = None,
        nodes: list[dict[str, Any]] | None = None,
        generated_at: GeneratedAt | None = None,
        now_seconds: Callable[[], float] | None = None,
    ) -> None:
        if not isinstance(repository, LocalStorageRepository):
            raise TypeError("StorageDashboardProvider requires a LocalStorageRepository")
        self.repository = repository
        self.runtime_state = runtime_state
        self.review_store = review_store
        self.diagnostics = list(diagnostics or [])
        self.nodes = list(nodes or [])
        self.generated_at = generated_at or _now
        self.now_seconds = now_seconds or (lambda: 0.0)

    @property
    def local_only(self) -> bool:
        return True

    def get(self, path: str) -> tuple[int, dict[str, Any]]:
        key = _path_key(path)
        generated_at = self.generated_at()
        if key == "health":
            return 200, runtime_state_response(self.runtime_state, generated_at=generated_at, now_seconds=self.now_seconds)
        if key == "events":
            return 200, collection_response(self.repository.list_events(), generated_at=generated_at)
        if key == "assets":
            return 200, collection_response(self.repository.list_assets(), generated_at=generated_at)
        if key == "snapshots":
            return 200, snapshot_summary_response(self.repository.list_snapshots(), generated_at=generated_at)
        if key == "nodes":
            return 200, collection_response(self.nodes, generated_at=generated_at)
        if key == "topology":
            return 200, topology_summary_response(
                snapshots=self.repository.list_snapshots(),
                topology_edges=self.repository.list_topology_edges(),
                generated_at=generated_at,
            )
        if key == "operator_reviews":
            return 200, review_summary_response(self.review_store, generated_at=generated_at)
        if key == "diagnostics":
            return 200, diagnostic_summary_response(self.diagnostics, generated_at=generated_at)
        return 404, error_response("not_found", generated_at=generated_at)


def collection_response(items: list[dict[str, Any]] | None = None, *, generated_at: str | None = None) -> dict[str, Any]:
    rows = _rows(items)
    return {
        "status": "ok",
        "count": len(rows),
        "items": rows,
        "generated_at": generated_at or _now(),
        **_SAFETY_FLAGS,
    }


def runtime_state_response(
    state: RuntimeState | dict[str, Any] | None,
    *,
    generated_at: str | None = None,
    now_seconds: Callable[[], float] | None = None,
) -> dict[str, Any]:
    if isinstance(state, RuntimeState):
        payload = state.to_dict(now=(now_seconds or (lambda: 0.0))())
    elif isinstance(state, dict):
        payload = dict(state)
    else:
        payload = {"scheduler_status": "not_configured", "executed_job_count": 0, "failed_job_count": 0}
    return {
        "status": "ok",
        "generated_at": generated_at or _now(),
        "runtime": payload,
        **_SAFETY_FLAGS,
    }


def snapshot_summary_response(snapshots: list[dict[str, Any]] | None = None, *, generated_at: str | None = None) -> dict[str, Any]:
    rows = _rows(snapshots)
    state = build_topology_state([row for row in rows if row.get("snapshot_type") == "topology_state"])
    return {
        **collection_response(rows, generated_at=generated_at),
        "summary": state["history_summary"],
        "current_snapshot_id": state["current_snapshot_id"],
    }


def topology_summary_response(
    *,
    snapshots: list[dict[str, Any]] | None = None,
    topology_edges: list[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    asset_rows: list[dict[str, Any]] = []
    edge_rows = _rows(topology_edges)
    for snapshot in _rows(snapshots):
        topology = snapshot.get("topology") if isinstance(snapshot.get("topology"), dict) else {}
        asset_rows.extend(_rows(topology.get("nodes")))
        edge_rows.extend(_rows(topology.get("edges")))
    graph = build_topology_graph(
        assets=asset_rows,
        topology_edges=edge_rows,
        generated_at=generated_at,
    )
    return {
        **collection_response(graph["edges"], generated_at=generated_at),
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "summary": summarize_topology(graph),
    }


def review_summary_response(review_store: PersistentReviewStore | ReviewQueue | None, *, generated_at: str | None = None) -> dict[str, Any]:
    if review_store is None:
        reviews: list[dict[str, Any]] = []
        summary = ReviewQueue().summarize_reviews()
    elif isinstance(review_store, PersistentReviewStore):
        reviews = [review.to_dict() for review in review_store.list_reviews()]
        summary = review_store.summarize_reviews()
    elif isinstance(review_store, ReviewQueue):
        reviews = [review.to_dict() for review in review_store.list_reviews()]
        summary = review_store.summarize_reviews()
    else:
        raise TypeError("review_store must be PersistentReviewStore, ReviewQueue, or None")
    return {
        **collection_response(reviews, generated_at=generated_at),
        "summary": summary,
    }


def diagnostic_summary_response(diagnostics: list[dict[str, Any]] | None = None, *, generated_at: str | None = None) -> dict[str, Any]:
    rows = _rows(diagnostics)
    by_status: dict[str, int] = {}
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        diagnostic_type = str(row.get("diagnostic_type") or row.get("type") or "diagnostic")
        severity = str(row.get("severity") or "info")
        by_status[status] = by_status.get(status, 0) + 1
        by_type[diagnostic_type] = by_type.get(diagnostic_type, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    return {
        **collection_response(rows, generated_at=generated_at),
        "summary": {
            "diagnostic_count": len(rows),
            "by_status": dict(sorted(by_status.items())),
            "by_type": dict(sorted(by_type.items())),
            "by_severity": dict(sorted(by_severity.items())),
            **_SAFETY_FLAGS,
        },
    }


def error_response(error: str, *, generated_at: str | None = None) -> dict[str, Any]:
    return {
        "status": "error",
        "error": error,
        "generated_at": generated_at or _now(),
        **_SAFETY_FLAGS,
    }


def _response_from_value(value: Any, *, generated_at: str) -> dict[str, Any]:
    if isinstance(value, dict) and {"status", "count", "items"} & set(value):
        return {**value, "generated_at": value.get("generated_at") or generated_at, **_SAFETY_FLAGS}
    if isinstance(value, list):
        return collection_response(value, generated_at=generated_at)
    if isinstance(value, dict):
        return {"status": value.get("status", "ok"), "generated_at": generated_at, **value, **_SAFETY_FLAGS}
    return collection_response([], generated_at=generated_at)


def _path_key(path: str) -> str:
    return str(path or "").strip("/") or "health"


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _now() -> str:
    return datetime.now(UTC).isoformat()


_SAFETY_FLAGS = {
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
    "local_only": True,
    "read_only": True,
}
