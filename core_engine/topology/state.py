from __future__ import annotations

from typing import Any, Iterable

from core_engine.storage.repositories import LocalStorageRepository
from core_engine.topology.snapshots import SAFETY_FLAGS, summarize_topology_snapshot, topology_snapshot_to_storage_record


def build_topology_state(snapshots: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = sorted(_rows(snapshots), key=lambda item: str(item.get("observed_at") or ""))
    summaries = [summarize_topology_snapshot(snapshot) for snapshot in rows]
    current = summaries[-1] if summaries else None
    return {
        "status": "ok",
        "snapshot_count": len(rows),
        "current_snapshot_id": current.get("snapshot_id") if current else None,
        "current": current,
        "history": summaries,
        "history_summary": summarize_topology_history(rows),
        **SAFETY_FLAGS,
    }


def summarize_topology_history(snapshots: Iterable[dict[str, Any]]) -> dict[str, Any]:
    summaries = [summarize_topology_snapshot(snapshot) for snapshot in _rows(snapshots)]
    if not summaries:
        return {
            "snapshot_count": 0,
            "first_observed_at": None,
            "last_observed_at": None,
            "max_node_count": 0,
            "max_edge_count": 0,
            "max_service_count": 0,
            "total_finding_count": 0,
            **SAFETY_FLAGS,
        }
    ordered = sorted(summaries, key=lambda item: item["observed_at"])
    return {
        "snapshot_count": len(ordered),
        "first_observed_at": ordered[0]["observed_at"],
        "last_observed_at": ordered[-1]["observed_at"],
        "max_node_count": max(item["node_count"] for item in ordered),
        "max_edge_count": max(item["edge_count"] for item in ordered),
        "max_service_count": max(item["service_count"] for item in ordered),
        "total_finding_count": sum(item["finding_count"] for item in ordered),
        **SAFETY_FLAGS,
    }


def persist_topology_snapshot(repository: LocalStorageRepository, snapshot: dict[str, Any]) -> int:
    record = topology_snapshot_to_storage_record(snapshot)
    return repository.insert_snapshot(
        {
            "snapshot_id": record["snapshot_id"],
            "label": record["label"],
            "observed_at": record["observed_at"],
            "snapshot_type": record["snapshot_type"],
            "summary": record["summary"],
            "topology": snapshot.get("topology"),
            "findings": snapshot.get("findings", []),
            "raw_payload_stored": False,
            "automatic_changes": False,
            "administrator_controlled": True,
        }
    )


def list_persisted_topology_snapshots(repository: LocalStorageRepository) -> list[dict[str, Any]]:
    return [
        snapshot
        for snapshot in repository.list_snapshots()
        if snapshot.get("snapshot_type") == "topology_state"
    ]


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]
