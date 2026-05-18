from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from core_engine.topology.snapshots import SAFETY_FLAGS, validate_topology_snapshot
from core_engine.topology.state import summarize_topology_history


def export_topology_snapshot(snapshot: dict[str, Any]) -> str:
    validation = validate_topology_snapshot(snapshot)
    if not validation["ok"]:
        raise ValueError("; ".join(validation["errors"]))
    return json.dumps(snapshot, sort_keys=True, indent=2)


def import_topology_snapshot(payload: str | bytes | dict[str, Any]) -> dict[str, Any]:
    if isinstance(payload, dict):
        snapshot = dict(payload)
    else:
        snapshot = json.loads(payload)
    validation = validate_topology_snapshot(snapshot)
    if not validation["ok"]:
        raise ValueError("; ".join(validation["errors"]))
    return snapshot


def write_topology_snapshot(path: str | Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    text = export_topology_snapshot(snapshot)
    output_path.write_text(text, encoding="utf-8")
    return {
        "status": "written",
        "snapshot_id": snapshot.get("snapshot_id"),
        "bytes_written": len(text.encode("utf-8")),
        "path_stored": False,
        **SAFETY_FLAGS,
    }


def load_topology_snapshot(path: str | Path) -> dict[str, Any]:
    return import_topology_snapshot(Path(path).read_text(encoding="utf-8"))


def build_topology_export_bundle(
    snapshots: Iterable[dict[str, Any]],
    *,
    label: str = "topology-export",
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [import_topology_snapshot(snapshot) for snapshot in snapshots]
    manifest = {
        "bundle_type": "topology_state_export",
        "label": label,
        "generated_at": generated_at or _now(),
        "snapshot_count": len(rows),
        "snapshot_ids": [str(snapshot.get("snapshot_id")) for snapshot in rows],
        "history_summary": summarize_topology_history(rows),
        **SAFETY_FLAGS,
    }
    return {
        "manifest": {
            **manifest,
            "digest": _digest({"snapshots": rows, "manifest": {key: value for key, value in manifest.items() if key != "digest"}}),
        },
        "snapshots": rows,
        **SAFETY_FLAGS,
    }


def export_topology_bundle(bundle: dict[str, Any]) -> str:
    return json.dumps(bundle, sort_keys=True, indent=2)


def _digest(payload: dict[str, Any]) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return "sha256:" + sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
