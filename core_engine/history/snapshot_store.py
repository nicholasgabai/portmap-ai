from __future__ import annotations

from pathlib import Path
from typing import Any, Iterable

from core_engine.history.snapshots import (
    HISTORICAL_SNAPSHOT_RECORD_VERSION,
    HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    HistoricalSnapshotError,
    build_export_safe_snapshot_summary,
    build_malformed_snapshot_record,
    deserialize_historical_snapshot,
    serialize_historical_snapshot,
    validate_historical_snapshot,
)


def rotate_historical_snapshots(
    snapshots: Iterable[dict[str, Any]],
    *,
    max_snapshots: int = 10,
) -> dict[str, Any]:
    limit = max(0, int(max_snapshots))
    valid_rows = []
    malformed_rows = []
    for row in snapshots or []:
        validation = validate_historical_snapshot(row) if isinstance(row, dict) else {"valid": False, "errors": ["snapshot must be an object"]}
        if validation["valid"]:
            valid_rows.append(dict(row))
        else:
            malformed_rows.append(build_malformed_snapshot_record(raw_record=row if isinstance(row, dict) else {}, errors=validation["errors"]))
    ordered = sorted(valid_rows, key=lambda item: (str(item.get("snapshot_timestamp") or item.get("generated_at") or ""), str(item.get("snapshot_id") or "")))
    retained = ordered[-limit:] if limit else []
    dropped = ordered[: max(0, len(ordered) - len(retained))]
    return {
        "record_type": "historical_snapshot_rotation",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "max_snapshots": limit,
        "input_count": len(valid_rows) + len(malformed_rows),
        "valid_count": len(valid_rows),
        "malformed_count": len(malformed_rows),
        "retained_count": len(retained),
        "dropped_count": len(dropped),
        "retained_snapshot_ids": [str(row.get("snapshot_id")) for row in retained],
        "dropped_snapshot_ids": [str(row.get("snapshot_id")) for row in dropped],
        "retained_snapshots": retained,
        "malformed_snapshots": malformed_rows,
        "delete_performed": False,
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def build_bounded_snapshot_store(
    snapshots: Iterable[dict[str, Any]] | None = None,
    *,
    max_snapshots: int = 10,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rotation = rotate_historical_snapshots(snapshots or [], max_snapshots=max_snapshots)
    summary = summarize_snapshot_store(rotation["retained_snapshots"], generated_at=generated_at)
    return {
        "record_type": "bounded_historical_snapshot_store",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "generated_at": generated_at or summary["generated_at"],
        "max_snapshots": int(rotation["max_snapshots"]),
        "snapshots": rotation["retained_snapshots"],
        "rotation": rotation,
        "summary": summary,
        "export_summary": {
            "record_type": "historical_snapshot_store_export_summary",
            "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
            "generated_at": generated_at or summary["generated_at"],
            "snapshot_count": int(summary["snapshot_count"]),
            "snapshot_ids": list(summary["snapshot_ids"]),
            "snapshot_digests": dict(summary["snapshot_digests"]),
            "write_performed": False,
            **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
        },
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def summarize_snapshot_store(
    snapshots: Iterable[dict[str, Any]] | None = None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in snapshots or [] if isinstance(row, dict) and validate_historical_snapshot(row)["valid"]]
    rows = sorted(rows, key=lambda item: str(item.get("snapshot_id") or ""))
    return {
        "record_type": "historical_snapshot_store_summary",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "generated_at": generated_at or (str(rows[-1].get("generated_at")) if rows else ""),
        "snapshot_count": len(rows),
        "snapshot_ids": [str(row.get("snapshot_id")) for row in rows],
        "snapshot_digests": {str(row.get("snapshot_id")): str(row.get("snapshot_digest")) for row in rows},
        "source_labels": sorted({str(row.get("source_label")) for row in rows if row.get("source_label")}),
        "statuses": sorted({str((row.get("metadata_summary") or {}).get("status") or "unknown") for row in rows}),
        "export_summaries": [build_export_safe_snapshot_summary(row) for row in rows],
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def build_snapshot_store_write_plan(
    path: str | Path,
    snapshot: dict[str, Any],
    *,
    dry_run: bool = True,
) -> dict[str, Any]:
    validation = validate_historical_snapshot(snapshot)
    target = _snapshot_path(path, snapshot)
    return {
        "record_type": "historical_snapshot_write_plan",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "status": "ready" if validation["valid"] else "blocked",
        "snapshot_id": str(snapshot.get("snapshot_id") or ""),
        "target_name": target.name,
        "parent_directory_stored": False,
        "dry_run": bool(dry_run),
        "write_performed": False,
        "validation": validation,
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def write_historical_snapshot(path: str | Path, snapshot: dict[str, Any]) -> dict[str, Any]:
    validation = validate_historical_snapshot(snapshot)
    if not validation["valid"]:
        raise HistoricalSnapshotError("; ".join(validation["errors"]))
    target = _snapshot_path(path, snapshot)
    target.parent.mkdir(parents=True, exist_ok=True)
    text = serialize_historical_snapshot(snapshot)
    target.write_text(text + "\n", encoding="utf-8")
    return {
        "record_type": "historical_snapshot_write_result",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "status": "written",
        "snapshot_id": str(snapshot.get("snapshot_id")),
        "target_name": target.name,
        "bytes_written": len((text + "\n").encode("utf-8")),
        "write_performed": True,
        "parent_directory_stored": False,
        "export_summary": build_export_safe_snapshot_summary(snapshot),
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
        "path_created": True,
        "path_modified": True,
    }


def read_historical_snapshot(path: str | Path) -> dict[str, Any]:
    try:
        return deserialize_historical_snapshot(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        return build_malformed_snapshot_record(errors=[f"snapshot file could not be read: {exc.__class__.__name__}"])


def _snapshot_path(path: str | Path, snapshot: dict[str, Any]) -> Path:
    target = Path(path)
    if target.suffix:
        return target
    snapshot_id = str(snapshot.get("snapshot_id") or "historical-snapshot")
    safe_name = "".join(ch for ch in snapshot_id if ch.isalnum() or ch in {"-", "_", "."})[:120] or "historical-snapshot"
    return target / f"{safe_name}.json"
