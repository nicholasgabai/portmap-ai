from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from core_engine.export.redaction import redact_operational_record, validate_placeholder_safe
from core_engine.policy.history import REVIEW_RECORD_TYPE, REVIEW_TRANSITION_RECORD_TYPE
from core_engine.policy.review_queue import ReviewQueue
from core_engine.policy.review_store import PersistentReviewStore
from core_engine.runtime.runtime_state import RuntimeState
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.topology.graph import build_topology_graph, summarize_topology
from gui.web.providers import diagnostic_summary_response, review_summary_response, runtime_state_response


SAFETY_FLAGS = {
    "local_only": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


def build_operational_export_bundle(
    *,
    repository: LocalStorageRepository | None = None,
    snapshots: Iterable[dict[str, Any]] | None = None,
    topology_edges: Iterable[dict[str, Any]] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    review_store: PersistentReviewStore | ReviewQueue | None = None,
    reviews: Iterable[dict[str, Any]] | None = None,
    runtime_state: RuntimeState | dict[str, Any] | None = None,
    runtime_summary: dict[str, Any] | None = None,
    diagnostics: Iterable[dict[str, Any]] | None = None,
    label: str = "operational-export",
    generated_at: str | None = None,
    redact: bool = True,
) -> dict[str, Any]:
    """Build a deterministic local operational evidence bundle."""
    timestamp = generated_at or _now()
    snapshot_rows = _collect_snapshots(repository, snapshots)
    topology_rows = _collect_topology_edges(repository, topology_edges)
    finding_rows, repository_review_rows = _collect_findings(repository, findings)
    review_rows = _collect_reviews(review_store, reviews, repository_review_rows)
    runtime_rows = [_runtime_payload(runtime_state, runtime_summary, generated_at=timestamp)]
    diagnostic_payload = diagnostic_summary_response(_rows(diagnostics), generated_at=timestamp)
    topology_payload = _topology_payload(snapshot_rows, topology_rows, generated_at=timestamp)

    content = {
        "snapshots": snapshot_rows,
        "topology": topology_payload,
        "findings": finding_rows,
        "reviews": review_rows,
        "runtime": runtime_rows,
        "diagnostics": diagnostic_payload,
    }
    if redact:
        content = redact_operational_record(content)
    validation = validate_placeholder_safe(content)
    manifest = {
        "bundle_type": "operational_evidence_export",
        "label": str(label or "operational-export"),
        "generated_at": timestamp,
        "record_counts": {
            "snapshots": len(content["snapshots"]),
            "topology_edges": len(content["topology"].get("edges") or []),
            "findings": len(content["findings"]),
            "review_records": len(content["reviews"]),
            "runtime_summaries": len(content["runtime"]),
            "diagnostics": len(content["diagnostics"].get("items") or []),
        },
        "placeholder_validation": validation,
        "redaction_applied": bool(redact),
        **SAFETY_FLAGS,
    }
    digest = _digest({"manifest": manifest, "content": content})
    return {
        "manifest": {**manifest, "digest": digest},
        **content,
        **SAFETY_FLAGS,
    }


def export_operational_bundle_json(bundle: dict[str, Any]) -> str:
    return json.dumps(bundle, sort_keys=True, indent=2, default=str)


def write_operational_export_bundle(path: str | Path, bundle: dict[str, Any]) -> dict[str, Any]:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    text = export_operational_bundle_json(bundle)
    output_path.write_text(text, encoding="utf-8")
    return {
        "status": "written",
        "output_name": output_path.name,
        "bytes_written": len(text.encode("utf-8")),
        "path_stored": False,
        **SAFETY_FLAGS,
    }


def write_operational_export_archive(path: str | Path, bundle: dict[str, Any]) -> dict[str, Any]:
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    bundle_text = export_operational_bundle_json(bundle)
    manifest_text = json.dumps(bundle.get("manifest") or {}, sort_keys=True, indent=2, default=str)
    with ZipFile(output_path, "w", compression=ZIP_DEFLATED) as archive:
        _write_zip_text(archive, "manifest.json", manifest_text)
        _write_zip_text(archive, "bundle.json", bundle_text)
    return {
        "status": "written",
        "archive_name": output_path.name,
        "bytes_written": output_path.stat().st_size,
        "path_stored": False,
        **SAFETY_FLAGS,
    }


def _collect_snapshots(repository: LocalStorageRepository | None, snapshots: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = []
    if repository is not None:
        rows.extend(repository.list_snapshots())
    rows.extend(_rows(snapshots))
    return _sorted_unique(rows, "snapshot_id")


def _collect_topology_edges(
    repository: LocalStorageRepository | None,
    topology_edges: Iterable[dict[str, Any]] | None,
) -> list[dict[str, Any]]:
    rows = []
    if repository is not None:
        rows.extend(repository.list_topology_edges())
    rows.extend(_rows(topology_edges))
    return _sorted_unique(rows, "edge_id")


def _collect_findings(
    repository: LocalStorageRepository | None,
    findings: Iterable[dict[str, Any]] | None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows = []
    if repository is not None:
        rows.extend(repository.list_findings())
    rows.extend(_rows(findings))
    review_records: list[dict[str, Any]] = []
    finding_records: list[dict[str, Any]] = []
    for row in rows:
        if row.get("record_type") in {REVIEW_RECORD_TYPE, REVIEW_TRANSITION_RECORD_TYPE}:
            review_records.append(row)
        else:
            finding_records.append(row)
    return _sorted_unique(finding_records, "finding_id"), _sorted_unique(review_records, "finding_id")


def _collect_reviews(
    review_store: PersistentReviewStore | ReviewQueue | None,
    reviews: Iterable[dict[str, Any]] | None,
    repository_review_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = list(repository_review_rows)
    if review_store is not None:
        response = review_summary_response(review_store)
        rows.extend(_rows(response.get("items")))
    rows.extend(_rows(reviews))
    by_key: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(_rows(rows)):
        key = str(
            row.get("transition_id")
            or row.get("status_record_id")
            or row.get("review_id")
            or row.get("finding_id")
            or _digest(row)
            or index
        )
        by_key.setdefault(key, row)
    return [by_key[key] for key in sorted(by_key)]


def _runtime_payload(
    runtime_state: RuntimeState | dict[str, Any] | None,
    runtime_summary: dict[str, Any] | None,
    *,
    generated_at: str,
) -> dict[str, Any]:
    if runtime_summary is not None:
        return {**dict(runtime_summary), "generated_at": generated_at, **SAFETY_FLAGS}
    return runtime_state_response(runtime_state, generated_at=generated_at)


def _topology_payload(snapshots: list[dict[str, Any]], topology_edges: list[dict[str, Any]], *, generated_at: str) -> dict[str, Any]:
    asset_rows: list[dict[str, Any]] = []
    edge_rows = list(topology_edges)
    for snapshot in snapshots:
        topology = snapshot.get("topology") if isinstance(snapshot.get("topology"), dict) else {}
        asset_rows.extend(_rows(topology.get("nodes")))
        edge_rows.extend(_rows(topology.get("edges")))
    graph = build_topology_graph(assets=asset_rows, topology_edges=edge_rows, generated_at=generated_at)
    return {
        "nodes": graph["nodes"],
        "edges": graph["edges"],
        "summary": summarize_topology(graph),
        **SAFETY_FLAGS,
    }


def _sorted_unique(rows: Iterable[dict[str, Any]], key_name: str, *, fallback_key: str | None = None) -> list[dict[str, Any]]:
    by_key: dict[str, dict[str, Any]] = {}
    for index, row in enumerate(_rows(rows)):
        key = str(row.get(key_name) or row.get(fallback_key or "") or _digest(row) or index)
        by_key.setdefault(key, row)
    return [by_key[key] for key in sorted(by_key)]


def _rows(value: Any) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return "sha256:" + sha256(material.encode("utf-8")).hexdigest()


def _write_zip_text(archive: ZipFile, name: str, text: str) -> None:
    info = ZipInfo(name)
    info.date_time = (2026, 1, 1, 0, 0, 0)
    info.compress_type = ZIP_DEFLATED
    archive.writestr(info, text.encode("utf-8"))


def _now() -> str:
    return datetime.now(UTC).isoformat()
