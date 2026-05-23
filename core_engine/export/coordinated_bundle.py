from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from core_engine.export.node_manifest import (
    build_local_archive_plan,
    build_node_evidence_manifest,
    digest_payload,
)
from core_engine.export.redaction import validate_placeholder_safe
from core_engine.runtime.distributed_state import SAFETY_FLAGS


COORDINATED_EXPORT_RECORD_VERSION = 1


def build_coordinated_export_bundle_plan(
    node_payloads: Iterable[dict[str, Any]],
    *,
    expected_nodes: Iterable[str] | None = None,
    generated_at: str | None = None,
    output_path: str | Path | None = None,
    redact: bool = True,
    label: str = "coordinated-export",
) -> dict[str, Any]:
    """Build a deterministic multi-node export manifest and archive plan."""
    timestamp = generated_at or _now()
    node_manifests, malformed = build_node_evidence_manifests(
        node_payloads,
        generated_at=timestamp,
        redact=redact,
    )
    missing = detect_missing_export_nodes(node_manifests, expected_nodes=expected_nodes, generated_at=timestamp)
    conflicts = detect_export_conflicts(node_manifests, malformed=malformed, missing=missing, generated_at=timestamp)
    digest_summary = build_cross_node_digest_summary(node_manifests)
    record_counts = summarize_coordinated_record_counts(node_manifests)
    placeholder_validation = validate_coordinated_placeholders(node_manifests)
    manifest = {
        "manifest_type": "coordinated_export_bundle",
        "record_version": COORDINATED_EXPORT_RECORD_VERSION,
        "label": str(label or "coordinated-export"),
        "generated_at": timestamp,
        "source_node_ids": sorted({manifest["node_id"] for manifest in node_manifests}),
        "record_counts": record_counts,
        "digest_summary": digest_summary,
        "placeholder_validation": placeholder_validation,
        "redaction_applied": bool(redact),
        "conflict_count": len(conflicts),
        "missing_node_count": len(missing),
        **SAFETY_FLAGS,
    }
    manifest_digest = digest_payload({"manifest": manifest, "nodes": node_manifests, "conflicts": conflicts})
    manifest["manifest_digest"] = manifest_digest
    archive_plan = build_local_archive_plan(output_path=output_path, manifest=manifest)
    return {
        "record_type": "coordinated_export_bundle_plan",
        "record_version": COORDINATED_EXPORT_RECORD_VERSION,
        "coordinated_export_id": _stable_id("coordinated-export", timestamp, manifest_digest),
        "manifest": manifest,
        "node_manifests": node_manifests,
        "malformed_node_manifests": malformed,
        "missing_nodes": missing,
        "conflicts": conflicts,
        "archive_plan": archive_plan,
        "summary": summarize_coordinated_export_plan(
            node_manifests=node_manifests,
            conflicts=conflicts,
            missing=missing,
            record_counts=record_counts,
            placeholder_validation=placeholder_validation,
        ),
        **SAFETY_FLAGS,
    }


def build_node_evidence_manifests(
    node_payloads: Iterable[dict[str, Any]],
    *,
    generated_at: str | None = None,
    redact: bool = True,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    timestamp = generated_at or _now()
    manifests: list[dict[str, Any]] = []
    malformed: list[dict[str, Any]] = []
    for index, payload in enumerate(node_payloads):
        try:
            manifests.append(build_node_evidence_manifest(payload, generated_at=timestamp, redact=redact))
        except Exception as exc:
            malformed.append(build_malformed_node_manifest(index=index, error=str(exc), generated_at=timestamp))
    return sorted(manifests, key=lambda item: item["node_id"]), malformed


def summarize_coordinated_record_counts(node_manifests: Iterable[dict[str, Any]]) -> dict[str, Any]:
    totals = {
        "snapshots": 0,
        "topology_assets": 0,
        "topology_services": 0,
        "topology_edges": 0,
        "topology_conflicts": 0,
        "findings": 0,
        "reviews": 0,
        "runtime": 0,
        "health": 0,
    }
    by_node: dict[str, dict[str, int]] = {}
    for manifest in node_manifests:
        node_id = str(manifest.get("node_id") or "node-unknown")
        counts = {key: int(value or 0) for key, value in dict(manifest.get("record_counts") or {}).items()}
        by_node[node_id] = counts
        for key in totals:
            totals[key] += int(counts.get(key) or 0)
    return {
        "node_count": len(by_node),
        "totals": totals,
        "by_node": dict(sorted(by_node.items())),
        **SAFETY_FLAGS,
    }


def build_cross_node_digest_summary(node_manifests: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = list(node_manifests)
    node_digests = {
        str(row.get("node_id") or "node-unknown"): str(row.get("manifest_digest") or "")
        for row in rows
    }
    section_digests: dict[str, dict[str, str]] = {}
    for row in rows:
        node_id = str(row.get("node_id") or "node-unknown")
        for section, digest in dict(row.get("section_digests") or {}).items():
            section_digests.setdefault(section, {})[node_id] = str(digest)
    return {
        "node_manifest_digests": dict(sorted(node_digests.items())),
        "section_digests": {section: dict(sorted(values.items())) for section, values in sorted(section_digests.items())},
        "cross_node_digest": digest_payload({"node_manifest_digests": node_digests, "section_digests": section_digests}),
        **SAFETY_FLAGS,
    }


def validate_coordinated_placeholders(node_manifests: Iterable[dict[str, Any]]) -> dict[str, Any]:
    validations = {
        str(row.get("node_id") or "node-unknown"): dict(row.get("placeholder_validation") or validate_placeholder_safe(row))
        for row in node_manifests
    }
    failed = sorted(node_id for node_id, result in validations.items() if not result.get("ok"))
    private_types = sorted(
        {
            item
            for result in validations.values()
            for item in result.get("private_identifier_types", [])
        }
    )
    return {
        "ok": not failed,
        "failed_node_ids": failed,
        "private_identifier_types": private_types,
        "by_node": dict(sorted(validations.items())),
        **SAFETY_FLAGS,
    }


def detect_missing_export_nodes(
    node_manifests: Iterable[dict[str, Any]],
    *,
    expected_nodes: Iterable[str] | None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    present = {str(row.get("node_id") or "") for row in node_manifests}
    missing = []
    for node_id in sorted(str(item) for item in expected_nodes or [] if str(item).strip()):
        if node_id in present:
            continue
        missing.append(
            {
                "record_type": "coordinated_export_missing_node",
                "missing_node_id": node_id,
                "source_node_ids": [node_id],
                "detected_at": timestamp,
                "recommended_review": True,
                "summary": f"Expected node {node_id} did not provide export evidence.",
                **SAFETY_FLAGS,
            }
        )
    return missing


def detect_export_conflicts(
    node_manifests: Iterable[dict[str, Any]],
    *,
    malformed: Iterable[dict[str, Any]] | None = None,
    missing: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    conflicts: list[dict[str, Any]] = []
    by_node: dict[str, list[dict[str, Any]]] = {}
    for manifest in node_manifests:
        by_node.setdefault(str(manifest.get("node_id") or "node-unknown"), []).append(manifest)
        validation = manifest.get("placeholder_validation") if isinstance(manifest.get("placeholder_validation"), dict) else {}
        if validation and not validation.get("ok"):
            conflicts.append(
                build_export_conflict(
                    "placeholder_validation_failed",
                    affected_ref=str(manifest.get("node_id") or "node-unknown"),
                    source_node_ids=[str(manifest.get("node_id") or "node-unknown")],
                    summary="Node evidence manifest failed placeholder validation.",
                    detected_at=timestamp,
                )
            )
    for node_id, rows in sorted(by_node.items()):
        if len(rows) > 1:
            conflicts.append(
                build_export_conflict(
                    "duplicate_node_manifest",
                    affected_ref=node_id,
                    source_node_ids=[node_id],
                    summary="Multiple export manifests were provided for the same node.",
                    detected_at=timestamp,
                )
            )
    for row in malformed or []:
        conflicts.append(
            build_export_conflict(
                "malformed_node_manifest",
                affected_ref=str(row.get("node_id") or "malformed-node"),
                source_node_ids=[str(row.get("node_id") or "malformed-node")],
                summary=str(row.get("error") or "Malformed node evidence manifest."),
                detected_at=timestamp,
            )
        )
    for row in missing or []:
        conflicts.append(
            build_export_conflict(
                "missing_node_manifest",
                affected_ref=str(row.get("missing_node_id") or "node-unknown"),
                source_node_ids=list(row.get("source_node_ids") or []),
                summary=str(row.get("summary") or "Expected node did not provide export evidence."),
                detected_at=timestamp,
            )
        )
    return sorted(conflicts, key=lambda item: item["conflict_id"])


def build_export_conflict(
    conflict_type: str,
    *,
    affected_ref: str,
    source_node_ids: list[str],
    summary: str,
    detected_at: str | None = None,
) -> dict[str, Any]:
    timestamp = detected_at or _now()
    source_nodes = sorted(set(str(item) for item in source_node_ids if str(item).strip()))
    conflict = {
        "record_type": "coordinated_export_conflict",
        "conflict_type": str(conflict_type),
        "affected_ref": str(affected_ref),
        "source_node_ids": source_nodes,
        "summary": str(summary),
        "severity": "medium",
        "detected_at": timestamp,
        "recommended_review": True,
        **SAFETY_FLAGS,
    }
    conflict["conflict_id"] = _stable_id("coordinated-export-conflict", conflict_type, affected_ref, source_nodes, summary)
    return conflict


def summarize_coordinated_export_plan(
    *,
    node_manifests: Iterable[dict[str, Any]],
    conflicts: Iterable[dict[str, Any]],
    missing: Iterable[dict[str, Any]],
    record_counts: dict[str, Any],
    placeholder_validation: dict[str, Any],
) -> dict[str, Any]:
    node_rows = list(node_manifests)
    conflict_rows = list(conflicts)
    missing_rows = list(missing)
    by_conflict_type: dict[str, int] = {}
    for conflict in conflict_rows:
        conflict_type = str(conflict.get("conflict_type") or "unknown")
        by_conflict_type[conflict_type] = by_conflict_type.get(conflict_type, 0) + 1
    return {
        "status": "review_required" if conflict_rows or missing_rows or not placeholder_validation.get("ok") else "ok",
        "node_count": len(node_rows),
        "missing_node_count": len(missing_rows),
        "conflict_count": len(conflict_rows),
        "by_conflict_type": dict(sorted(by_conflict_type.items())),
        "record_counts": record_counts,
        "placeholder_validation_ok": bool(placeholder_validation.get("ok")),
        "administrator_review_required": bool(conflict_rows or missing_rows or not placeholder_validation.get("ok")),
        **SAFETY_FLAGS,
    }


def build_malformed_node_manifest(*, index: int, error: str, generated_at: str) -> dict[str, Any]:
    node_id = f"malformed-export-node-{index}"
    return {
        "record_type": "node_evidence_manifest",
        "node_id": node_id,
        "node_label": node_id,
        "role": "unknown",
        "generated_at": generated_at,
        "status": "malformed",
        "error": error,
        "record_counts": {},
        "section_digests": {},
        "manifest_digest": "",
        "placeholder_validation": {
            "ok": False,
            "private_identifier_types": [],
            **SAFETY_FLAGS,
        },
        **SAFETY_FLAGS,
    }


def export_coordinated_bundle_plan_json(plan: dict[str, Any]) -> str:
    return json.dumps(plan, sort_keys=True, indent=2, default=str)


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
