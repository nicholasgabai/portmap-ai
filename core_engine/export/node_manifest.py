from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable

from core_engine.export.redaction import redact_operational_record, validate_placeholder_safe
from core_engine.runtime.distributed_state import SAFETY_FLAGS


NODE_EVIDENCE_MANIFEST_VERSION = 1
EVIDENCE_SECTIONS = (
    "snapshots",
    "topology",
    "findings",
    "reviews",
    "runtime",
    "health",
)


class NodeEvidenceManifestError(ValueError):
    """Raised when a trusted-node evidence manifest cannot be built."""


def build_node_evidence_manifest(
    node_payload: dict[str, Any],
    *,
    generated_at: str | None = None,
    redact: bool = True,
) -> dict[str, Any]:
    """Build a deterministic evidence manifest for one trusted local node."""
    if not isinstance(node_payload, dict):
        raise NodeEvidenceManifestError("node evidence payload must be an object")
    timestamp = generated_at or _now()
    node_id = _required_str(node_payload.get("node_id") or node_payload.get("source_node_id"), "node_id")
    evidence = collect_node_evidence_sections(node_payload)
    if redact:
        evidence = redact_operational_record(evidence)
    validation = validate_placeholder_safe(evidence)
    record_counts = count_node_evidence_records(evidence)
    digest = digest_payload({"node_id": node_id, "record_counts": record_counts, "evidence": evidence})
    return {
        "record_type": "node_evidence_manifest",
        "record_version": NODE_EVIDENCE_MANIFEST_VERSION,
        "node_manifest_id": _stable_id("node-evidence-manifest", node_id, timestamp, digest),
        "node_id": node_id,
        "node_label": str(node_payload.get("node_label") or node_payload.get("label") or node_id),
        "role": str(node_payload.get("role") or "worker"),
        "generated_at": timestamp,
        "source_refs": _source_refs(node_payload, node_id=node_id),
        "record_counts": record_counts,
        "section_digests": build_section_digests(evidence),
        "manifest_digest": digest,
        "placeholder_validation": validation,
        "redaction_applied": bool(redact),
        "evidence": evidence,
        **SAFETY_FLAGS,
    }


def collect_node_evidence_sections(node_payload: dict[str, Any]) -> dict[str, Any]:
    topology_payload = node_payload.get("topology")
    if not isinstance(topology_payload, dict):
        topology_payload = {}
    reviews = _coerce_review_items(node_payload)
    runtime_rows = _coerce_runtime_rows(node_payload)
    health_rows = _coerce_health_rows(node_payload)
    return {
        "snapshots": _rows(node_payload.get("snapshots") or node_payload.get("snapshot_records")),
        "topology": {
            "assets": _rows(node_payload.get("assets") or topology_payload.get("assets") or topology_payload.get("nodes")),
            "services": _rows(node_payload.get("services") or topology_payload.get("services")),
            "edges": _rows(node_payload.get("topology_edges") or topology_payload.get("edges")),
            "conflicts": _rows(node_payload.get("topology_conflicts") or topology_payload.get("conflicts")),
        },
        "findings": _rows(node_payload.get("findings") or node_payload.get("finding_records")),
        "reviews": reviews,
        "runtime": runtime_rows,
        "health": health_rows,
    }


def count_node_evidence_records(evidence: dict[str, Any]) -> dict[str, int]:
    topology = evidence.get("topology") if isinstance(evidence.get("topology"), dict) else {}
    return {
        "snapshots": len(_rows(evidence.get("snapshots"))),
        "topology_assets": len(_rows(topology.get("assets"))),
        "topology_services": len(_rows(topology.get("services"))),
        "topology_edges": len(_rows(topology.get("edges"))),
        "topology_conflicts": len(_rows(topology.get("conflicts"))),
        "findings": len(_rows(evidence.get("findings"))),
        "reviews": len(_rows(evidence.get("reviews"))),
        "runtime": len(_rows(evidence.get("runtime"))),
        "health": len(_rows(evidence.get("health"))),
    }


def build_section_digests(evidence: dict[str, Any]) -> dict[str, str]:
    return {section: digest_payload(evidence.get(section) or []) for section in EVIDENCE_SECTIONS}


def build_local_archive_plan(
    *,
    output_path: str | Path | None,
    manifest: dict[str, Any],
    archive_name: str = "coordinated-export-bundle.zip",
) -> dict[str, Any]:
    """Describe an optional local archive target without writing it."""
    if output_path is None:
        return {
            "archive_requested": False,
            "status": "not_requested",
            "archive_name": "",
            "output_directory_stored": False,
            "write_performed": False,
            **SAFETY_FLAGS,
        }
    output = Path(output_path)
    name = output.name if output.suffix else archive_name
    return {
        "archive_requested": True,
        "status": "planned",
        "archive_name": name,
        "manifest_digest": str(manifest.get("manifest_digest") or manifest.get("digest") or ""),
        "output_directory_stored": False,
        "write_performed": False,
        **SAFETY_FLAGS,
    }


def digest_payload(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return "sha256:" + sha256(material.encode("utf-8")).hexdigest()


def _coerce_review_items(node_payload: dict[str, Any]) -> list[dict[str, Any]]:
    for key in ("reviews", "review_records", "review_drafts"):
        rows = _rows(node_payload.get(key))
        if rows:
            return rows
    distributed_review = node_payload.get("distributed_review")
    if isinstance(distributed_review, dict):
        return _rows(distributed_review.get("reviews") or distributed_review.get("items"))
    review_export = node_payload.get("review_export")
    if isinstance(review_export, dict):
        return _rows(review_export.get("items"))
    return []


def _coerce_runtime_rows(node_payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _rows(node_payload.get("runtime") or node_payload.get("runtime_summaries"))
    for key in ("runtime_summary", "session_summary", "profile_summary", "checkpoint_summary"):
        value = node_payload.get(key)
        if isinstance(value, dict) and value:
            rows.append(value)
    return rows


def _coerce_health_rows(node_payload: dict[str, Any]) -> list[dict[str, Any]]:
    rows = _rows(node_payload.get("health") or node_payload.get("health_summaries"))
    for key in ("health_summary", "cluster_health"):
        value = node_payload.get(key)
        if isinstance(value, dict) and value:
            rows.append(value)
    return rows


def _source_refs(node_payload: dict[str, Any], *, node_id: str) -> list[str]:
    refs = [str(item) for item in node_payload.get("source_refs") or [] if str(item).strip()]
    if not refs:
        refs.append(f"node:{node_id}")
    return sorted(set(refs))


def _rows(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise NodeEvidenceManifestError(f"{field_name} must be a non-empty string")
    return value


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}-" + digest_payload(parts).removeprefix("sha256:")[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
