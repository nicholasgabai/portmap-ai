from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.export.node_manifest import digest_payload
from core_engine.platform.filesystem_safety import FILESYSTEM_SAFETY_FLAGS
from core_engine.telemetry.behavior_summary import (
    BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    COMPONENT_ORDER,
)


HISTORICAL_SNAPSHOT_RECORD_VERSION = 1

HISTORICAL_SNAPSHOT_SAFETY_FLAGS = {
    **BEHAVIORAL_INTELLIGENCE_SAFETY_FLAGS,
    **FILESYSTEM_SAFETY_FLAGS,
    "historical_persistence": True,
    "metadata_only": True,
    "bounded_retention": True,
    "local_first": True,
    "dry_run_safe": True,
    "advisory_only": True,
    "raw_payload_stored": False,
    "packet_payloads_stored": False,
    "credentials_stored": False,
    "raw_logs_stored": False,
    "raw_browsing_history_stored": False,
    "private_runtime_artifacts_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
    "dashboard_safe": True,
    "api_safe": True,
    "export_ready": True,
}


class HistoricalSnapshotError(ValueError):
    """Raised when a historical metadata snapshot cannot be created."""


def build_historical_snapshot(
    behavioral_intelligence_summary: dict[str, Any],
    *,
    source_label: str = "behavioral_intelligence",
    source_refs: Iterable[str] | None = None,
    generated_at: str | None = None,
    snapshot_label: str | None = None,
) -> dict[str, Any]:
    """Build a retention-safe metadata snapshot from a behavioral summary."""
    if not isinstance(behavioral_intelligence_summary, dict):
        raise HistoricalSnapshotError("behavioral intelligence summary must be an object")
    timestamp = generated_at or _now()
    payload = _snapshot_payload(behavioral_intelligence_summary)
    summary = build_snapshot_metadata_summary(payload, generated_at=timestamp)
    digest = digest_payload(payload)
    snapshot_id = _stable_id("historical-snapshot", source_label, timestamp, digest)
    snapshot = {
        "record_type": "historical_behavior_snapshot",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "snapshot_id": snapshot_id,
        "snapshot_label": str(snapshot_label or snapshot_id),
        "generated_at": timestamp,
        "snapshot_timestamp": timestamp,
        "source_label": _safe_label(source_label),
        "source_refs": _source_refs(source_refs, behavioral_intelligence_summary, source_label=source_label),
        "retention_safe_snapshot_id": True,
        "snapshot_digest": digest,
        "metadata_summary": summary,
        "payload": payload,
        "export_summary": build_export_safe_snapshot_summary(
            {
                "snapshot_id": snapshot_id,
                "generated_at": timestamp,
                "source_label": _safe_label(source_label),
                "snapshot_digest": digest,
                "metadata_summary": summary,
            },
            generated_at=timestamp,
        ),
        "dashboard_status": build_snapshot_dashboard_record(
            {
                "snapshot_id": snapshot_id,
                "generated_at": timestamp,
                "source_label": _safe_label(source_label),
                "snapshot_digest": digest,
                "metadata_summary": summary,
            },
            generated_at=timestamp,
        ),
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }
    snapshot["export_summary"] = build_export_safe_snapshot_summary(snapshot, generated_at=timestamp)
    snapshot["dashboard_status"] = build_snapshot_dashboard_record(snapshot, generated_at=timestamp)
    return snapshot


def build_snapshot_metadata_summary(snapshot_or_payload: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    payload = snapshot_or_payload.get("payload") if isinstance(snapshot_or_payload.get("payload"), dict) else snapshot_or_payload
    if not isinstance(payload, dict):
        payload = {}
    rollups = payload.get("component_rollups") if isinstance(payload.get("component_rollups"), dict) else {}
    state_summary = payload.get("state_summary") if isinstance(payload.get("state_summary"), dict) else {}
    export_summary = payload.get("export_summary") if isinstance(payload.get("export_summary"), dict) else {}
    record_counts = export_summary.get("record_counts") if isinstance(export_summary.get("record_counts"), dict) else {}
    component_states = state_summary.get("component_states") if isinstance(state_summary.get("component_states"), dict) else {}
    total_records = sum(int(value or 0) for value in record_counts.values()) if record_counts else sum(
        int((rollups.get(name) or {}).get("record_count") or 0)
        for name in COMPONENT_ORDER
        if isinstance(rollups.get(name), dict)
    )
    summary = {
        "record_type": "historical_snapshot_metadata_summary",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "source_record_type": str(payload.get("record_type") or "unknown"),
        "source_summary_id": str(payload.get("summary_id") or payload.get("report_id") or ""),
        "status": str(payload.get("status") or state_summary.get("overall_state") or "unknown"),
        "component_count": len([name for name in COMPONENT_ORDER if isinstance(rollups.get(name), dict)]),
        "record_count": int(total_records),
        "recommendation_count": len(_rows(payload.get("recommendations"))),
        "explanation_count": len(_rows(payload.get("explanations"))),
        "component_states": {str(key): str(value) for key, value in sorted(component_states.items())},
        "component_record_counts": {
            name: int((rollups.get(name) or {}).get("record_count") or record_counts.get(name) or 0)
            for name in COMPONENT_ORDER
        },
        "source_export_digest": str(export_summary.get("digest") or ""),
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }
    summary["metadata_digest"] = digest_payload(
        {
            "source_summary_id": summary["source_summary_id"],
            "status": summary["status"],
            "component_record_counts": summary["component_record_counts"],
            "source_export_digest": summary["source_export_digest"],
        }
    )
    return summary


def build_export_safe_snapshot_summary(snapshot: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    metadata = snapshot.get("metadata_summary") if isinstance(snapshot.get("metadata_summary"), dict) else {}
    payload = {
        "record_type": "historical_snapshot_export_summary",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "generated_at": generated_at or snapshot.get("generated_at") or _now(),
        "snapshot_id": str(snapshot.get("snapshot_id") or ""),
        "snapshot_digest": str(snapshot.get("snapshot_digest") or ""),
        "source_label": str(snapshot.get("source_label") or ""),
        "status": str(metadata.get("status") or "unknown"),
        "record_counts": {
            "snapshot": 1 if snapshot.get("snapshot_id") else 0,
            "components": int(metadata.get("component_count") or 0),
            "behavior_records": int(metadata.get("record_count") or 0),
            "recommendations": int(metadata.get("recommendation_count") or 0),
            "explanations": int(metadata.get("explanation_count") or 0),
        },
        "metadata_digest": str(metadata.get("metadata_digest") or ""),
        "digest": "",
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }
    payload["digest"] = digest_payload(
        {
            "snapshot_id": payload["snapshot_id"],
            "snapshot_digest": payload["snapshot_digest"],
            "record_counts": payload["record_counts"],
            "metadata_digest": payload["metadata_digest"],
        }
    )
    return payload


def build_snapshot_dashboard_record(snapshot: dict[str, Any], *, generated_at: str | None = None) -> dict[str, Any]:
    metadata = snapshot.get("metadata_summary") if isinstance(snapshot.get("metadata_summary"), dict) else {}
    return {
        "record_type": "historical_snapshot_dashboard",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "panel": "historical_snapshot_persistence",
        "generated_at": generated_at or snapshot.get("generated_at") or _now(),
        "status": str(metadata.get("status") or "unknown"),
        "snapshot_id": str(snapshot.get("snapshot_id") or ""),
        "source_label": str(snapshot.get("source_label") or ""),
        "metrics": {
            "component_count": int(metadata.get("component_count") or 0),
            "record_count": int(metadata.get("record_count") or 0),
            "recommendation_count": int(metadata.get("recommendation_count") or 0),
            "explanation_count": int(metadata.get("explanation_count") or 0),
        },
        "component_states": dict(metadata.get("component_states") or {}),
        "component_record_counts": dict(metadata.get("component_record_counts") or {}),
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def serialize_historical_snapshot(snapshot: dict[str, Any]) -> str:
    validation = validate_historical_snapshot(snapshot)
    if not validation["valid"]:
        raise HistoricalSnapshotError("; ".join(validation["errors"]))
    return deterministic_historical_snapshot_json(snapshot)


def deserialize_historical_snapshot(text: str | bytes | dict[str, Any]) -> dict[str, Any]:
    try:
        if isinstance(text, dict):
            candidate = dict(text)
        else:
            candidate = json.loads(text.decode("utf-8") if isinstance(text, bytes) else str(text))
        if not isinstance(candidate, dict):
            return build_malformed_snapshot_record(errors=["snapshot JSON must decode to an object"])
        validation = validate_historical_snapshot(candidate)
        if not validation["valid"]:
            return build_malformed_snapshot_record(raw_record=candidate, errors=validation["errors"])
        return candidate
    except (TypeError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return build_malformed_snapshot_record(errors=[f"snapshot JSON could not be decoded: {exc}"])


def validate_historical_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(snapshot, dict):
        errors.append("snapshot must be an object")
    else:
        if snapshot.get("record_type") != "historical_behavior_snapshot":
            errors.append("record_type must be historical_behavior_snapshot")
        for key in ("snapshot_id", "generated_at", "snapshot_timestamp", "source_label", "snapshot_digest"):
            if not str(snapshot.get(key) or "").strip():
                errors.append(f"{key} is required")
        if not isinstance(snapshot.get("metadata_summary"), dict):
            errors.append("metadata_summary must be an object")
        if not isinstance(snapshot.get("payload"), dict):
            errors.append("payload must be an object")
        if snapshot.get("raw_payload_stored") is not False:
            errors.append("raw_payload_stored must be false")
        if snapshot.get("credentials_stored") is not False:
            errors.append("credentials_stored must be false")
        if snapshot.get("metadata_only") is not True:
            errors.append("metadata_only must be true")
    return {
        "record_type": "historical_snapshot_validation",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "valid": not errors,
        "errors": errors,
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def build_malformed_snapshot_record(
    raw_record: dict[str, Any] | None = None,
    *,
    errors: Iterable[str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    error_rows = [str(error) for error in errors or ["snapshot record is malformed"] if str(error).strip()]
    return {
        "record_type": "malformed_historical_snapshot",
        "record_version": HISTORICAL_SNAPSHOT_RECORD_VERSION,
        "generated_at": timestamp,
        "status": "malformed",
        "valid": False,
        "errors": error_rows,
        "raw_record_digest": digest_payload(raw_record or {}),
        "raw_record_stored": False,
        "operator_action": "review_sanitized_snapshot_input",
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def deterministic_historical_snapshot_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _snapshot_payload(summary: dict[str, Any]) -> dict[str, Any]:
    state_summary = summary.get("state_summary") if isinstance(summary.get("state_summary"), dict) else {}
    dashboard = summary.get("dashboard_status") if isinstance(summary.get("dashboard_status"), dict) else {}
    export = summary.get("export_summary") if isinstance(summary.get("export_summary"), dict) else {}
    privacy = summary.get("privacy_safety_summary") if isinstance(summary.get("privacy_safety_summary"), dict) else {}
    rollups = summary.get("component_rollups") if isinstance(summary.get("component_rollups"), dict) else {}
    return {
        "record_type": str(summary.get("record_type") or "behavioral_intelligence_summary"),
        "record_version": int(summary.get("record_version") or 1),
        "summary_id": str(summary.get("summary_id") or ""),
        "generated_at": str(summary.get("generated_at") or ""),
        "status": str(summary.get("status") or state_summary.get("overall_state") or "unknown"),
        "component_rollups": {
            name: _project_rollup(rollups.get(name))
            for name in COMPONENT_ORDER
            if isinstance(rollups.get(name), dict)
        },
        "state_summary": {
            "overall_state": str(state_summary.get("overall_state") or "unknown"),
            "component_states": dict(sorted((state_summary.get("component_states") or {}).items()))
            if isinstance(state_summary.get("component_states"), dict)
            else {},
            "recommended_review_count": int(state_summary.get("recommended_review_count") or 0),
            "supported_component_count": int(state_summary.get("supported_component_count") or 0),
            "degraded_component_count": int(state_summary.get("degraded_component_count") or 0),
            "unavailable_component_count": int(state_summary.get("unavailable_component_count") or 0),
        },
        "recommendations": _project_recommendations(summary.get("recommendations")),
        "explanations": _project_explanations(summary.get("explanations")),
        "dashboard_status": {
            "status": str(dashboard.get("status") or ""),
            "metrics": dict(sorted((dashboard.get("metrics") or {}).items())) if isinstance(dashboard.get("metrics"), dict) else {},
            "recommended_review": bool(dashboard.get("recommended_review")),
        },
        "export_summary": {
            "record_type": str(export.get("record_type") or ""),
            "overall_state": str(export.get("overall_state") or ""),
            "record_counts": dict(sorted((export.get("record_counts") or {}).items())) if isinstance(export.get("record_counts"), dict) else {},
            "recommendation_count": int(export.get("recommendation_count") or 0),
            "digest": str(export.get("digest") or ""),
        },
        "privacy_safety_summary": {
            "payloads_stored": bool(privacy.get("payloads_stored", False)),
            "credentials_stored": bool(privacy.get("credentials_stored", False)),
            "raw_dns_payloads_stored": bool(privacy.get("raw_dns_payloads_stored", False)),
            "raw_browsing_history_stored": bool(privacy.get("raw_browsing_history_stored", False)),
            "external_reputation_calls": bool(privacy.get("external_reputation_calls", False)),
            "automatic_enforcement": bool(privacy.get("automatic_enforcement", False)),
            "firewall_changes": bool(privacy.get("firewall_changes", False)),
        },
        **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    }


def _project_rollup(row: Any) -> dict[str, Any]:
    if not isinstance(row, dict):
        return {}
    return {
        "component": str(row.get("component") or ""),
        "state": str(row.get("state") or "unknown"),
        "record_count": int(row.get("record_count") or 0),
        "recommended_review_count": int(row.get("recommended_review_count") or 0),
        "confidence": round(float(row.get("confidence") or 0.0), 3),
        "metrics": dict(sorted((row.get("metrics") or {}).items())) if isinstance(row.get("metrics"), dict) else {},
        "by_state": dict(sorted((row.get("by_state") or {}).items())) if isinstance(row.get("by_state"), dict) else {},
    }


def _project_recommendations(rows: Any) -> list[dict[str, Any]]:
    projected = []
    for row in _rows(rows)[:50]:
        projected.append(
            {
                "component": str(row.get("component") or ""),
                "action": str(row.get("action") or ""),
                "severity": str(row.get("severity") or ""),
                "summary": str(row.get("summary") or ""),
                "recommendation_id": str(row.get("recommendation_id") or ""),
            }
        )
    return projected


def _project_explanations(rows: Any) -> list[dict[str, Any]]:
    projected = []
    for row in _rows(rows)[:50]:
        projected.append(
            {
                "component": str(row.get("component") or ""),
                "state": str(row.get("state") or ""),
                "operator_action": str(row.get("operator_action") or ""),
                "confidence": round(float(row.get("confidence") or 0.0), 3),
                "explanation_id": str(row.get("explanation_id") or ""),
            }
        )
    return projected


def _source_refs(source_refs: Iterable[str] | None, summary: dict[str, Any], *, source_label: str) -> list[str]:
    refs = [str(ref) for ref in source_refs or [] if str(ref).strip()]
    for key in ("summary_id", "report_id"):
        if summary.get(key):
            refs.append(f"{source_label}:{summary[key]}")
    if not refs:
        refs.append(f"{source_label}:metadata-summary")
    return sorted(set(refs))


def _safe_label(value: str) -> str:
    text = str(value or "behavioral_intelligence").strip().lower().replace(" ", "-")
    return "".join(ch for ch in text if ch.isalnum() or ch in {"-", "_", "."})[:80] or "behavioral_intelligence"


def _stable_id(prefix: str, *parts: Any) -> str:
    return f"{prefix}-" + _digest(parts)[:16]


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _rows(value: Any) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _now() -> str:
    return datetime.now(UTC).isoformat()
