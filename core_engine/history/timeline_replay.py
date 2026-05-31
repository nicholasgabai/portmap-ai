from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.export.node_manifest import digest_payload
from core_engine.history.baseline_decay import BASELINE_DECAY_SAFETY_FLAGS
from core_engine.history.replay_windows import (
    DEFAULT_MAX_REPLAY_EVENTS,
    REPLAY_WINDOW_SAFETY_FLAGS,
    build_replay_window_record,
    build_snapshot_sequence_summary,
    infer_replay_window,
    select_snapshots_for_replay_window,
)
from core_engine.history.topology_evolution import TOPOLOGY_EVOLUTION_SAFETY_FLAGS


TIMELINE_REPLAY_RECORD_VERSION = 1

TIMELINE_REPLAY_SAFETY_FLAGS = {
    **REPLAY_WINDOW_SAFETY_FLAGS,
    **BASELINE_DECAY_SAFETY_FLAGS,
    **TOPOLOGY_EVOLUTION_SAFETY_FLAGS,
    "timeline_replay_only": True,
    "metadata_only": True,
    "local_first": True,
    "bounded_retention": True,
    "advisory_only": True,
    "dry_run_safe": True,
    "offline_review_only": True,
    "collectors_rerun": False,
    "packet_payloads_stored": False,
    "credentials_stored": False,
    "raw_browsing_history_stored": False,
    "external_services_used": False,
    "automatic_enforcement": False,
    "firewall_changes": False,
}

COMPONENT_REPLAY_NAMES = (
    "baselines",
    "temporal_anomalies",
    "service_fingerprints",
    "dns_destination_behavior",
    "adaptive_risk",
)


def build_historical_timeline_replay(
    *,
    historical_snapshots: Iterable[dict[str, Any]] | None = None,
    replay_window: dict[str, Any] | None = None,
    temporal_anomaly_reports: Iterable[dict[str, Any]] | None = None,
    topology_evolution_reports: Iterable[dict[str, Any]] | None = None,
    baseline_decay_reports: Iterable[dict[str, Any]] | None = None,
    service_fingerprint_reports: Iterable[dict[str, Any]] | None = None,
    dns_destination_behavior_reports: Iterable[dict[str, Any]] | None = None,
    adaptive_risk_reports: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_events: int = DEFAULT_MAX_REPLAY_EVENTS,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    window = replay_window or infer_replay_window(historical_snapshots or [], max_events=max_events, generated_at=timestamp)
    if not replay_window:
        window["max_events"] = max(0, int(max_events))
    snapshots, malformed = select_snapshots_for_replay_window(historical_snapshots or [], replay_window=window)
    sequence = build_snapshot_sequence_summary(snapshots + malformed, replay_window=window, generated_at=timestamp)
    raw_events = build_bounded_timeline_events(
        snapshots=snapshots,
        temporal_anomaly_reports=temporal_anomaly_reports,
        topology_evolution_reports=topology_evolution_reports,
        baseline_decay_reports=baseline_decay_reports,
        service_fingerprint_reports=service_fingerprint_reports,
        dns_destination_behavior_reports=dns_destination_behavior_reports,
        adaptive_risk_reports=adaptive_risk_reports,
        generated_at=timestamp,
    )
    timeline_events = _bound_events(raw_events, max_events=int(window.get("max_events") or max_events))
    anomaly_replay = build_anomaly_replay_summary(snapshots=snapshots, temporal_anomaly_reports=temporal_anomaly_reports, generated_at=timestamp)
    topology_replay = build_topology_replay_summary(topology_evolution_reports=topology_evolution_reports, generated_at=timestamp)
    baseline_replay = build_component_replay_summary("baselines", snapshots=snapshots, component_reports=baseline_decay_reports, generated_at=timestamp)
    service_replay = build_component_replay_summary("service_fingerprints", snapshots=snapshots, component_reports=service_fingerprint_reports, generated_at=timestamp)
    dns_replay = build_component_replay_summary("dns_destination_behavior", snapshots=snapshots, component_reports=dns_destination_behavior_reports, generated_at=timestamp)
    risk_replay = build_component_replay_summary("adaptive_risk", snapshots=snapshots, component_reports=adaptive_risk_reports, generated_at=timestamp)
    offline_review = build_offline_review_helper_records(
        timeline_events=timeline_events,
        anomaly_replay=anomaly_replay,
        topology_replay=topology_replay,
        generated_at=timestamp,
    )
    export = build_timeline_replay_export_summary(
        sequence_summary=sequence,
        timeline_events=timeline_events,
        anomaly_replay=anomaly_replay,
        topology_replay=topology_replay,
        generated_at=timestamp,
    )
    dashboard = build_timeline_replay_dashboard_record(
        sequence_summary=sequence,
        timeline_events=timeline_events,
        anomaly_replay=anomaly_replay,
        topology_replay=topology_replay,
        generated_at=timestamp,
    )
    api = build_timeline_replay_api_response(
        sequence_summary=sequence,
        timeline_events=timeline_events,
        anomaly_replay=anomaly_replay,
        topology_replay=topology_replay,
        baseline_replay=baseline_replay,
        service_replay=service_replay,
        dns_replay=dns_replay,
        risk_replay=risk_replay,
        offline_review=offline_review,
        dashboard=dashboard,
        export=export,
        generated_at=timestamp,
    )
    return {
        "record_type": "historical_timeline_replay",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "report_id": "historical-replay-" + _digest({"generated_at": timestamp, "events": [row.get("event_id") for row in timeline_events]})[:16],
        "generated_at": timestamp,
        "window": window,
        "snapshot_sequence": sequence,
        "timeline_events": timeline_events,
        "truncated_event_count": max(0, len(raw_events) - len(timeline_events)),
        "malformed_snapshots": malformed,
        "anomaly_replay_summary": anomaly_replay,
        "topology_replay_summary": topology_replay,
        "baseline_change_replay_summary": baseline_replay,
        "service_fingerprint_replay_summary": service_replay,
        "dns_destination_replay_summary": dns_replay,
        "adaptive_risk_replay_summary": risk_replay,
        "offline_review_helpers": offline_review,
        "dashboard_status": dashboard,
        "api_status": api,
        "export_summary": export,
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def build_bounded_timeline_events(
    *,
    snapshots: Iterable[dict[str, Any]],
    temporal_anomaly_reports: Iterable[dict[str, Any]] | None = None,
    topology_evolution_reports: Iterable[dict[str, Any]] | None = None,
    baseline_decay_reports: Iterable[dict[str, Any]] | None = None,
    service_fingerprint_reports: Iterable[dict[str, Any]] | None = None,
    dns_destination_behavior_reports: Iterable[dict[str, Any]] | None = None,
    adaptive_risk_reports: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    events = []
    for snapshot in _rows(snapshots):
        events.append(_snapshot_event(snapshot, generated_at=timestamp))
        rollups = (snapshot.get("payload") or {}).get("component_rollups") if isinstance(snapshot.get("payload"), dict) else {}
        if isinstance(rollups, dict):
            for name in COMPONENT_REPLAY_NAMES:
                if isinstance(rollups.get(name), dict):
                    events.append(_component_event(snapshot, name, rollups[name], generated_at=timestamp))
    for report in _rows(temporal_anomaly_reports):
        events.append(_report_event(report, "temporal_anomaly", generated_at=timestamp))
    for report in _rows(topology_evolution_reports):
        events.append(_report_event(report, "topology_evolution", generated_at=timestamp))
    for report in _rows(baseline_decay_reports):
        events.append(_report_event(report, "baseline_decay", generated_at=timestamp))
    for report in _rows(service_fingerprint_reports):
        events.append(_report_event(report, "service_fingerprint", generated_at=timestamp))
    for report in _rows(dns_destination_behavior_reports):
        events.append(_report_event(report, "dns_destination_behavior", generated_at=timestamp))
    for report in _rows(adaptive_risk_reports):
        events.append(_report_event(report, "adaptive_risk", generated_at=timestamp))
    for event in events:
        event["event_id"] = "historical-replay-event-" + _digest(
            {
                "event_type": event.get("event_type"),
                "occurred_at": event.get("occurred_at"),
                "source_ref": event.get("source_ref"),
                "component": event.get("component"),
            }
        )[:16]
    return sorted(events, key=lambda item: (str(item.get("occurred_at") or ""), _event_sort_order(str(item.get("event_type") or "")), str(item.get("event_id") or "")))


def build_anomaly_replay_summary(
    *,
    snapshots: Iterable[dict[str, Any]],
    temporal_anomaly_reports: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    snapshot_count = 0
    review_count = 0
    for snapshot in _rows(snapshots):
        rollup = _component_rollup(snapshot, "temporal_anomalies")
        if rollup:
            snapshot_count += int(rollup.get("record_count") or 0)
            review_count += int(rollup.get("recommended_review_count") or 0)
    reports = _rows(temporal_anomaly_reports)
    report_count = sum(int(((report.get("summary") or {}).get("anomaly_count") if isinstance(report.get("summary"), dict) else 0) or 0) for report in reports)
    return {
        "record_type": "anomaly_replay_summary",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "snapshot_anomaly_count": snapshot_count,
        "report_anomaly_count": report_count,
        "recommended_review_count": review_count,
        "total_anomaly_count": snapshot_count + report_count,
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def build_topology_replay_summary(
    *,
    topology_evolution_reports: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    reports = _rows(topology_evolution_reports)
    added = removed = dormant = stable = transient = 0
    for report in reports:
        drift = report.get("drift_summary") if isinstance(report.get("drift_summary"), dict) else {}
        relationship = report.get("relationship_summary") if isinstance(report.get("relationship_summary"), dict) else {}
        added += int(drift.get("added_relationship_count") or 0)
        removed += int(drift.get("removed_relationship_count") or 0)
        dormant += int(drift.get("dormant_return_count") or relationship.get("dormant_return_count") or 0)
        stable += int(relationship.get("stable_relationship_count") or 0)
        transient += int(relationship.get("transient_relationship_count") or 0)
    return {
        "record_type": "topology_replay_summary",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "topology_report_count": len(reports),
        "added_relationship_count": added,
        "removed_relationship_count": removed,
        "dormant_return_count": dormant,
        "stable_relationship_count": stable,
        "transient_relationship_count": transient,
        "review_recommended": bool(added or removed or dormant),
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def build_component_replay_summary(
    component: str,
    *,
    snapshots: Iterable[dict[str, Any]],
    component_reports: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    snapshot_records = 0
    review_count = 0
    states: dict[str, int] = {}
    for snapshot in _rows(snapshots):
        rollup = _component_rollup(snapshot, component)
        if not rollup:
            continue
        snapshot_records += int(rollup.get("record_count") or 0)
        review_count += int(rollup.get("recommended_review_count") or 0)
        state = str(rollup.get("state") or "unknown")
        states[state] = states.get(state, 0) + 1
    report_rows = _rows(component_reports)
    return {
        "record_type": "component_replay_summary",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "component": component,
        "snapshot_record_count": snapshot_records,
        "provided_report_count": len(report_rows),
        "recommended_review_count": review_count,
        "state_counts": dict(sorted(states.items())),
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def build_offline_review_helper_records(
    *,
    timeline_events: Iterable[dict[str, Any]],
    anomaly_replay: dict[str, Any],
    topology_replay: dict[str, Any],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    helpers = []
    if int(anomaly_replay.get("total_anomaly_count") or 0):
        helpers.append(_review_helper("review_anomaly_timeline", "medium", "Review anomaly replay windows for local behavior changes.", timestamp))
    if topology_replay.get("review_recommended"):
        helpers.append(_review_helper("review_topology_drift", "medium", "Review added, removed, or dormant-return topology relationships.", timestamp))
    if not helpers and list(timeline_events):
        helpers.append(_review_helper("continue_historical_monitoring", "info", "Replay timeline contains metadata events without review-required drift.", timestamp))
    if not helpers:
        helpers.append(_review_helper("provide_historical_snapshots", "low", "Add sanitized metadata snapshots before replay review.", timestamp))
    return helpers


def build_timeline_replay_dashboard_record(
    *,
    sequence_summary: dict[str, Any],
    timeline_events: Iterable[dict[str, Any]],
    anomaly_replay: dict[str, Any],
    topology_replay: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(timeline_events)
    review = bool(int(anomaly_replay.get("total_anomaly_count") or 0) or topology_replay.get("review_recommended"))
    return {
        "record_type": "historical_replay_dashboard",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "panel": "historical_replay",
        "generated_at": generated_at or _now(),
        "status": "review" if review else "empty" if not rows else "supported",
        "metrics": {
            "snapshot_count": int(sequence_summary.get("snapshot_count") or 0),
            "timeline_event_count": len(rows),
            "malformed_snapshot_count": int(sequence_summary.get("malformed_snapshot_count") or 0),
            "anomaly_count": int(anomaly_replay.get("total_anomaly_count") or 0),
            "topology_added_count": int(topology_replay.get("added_relationship_count") or 0),
            "topology_removed_count": int(topology_replay.get("removed_relationship_count") or 0),
        },
        "recommended_review": review,
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def build_timeline_replay_export_summary(
    *,
    sequence_summary: dict[str, Any],
    timeline_events: Iterable[dict[str, Any]],
    anomaly_replay: dict[str, Any],
    topology_replay: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = _rows(timeline_events)
    payload = {
        "record_type": "historical_replay_export_summary",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "record_counts": {
            "snapshots": int(sequence_summary.get("snapshot_count") or 0),
            "malformed_snapshots": int(sequence_summary.get("malformed_snapshot_count") or 0),
            "timeline_events": len(rows),
            "anomalies": int(anomaly_replay.get("total_anomaly_count") or 0),
            "topology_reports": int(topology_replay.get("topology_report_count") or 0),
        },
        "event_ids": [str(row.get("event_id") or "") for row in rows],
        "digest": "",
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }
    payload["digest"] = digest_payload({"record_counts": payload["record_counts"], "event_ids": payload["event_ids"]})
    return payload


def build_timeline_replay_api_response(
    *,
    sequence_summary: dict[str, Any],
    timeline_events: Iterable[dict[str, Any]],
    anomaly_replay: dict[str, Any],
    topology_replay: dict[str, Any],
    baseline_replay: dict[str, Any],
    service_replay: dict[str, Any],
    dns_replay: dict[str, Any],
    risk_replay: dict[str, Any],
    offline_review: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    export: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "historical_replay_api",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "snapshot_sequence": dict(sequence_summary),
        "timeline_events": _rows(timeline_events),
        "anomaly_replay_summary": dict(anomaly_replay),
        "topology_replay_summary": dict(topology_replay),
        "baseline_change_replay_summary": dict(baseline_replay),
        "service_fingerprint_replay_summary": dict(service_replay),
        "dns_destination_replay_summary": dict(dns_replay),
        "adaptive_risk_replay_summary": dict(risk_replay),
        "offline_review_helpers": _rows(offline_review),
        "dashboard": dict(dashboard),
        "export_summary": dict(export),
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def deterministic_historical_replay_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _snapshot_event(snapshot: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    metadata = snapshot.get("metadata_summary") if isinstance(snapshot.get("metadata_summary"), dict) else {}
    return {
        "record_type": "historical_timeline_event",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at,
        "event_type": "snapshot",
        "occurred_at": str(snapshot.get("snapshot_timestamp") or snapshot.get("generated_at") or ""),
        "source_ref": str(snapshot.get("snapshot_id") or ""),
        "component": "snapshot",
        "status": str(metadata.get("status") or "unknown"),
        "record_count": int(metadata.get("record_count") or 0),
        "recommended_review_count": int(metadata.get("recommendation_count") or 0),
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def _component_event(snapshot: dict[str, Any], component: str, rollup: dict[str, Any], *, generated_at: str) -> dict[str, Any]:
    return {
        "record_type": "historical_timeline_event",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at,
        "event_type": "component_rollup",
        "occurred_at": str(snapshot.get("snapshot_timestamp") or snapshot.get("generated_at") or ""),
        "source_ref": str(snapshot.get("snapshot_id") or ""),
        "component": component,
        "status": str(rollup.get("state") or "unknown"),
        "record_count": int(rollup.get("record_count") or 0),
        "recommended_review_count": int(rollup.get("recommended_review_count") or 0),
        "confidence": float(rollup.get("confidence") or 0.0),
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def _report_event(report: dict[str, Any], event_type: str, *, generated_at: str) -> dict[str, Any]:
    summary = report.get("summary") if isinstance(report.get("summary"), dict) else {}
    export = report.get("export_summary") if isinstance(report.get("export_summary"), dict) else {}
    record_counts = export.get("record_counts") if isinstance(export.get("record_counts"), dict) else {}
    count = sum(int(value or 0) for value in record_counts.values()) if record_counts else int(summary.get("record_count") or summary.get("anomaly_count") or 0)
    return {
        "record_type": "historical_timeline_event",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at,
        "event_type": event_type,
        "occurred_at": str(report.get("generated_at") or generated_at),
        "source_ref": str(report.get("report_id") or report.get("summary_id") or report.get("record_type") or event_type),
        "component": event_type,
        "status": str(report.get("status") or summary.get("status") or export.get("drift_status") or "available"),
        "record_count": int(count),
        "recommended_review_count": int(summary.get("recommended_review_count") or 0),
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }


def _component_rollup(snapshot: dict[str, Any], component: str) -> dict[str, Any]:
    payload = snapshot.get("payload") if isinstance(snapshot.get("payload"), dict) else {}
    rollups = payload.get("component_rollups") if isinstance(payload.get("component_rollups"), dict) else {}
    return dict(rollups.get(component) or {}) if isinstance(rollups.get(component), dict) else {}


def _event_sort_order(event_type: str) -> int:
    order = {
        "snapshot": 0,
        "component_rollup": 1,
        "temporal_anomaly": 2,
        "topology_evolution": 3,
        "baseline_decay": 4,
        "service_fingerprint": 5,
        "dns_destination_behavior": 6,
        "adaptive_risk": 7,
    }
    return order.get(event_type, 99)


def _bound_events(events: list[dict[str, Any]], *, max_events: int) -> list[dict[str, Any]]:
    limit = max(0, int(max_events))
    selected = events[:limit]
    dropped = max(0, len(events) - len(selected))
    for event in selected:
        event["bounded_retention_applied"] = dropped > 0
        event["dropped_event_count"] = dropped
    return selected


def _review_helper(action: str, severity: str, summary: str, generated_at: str) -> dict[str, Any]:
    record = {
        "record_type": "offline_replay_review_helper",
        "record_version": TIMELINE_REPLAY_RECORD_VERSION,
        "generated_at": generated_at,
        "action": action,
        "severity": severity,
        "summary": summary,
        "advisory_only": True,
        "enforcement_allowed": False,
        **TIMELINE_REPLAY_SAFETY_FLAGS,
    }
    record["helper_id"] = "offline-replay-helper-" + _digest({"action": action, "severity": severity, "summary": summary})[:16]
    return record


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(item) for item in value or [] if isinstance(item, dict)]


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
