from __future__ import annotations

from collections import Counter
from hashlib import sha256
from typing import Any, Iterable

from core_engine.visualization.timeline_models import (
    TIMELINE_CATEGORIES,
    TIMELINE_SEVERITIES,
    TimelineEvent,
    TimelineVisualizationError,
    TimelineWindow,
    make_timeline_event,
    normalize_timestamp,
    sanitize_reference,
)
from core_engine.visualization.topology_models import TopologyGraph, clamp_score, normalize_source_mode, now_timestamp


DEFAULT_MAX_TIMELINE_EVENTS = 256


def build_historical_timeline_window(
    *,
    topology_graphs: Iterable[TopologyGraph | dict[str, Any]] | None = None,
    flow_summaries: Iterable[dict[str, Any]] | None = None,
    asset_classifications: Iterable[dict[str, Any]] | None = None,
    drift_records: Iterable[dict[str, Any]] | None = None,
    policy_evaluations: Iterable[dict[str, Any]] | None = None,
    remediation_recommendations: Iterable[dict[str, Any]] | None = None,
    incident_candidates: Iterable[dict[str, Any]] | None = None,
    runtime_health_summaries: Iterable[dict[str, Any]] | None = None,
    start_timestamp: str | None = None,
    end_timestamp: str | None = None,
    generated_at: str | None = None,
    max_events: int = DEFAULT_MAX_TIMELINE_EVENTS,
) -> TimelineWindow:
    timestamp = generated_at or now_timestamp()
    collections = {
        "topology_graphs": topology_graphs,
        "flow_summaries": flow_summaries,
        "asset_classifications": asset_classifications,
        "drift_records": drift_records,
        "policy_evaluations": policy_evaluations,
        "remediation_recommendations": remediation_recommendations,
        "incident_candidates": incident_candidates,
        "runtime_health_summaries": runtime_health_summaries,
    }
    for name, value in collections.items():
        if value is not None and not _is_iterable(value):
            raise TimelineVisualizationError(f"{name} must be iterable")

    events: list[TimelineEvent] = []
    for graph in topology_graphs or []:
        events.extend(timeline_events_from_topology_graph(graph, generated_at=timestamp))
    for flow in flow_summaries or []:
        if isinstance(flow, dict):
            events.extend(timeline_events_from_flow(flow, generated_at=timestamp))
    for asset in asset_classifications or []:
        if isinstance(asset, dict):
            events.append(timeline_event_from_asset(asset, generated_at=timestamp))
    for drift in drift_records or []:
        if isinstance(drift, dict):
            events.append(timeline_event_from_drift(drift, generated_at=timestamp))
    for policy in policy_evaluations or []:
        if isinstance(policy, dict):
            events.append(timeline_event_from_policy(policy, generated_at=timestamp))
    for recommendation in remediation_recommendations or []:
        if isinstance(recommendation, dict):
            events.append(timeline_event_from_remediation(recommendation, generated_at=timestamp))
    for candidate in incident_candidates or []:
        if isinstance(candidate, dict):
            events.append(timeline_event_from_incident_candidate(candidate, generated_at=timestamp))
    for health in runtime_health_summaries or []:
        if isinstance(health, dict):
            event = timeline_event_from_runtime_health(health, generated_at=timestamp)
            if event:
                events.append(event)

    deduped = deduplicate_timeline_events(events)
    sorted_events = sort_timeline_events(deduped)
    bounded_events = sorted_events[: max(0, int(max_events))]
    start = normalize_timestamp(start_timestamp or (bounded_events[0].timestamp if bounded_events else timestamp))
    end = normalize_timestamp(end_timestamp or (bounded_events[-1].timestamp if bounded_events else timestamp))
    category_counts = count_event_categories(bounded_events)
    severity_counts = count_event_severities(bounded_events)
    return TimelineWindow(
        timeline_window_id="timeline-window-" + _digest({"start": start, "end": end, "events": [event.event_id for event in bounded_events], "max_events": max_events})[:16],
        start_timestamp=start,
        end_timestamp=end,
        event_count=len(bounded_events),
        category_counts=category_counts,
        severity_counts=severity_counts,
        events=bounded_events,
        bounded=True,
        max_events=max_events,
        export_safe=True,
    )


def timeline_events_from_topology_graph(graph: TopologyGraph | dict[str, Any], *, generated_at: str | None = None) -> list[TimelineEvent]:
    payload = graph.to_dict() if isinstance(graph, TopologyGraph) else graph
    if not isinstance(payload, dict):
        raise TimelineVisualizationError("topology graph must be an object")
    timestamp = payload.get("generated_at") or generated_at or now_timestamp()
    events: list[TimelineEvent] = []
    for node in payload.get("nodes") or []:
        if not isinstance(node, dict):
            continue
        events.append(
            make_timeline_event(
                event_type="node_seen",
                event_category="topology",
                timestamp=node.get("first_seen") or timestamp,
                source_reference=node.get("node_id"),
                summary=f"Topology node observed as {node.get('asset_category') or 'UNKNOWN'}",
                severity_level="info",
                confidence_score=node.get("confidence_score"),
                related_asset_references=[node.get("node_id")],
                source_mode=node.get("source_mode"),
            )
        )
    for edge in payload.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        events.append(
            make_timeline_event(
                event_type="topology_edge_seen",
                event_category="topology",
                timestamp=timestamp,
                source_reference=edge.get("source_node_id"),
                target_reference=edge.get("target_node_id"),
                summary="Topology edge observed from flow metadata",
                severity_level="info",
                confidence_score=edge.get("confidence_score"),
                related_flow_references=[edge.get("flow_reference")],
                related_topology_references=[edge.get("edge_id")],
                source_mode=edge.get("source_mode"),
            )
        )
    return events


def timeline_events_from_flow(flow: dict[str, Any], *, generated_at: str | None = None) -> list[TimelineEvent]:
    timestamp = _timestamp_from_record(flow, generated_at=generated_at)
    event_type = "flow_changed" if flow.get("drift_detected") or flow.get("state_transition") else "flow_started"
    severity = "medium" if event_type == "flow_changed" else "info"
    flow_ref = flow.get("flow_reference") or flow.get("flow_id") or flow.get("session_id")
    events = [
        make_timeline_event(
            event_type=event_type,
            event_category="flow",
            timestamp=timestamp,
            source_reference=flow.get("source_node_id") or flow.get("local_node_id") or flow.get("local_endpoint_class"),
            target_reference=flow.get("target_node_id") or flow.get("remote_node_id") or flow.get("remote_endpoint_class"),
            summary="Flow metadata added to historical timeline",
            severity_level=severity,
            confidence_score=flow.get("confidence_score") or flow.get("reconstruction_confidence"),
            related_flow_references=[flow_ref],
            source_mode=flow.get("source_mode") or flow.get("data_source"),
        )
    ]
    if flow.get("service_hint") or flow.get("service") or flow.get("service_attribution"):
        events.append(
            make_timeline_event(
                event_type="service_seen",
                event_category="service",
                timestamp=timestamp,
                source_reference=flow_ref,
                summary="Service metadata observed with flow",
                severity_level="info",
                confidence_score=flow.get("confidence_score"),
                related_flow_references=[flow_ref],
                source_mode=flow.get("source_mode") or flow.get("data_source"),
            )
        )
    return events


def timeline_event_from_asset(asset: dict[str, Any], *, generated_at: str | None = None) -> TimelineEvent:
    return make_timeline_event(
        event_type="asset_classified",
        event_category="asset",
        timestamp=_timestamp_from_record(asset, generated_at=generated_at),
        source_reference=asset.get("asset_reference") or asset.get("node_id") or asset.get("asset_id"),
        summary=f"Asset classified as {asset.get('asset_category') or asset.get('category') or 'UNKNOWN'}",
        severity_level="info",
        confidence_score=asset.get("confidence_score"),
        related_asset_references=[asset.get("asset_reference") or asset.get("node_id") or asset.get("asset_id")],
        source_mode=asset.get("source_mode") or asset.get("data_source"),
    )


def timeline_event_from_drift(drift: dict[str, Any], *, generated_at: str | None = None) -> TimelineEvent:
    severity = _severity_from_drift(drift.get("drift_severity") or drift.get("severity_level"))
    return make_timeline_event(
        event_type="drift_detected",
        event_category="drift",
        timestamp=_timestamp_from_record(drift, generated_at=generated_at),
        source_reference=drift.get("drift_id") or drift.get("baseline_reference"),
        target_reference=drift.get("current_reference"),
        summary="Behavioral drift recorded for visual review",
        severity_level=severity,
        confidence_score=drift.get("confidence_score"),
        related_topology_references=[drift.get("topology_reference")],
        related_flow_references=[drift.get("flow_reference")],
        source_mode=drift.get("source_mode") or drift.get("data_source"),
    )


def timeline_event_from_policy(policy: dict[str, Any], *, generated_at: str | None = None) -> TimelineEvent:
    matched = bool(policy.get("matched") or policy.get("evaluation_state") == "matched")
    return make_timeline_event(
        event_type="policy_matched" if matched else "unknown",
        event_category="policy",
        timestamp=_timestamp_from_record(policy, generated_at=generated_at),
        source_reference=policy.get("evaluation_id"),
        target_reference=policy.get("policy_id"),
        summary="Policy evaluation matched metadata context" if matched else "Policy evaluation recorded",
        severity_level=_severity_from_policy(policy),
        confidence_score=policy.get("confidence_score"),
        related_policy_references=[policy.get("policy_id")],
        source_mode=policy.get("source_mode") or policy.get("data_source"),
    )


def timeline_event_from_remediation(recommendation: dict[str, Any], *, generated_at: str | None = None) -> TimelineEvent:
    return make_timeline_event(
        event_type="remediation_recommended",
        event_category="remediation",
        timestamp=_timestamp_from_record(recommendation, generated_at=generated_at),
        source_reference=recommendation.get("recommendation_id"),
        summary="Remediation preview recommended for operator review",
        severity_level=_severity_from_risk(recommendation.get("risk_score")),
        confidence_score=recommendation.get("confidence_score"),
        related_flow_references=list(recommendation.get("flow_references") or []),
        related_topology_references=list(recommendation.get("topology_references") or []),
        related_policy_references=list(recommendation.get("policy_references") or []),
        source_mode=recommendation.get("source_mode") or recommendation.get("data_source"),
    )


def timeline_event_from_incident_candidate(candidate: dict[str, Any], *, generated_at: str | None = None) -> TimelineEvent:
    event_type = "guardrail_blocked" if candidate.get("candidate_state") == "blocked_by_safety" else "policy_matched"
    return make_timeline_event(
        event_type=event_type,
        event_category="guardrail" if event_type == "guardrail_blocked" else "policy",
        timestamp=_timestamp_from_record(candidate, generated_at=generated_at),
        source_reference=candidate.get("candidate_id"),
        summary="Incident candidate recorded for visual review",
        severity_level=str(candidate.get("severity_level") or "medium"),
        confidence_score=candidate.get("confidence_score"),
        related_flow_references=list(candidate.get("related_flow_references") or []),
        related_topology_references=list(candidate.get("related_topology_references") or []),
        related_policy_references=list(candidate.get("related_policy_ids") or []),
        source_mode=candidate.get("source_mode") or candidate.get("data_source"),
    )


def timeline_event_from_runtime_health(health: dict[str, Any], *, generated_at: str | None = None) -> TimelineEvent | None:
    state = str(health.get("health_state") or health.get("runtime_state") or health.get("state") or "unknown").lower()
    if state in {"healthy", "ok", "ready", "supported"}:
        return None
    return make_timeline_event(
        event_type="runtime_degraded",
        event_category="runtime",
        timestamp=_timestamp_from_record(health, generated_at=generated_at),
        source_reference=health.get("runtime_id") or health.get("component") or health.get("summary_id"),
        summary="Runtime health degraded for visual review",
        severity_level="medium" if state in {"degraded", "warning"} else "high",
        confidence_score=health.get("confidence_score") or 0.7,
        source_mode=health.get("source_mode") or health.get("data_source"),
    )


def deduplicate_timeline_events(events: Iterable[TimelineEvent]) -> list[TimelineEvent]:
    grouped: dict[str, TimelineEvent] = {}
    for event in events or []:
        if not isinstance(event, TimelineEvent):
            continue
        existing = grouped.get(event.event_id)
        if existing is None:
            grouped[event.event_id] = event
            continue
        grouped[event.event_id] = TimelineEvent(
            event_id=event.event_id,
            event_type=existing.event_type,
            event_category=existing.event_category,
            timestamp=min(existing.timestamp, event.timestamp),
            source_reference=existing.source_reference,
            target_reference=existing.target_reference,
            summary=existing.summary,
            severity_level=_higher_severity(existing.severity_level, event.severity_level),
            confidence_score=max(existing.confidence_score, event.confidence_score),
            related_flow_references=sorted(set(existing.related_flow_references + event.related_flow_references)),
            related_topology_references=sorted(set(existing.related_topology_references + event.related_topology_references)),
            related_asset_references=sorted(set(existing.related_asset_references + event.related_asset_references)),
            related_policy_references=sorted(set(existing.related_policy_references + event.related_policy_references)),
            source_mode=existing.source_mode,
            preview_only=True,
            destructive_action=False,
            advisory_notes=sorted(set(existing.advisory_notes + event.advisory_notes)),
        )
    return list(grouped.values())


def sort_timeline_events(events: Iterable[TimelineEvent]) -> list[TimelineEvent]:
    return sorted([event for event in events or [] if isinstance(event, TimelineEvent)], key=lambda event: (event.timestamp, event.event_id))


def count_event_categories(events: Iterable[TimelineEvent]) -> dict[str, int]:
    counter = Counter(event.event_category for event in events or [] if isinstance(event, TimelineEvent))
    return {category: int(counter.get(category, 0)) for category in sorted(TIMELINE_CATEGORIES) if counter.get(category, 0)}


def count_event_severities(events: Iterable[TimelineEvent]) -> dict[str, int]:
    counter = Counter(event.severity_level for event in events or [] if isinstance(event, TimelineEvent))
    return {severity: int(counter.get(severity, 0)) for severity in sorted(TIMELINE_SEVERITIES) if counter.get(severity, 0)}


def empty_timeline_window(*, generated_at: str | None = None, max_events: int = DEFAULT_MAX_TIMELINE_EVENTS) -> TimelineWindow:
    timestamp = generated_at or now_timestamp()
    return TimelineWindow(
        timeline_window_id="timeline-window-" + _digest({"empty": True, "timestamp": timestamp, "max_events": max_events})[:16],
        start_timestamp=timestamp,
        end_timestamp=timestamp,
        event_count=0,
        category_counts={},
        severity_counts={},
        events=[],
        bounded=True,
        max_events=max_events,
        export_safe=True,
    )


def _timestamp_from_record(record: dict[str, Any], *, generated_at: str | None = None) -> str:
    return normalize_timestamp(record.get("timestamp") or record.get("event_timestamp") or record.get("last_seen") or record.get("first_seen") or record.get("generated_at") or generated_at)


def _severity_from_drift(value: Any) -> str:
    severity = str(value or "medium").lower()
    if severity in {"major_drift", "high"}:
        return "high"
    if severity in {"moderate_drift", "medium"}:
        return "medium"
    if severity in {"minor_drift", "low"}:
        return "low"
    if severity in {"stable", "info"}:
        return "info"
    return "unknown"


def _severity_from_policy(policy: dict[str, Any]) -> str:
    severity = str(policy.get("severity") or policy.get("severity_level") or "info").lower()
    return severity if severity in {"info", "low", "medium", "high", "critical"} else "medium"


def _severity_from_risk(value: Any) -> str:
    score = clamp_score(value)
    if score >= 0.85:
        return "critical"
    if score >= 0.65:
        return "high"
    if score >= 0.4:
        return "medium"
    if score > 0.0:
        return "low"
    return "info"


def _higher_severity(left: str, right: str) -> str:
    order = {"unknown": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
    return left if order.get(left, 0) >= order.get(right, 0) else right


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()


def _is_iterable(value: Any) -> bool:
    try:
        iter(value)
    except TypeError:
        return False
    return not isinstance(value, (str, bytes))
