from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    DELIVERY_STATES,
    PRIORITIES,
    TELEMETRY_BUS_TOPICS,
    TelemetryBusEnvelope,
    build_bus_envelope,
    deterministic_envelope_json,
    digest,
    normalize_delivery_state,
    normalize_envelope,
    normalize_priority,
    normalize_source_mode,
    normalize_topic,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
)


TELEMETRY_BUS_RECORD_VERSION = 1
BUS_STATES = {"ready", "degraded", "empty", "bounded", "unavailable", "unknown"}
TELEMETRY_BUS_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "bounded_queue": True,
    "fanout_preview_only": True,
    "live_forwarding_enabled": False,
}


@dataclass(frozen=True)
class TelemetryBusSummary:
    bus_id: str
    generated_at: str
    bus_state: str
    queue_depth: int
    max_queue_depth: int
    dropped_count: int
    retry_pending_count: int
    topic_counts: dict[str, int] = field(default_factory=dict)
    priority_counts: dict[str, int] = field(default_factory=dict)
    delivery_state_counts: dict[str, int] = field(default_factory=dict)
    fanout_ready: bool = False
    external_broker_required: bool = False
    envelopes: list[dict[str, Any]] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    export_safe: bool = True
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "telemetry_bus_summary",
            "record_version": TELEMETRY_BUS_RECORD_VERSION,
            "bus_id": sanitize_reference(self.bus_id),
            "generated_at": str(self.generated_at or ""),
            "bus_state": normalize_bus_state(self.bus_state),
            "queue_depth": max(0, int(self.queue_depth or 0)),
            "max_queue_depth": max(0, int(self.max_queue_depth or 0)),
            "dropped_count": max(0, int(self.dropped_count or 0)),
            "retry_pending_count": max(0, int(self.retry_pending_count or 0)),
            "topic_counts": _ordered_counts(self.topic_counts, TELEMETRY_BUS_TOPICS),
            "priority_counts": _ordered_counts(self.priority_counts, PRIORITIES),
            "delivery_state_counts": _ordered_counts(self.delivery_state_counts, DELIVERY_STATES),
            "fanout_ready": bool(self.fanout_ready),
            "external_broker_required": False,
            "envelopes": list(self.envelopes),
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **TELEMETRY_BUS_SAFETY_FLAGS,
        }


def build_telemetry_bus_summary(
    envelopes: Iterable[TelemetryBusEnvelope | dict[str, Any] | Any] | None = None,
    *,
    max_queue_depth: int = 100,
    generated_at: str | None = None,
    bus_id: str | None = None,
    fanout_targets: Iterable[Any] | None = None,
    advisory_notes: list[Any] | None = None,
) -> TelemetryBusSummary:
    timestamp = generated_at or now_timestamp()
    bound = max(0, int(max_queue_depth or 0))
    normalized = [normalize_envelope(item, generated_at=timestamp) for item in list(envelopes or [])]
    dropped_by_bound = max(0, len(normalized) - bound)
    kept = normalized[:bound] if bound else []
    if dropped_by_bound:
        kept = [
            *kept,
            build_bus_envelope(
                topic="unknown",
                message_type="queue_bound",
                source_node="local-bus",
                target_scope="local",
                source_mode="unknown",
                created_at=timestamp,
                priority="normal",
                retry_count=0,
                max_retries=0,
                backoff_seconds=0,
                payload_summary={"dropped_count": dropped_by_bound, "raw_payload_stored": False},
                payload_reference="queue-bound",
                delivery_state="dropped_by_bound",
                advisory_notes=["queue bound preview dropped excess envelope metadata"],
            ),
        ]
    envelope_dicts = [envelope.to_dict() for envelope in kept]
    topic_counts = Counter(row["topic"] for row in envelope_dicts)
    priority_counts = Counter(row["priority"] for row in envelope_dicts)
    delivery_counts = Counter(row["delivery_state"] for row in envelope_dicts)
    retry_pending_count = delivery_counts.get("retry_pending", 0) + sum(
        1 for row in envelope_dicts if row.get("retry_count", 0) > 0 and row.get("delivery_state") == "queued"
    )
    fanout_ready = _fanout_ready(envelope_dicts, fanout_targets)
    state = _bus_state(envelope_dicts, dropped_by_bound=dropped_by_bound, max_queue_depth=bound)
    notes = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    notes.append("in-memory telemetry bus summary; no external broker or forwarding")
    summary_id = bus_id or "telemetry-bus-" + digest(
        {
            "generated_at": timestamp,
            "max_queue_depth": bound,
            "envelopes": [row.get("envelope_id") for row in envelope_dicts],
            "dropped_count": dropped_by_bound,
        }
    )[:16]
    return TelemetryBusSummary(
        bus_id=summary_id,
        generated_at=timestamp,
        bus_state=state,
        queue_depth=len(envelope_dicts),
        max_queue_depth=bound,
        dropped_count=dropped_by_bound,
        retry_pending_count=retry_pending_count,
        topic_counts=dict(topic_counts),
        priority_counts=dict(priority_counts),
        delivery_state_counts=dict(delivery_counts),
        fanout_ready=fanout_ready,
        external_broker_required=False,
        envelopes=envelope_dicts,
        preview_only=True,
        destructive_action=False,
        export_safe=True,
        advisory_notes=notes,
    )


def empty_telemetry_bus_summary(*, generated_at: str | None = None, max_queue_depth: int = 100) -> TelemetryBusSummary:
    return build_telemetry_bus_summary([], generated_at=generated_at, max_queue_depth=max_queue_depth)


def normalize_bus_state(value: Any) -> str:
    safe_value = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return safe_value if safe_value in BUS_STATES else "unknown"


def deterministic_bus_json(summary: TelemetryBusSummary | dict[str, Any]) -> str:
    payload = summary.to_dict() if isinstance(summary, TelemetryBusSummary) else summary
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _bus_state(envelopes: list[dict[str, Any]], *, dropped_by_bound: int, max_queue_depth: int) -> str:
    if not envelopes and max_queue_depth <= 0:
        return "unavailable"
    if not envelopes:
        return "empty"
    if any(row.get("delivery_state") == "invalid" for row in envelopes):
        return "degraded"
    if dropped_by_bound:
        return "bounded"
    if any(row.get("delivery_state") == "retry_pending" for row in envelopes):
        return "degraded"
    return "ready"


def _fanout_ready(envelopes: list[dict[str, Any]], targets: Iterable[Any] | None) -> bool:
    target_count = len([target for target in targets or [] if sanitize_reference(target)])
    if target_count <= 0:
        return False
    return bool(envelopes) and all(row.get("delivery_state") in {"queued", "delivered_preview", "retry_pending"} for row in envelopes)


def _ordered_counts(counts: dict[str, int], allowed: set[str]) -> dict[str, int]:
    normalized: Counter[str] = Counter()
    for key, value in counts.items():
        if allowed is TELEMETRY_BUS_TOPICS:
            normalized[normalize_topic(key)] += max(0, int(value or 0))
        elif allowed is PRIORITIES:
            normalized[normalize_priority(key)] += max(0, int(value or 0))
        elif allowed is DELIVERY_STATES:
            normalized[normalize_delivery_state(key)] += max(0, int(value or 0))
        else:
            normalized[str(key)] += max(0, int(value or 0))
    return {key: normalized[key] for key in sorted(normalized) if normalized[key]}


def envelope_from_summary(summary: dict[str, Any], *, topic: str = "unknown", generated_at: str | None = None) -> TelemetryBusEnvelope:
    return build_bus_envelope(
        topic=topic,
        message_type=summary.get("record_type", "summary") if isinstance(summary, dict) else "summary",
        source_node=summary.get("node_reference", summary.get("node_id", "unknown")) if isinstance(summary, dict) else "unknown",
        target_scope="local",
        source_mode=summary.get("source_mode", summary.get("data_source", "unknown")) if isinstance(summary, dict) else "unknown",
        created_at=summary.get("generated_at", generated_at) if isinstance(summary, dict) else generated_at,
        payload=summary,
        payload_reference=summary.get("summary_id", summary.get("record_id", "")) if isinstance(summary, dict) else "",
    )


__all__ = [
    "TelemetryBusSummary",
    "build_telemetry_bus_summary",
    "deterministic_bus_json",
    "empty_telemetry_bus_summary",
    "envelope_from_summary",
    "normalize_bus_state",
    "deterministic_envelope_json",
]
