from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


BUS_ENVELOPE_RECORD_VERSION = 1
TELEMETRY_BUS_TOPICS = {
    "worker_telemetry",
    "flow_summary",
    "topology_update",
    "policy_evaluation",
    "remediation_preview",
    "visualization_summary",
    "intelligence_summary",
    "runtime_health",
    "audit_event",
    "unknown",
}
DELIVERY_STATES = {
    "queued",
    "delivered_preview",
    "retry_pending",
    "dropped_by_bound",
    "invalid",
    "unknown",
}
PRIORITIES = {"low", "normal", "high", "critical", "unknown"}
SOURCE_MODES = {"live", "simulated", "fixture", "replay", "unknown"}
BUS_ENVELOPE_SAFETY_FLAGS = {
    "metadata_only": True,
    "external_broker_required": False,
    "network_forwarded": False,
    "filesystem_written": False,
    "raw_payload_stored": False,
    "private_identifier_exported": False,
    "enforcement_action_created": False,
    "preview_only": True,
    "destructive_action": False,
    "export_safe": True,
}


class TelemetryBusEnvelopeError(ValueError):
    """Raised when a telemetry bus envelope cannot be built safely."""


@dataclass(frozen=True)
class TelemetryBusEnvelope:
    envelope_id: str
    topic: str
    message_type: str
    source_node: str
    target_scope: str
    source_mode: str
    created_at: str
    priority: str
    retry_count: int
    max_retries: int
    backoff_seconds: float
    payload_summary: dict[str, Any] = field(default_factory=dict)
    payload_reference: str = ""
    delivery_state: str = "queued"
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        mode = normalize_source_mode(self.source_mode)
        return {
            "record_type": "telemetry_bus_envelope",
            "record_version": BUS_ENVELOPE_RECORD_VERSION,
            "envelope_id": sanitize_reference(self.envelope_id),
            "topic": normalize_topic(self.topic),
            "message_type": sanitize_token(self.message_type) or "unknown",
            "source_node": sanitize_reference(self.source_node),
            "target_scope": sanitize_reference(self.target_scope) or "local",
            "source_mode": mode,
            "data_source": mode,
            "created_at": str(self.created_at or ""),
            "priority": normalize_priority(self.priority),
            "retry_count": max(0, int(self.retry_count or 0)),
            "max_retries": max(0, int(self.max_retries or 0)),
            "backoff_seconds": round(max(0.0, float(self.backoff_seconds or 0.0)), 3),
            "payload_summary": sanitize_payload_summary(self.payload_summary),
            "payload_reference": sanitize_reference(self.payload_reference),
            "delivery_state": normalize_delivery_state(self.delivery_state),
            "preview_only": True,
            "destructive_action": False,
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **BUS_ENVELOPE_SAFETY_FLAGS,
        }


def build_bus_envelope(
    *,
    topic: Any = "unknown",
    message_type: Any = "unknown",
    source_node: Any = "unknown",
    target_scope: Any = "local",
    source_mode: Any = "unknown",
    created_at: Any = None,
    priority: Any = "normal",
    retry_count: Any = 0,
    max_retries: Any = 3,
    backoff_seconds: Any = 0.0,
    payload: Any = None,
    payload_summary: dict[str, Any] | None = None,
    payload_reference: Any = "",
    delivery_state: Any = "queued",
    advisory_notes: list[Any] | None = None,
) -> TelemetryBusEnvelope:
    normalized_topic = normalize_topic(topic)
    normalized_state = normalize_delivery_state(delivery_state)
    timestamp = str(created_at or now_timestamp())
    safe_payload_summary = sanitize_payload_summary(payload_summary if payload_summary is not None else summarize_payload(payload))
    reference = sanitize_reference(payload_reference) or "payload-" + digest(safe_payload_summary)[:16]
    envelope_id = "bus-env-" + digest(
        {
            "topic": normalized_topic,
            "message_type": sanitize_token(message_type) or "unknown",
            "source_node": sanitize_reference(source_node),
            "target_scope": sanitize_reference(target_scope) or "local",
            "created_at": timestamp,
            "payload_reference": reference,
        }
    )[:16]
    notes = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    notes.append("metadata-only telemetry bus envelope; no forwarding performed")
    return TelemetryBusEnvelope(
        envelope_id=envelope_id,
        topic=normalized_topic,
        message_type=sanitize_token(message_type) or "unknown",
        source_node=sanitize_reference(source_node) or "unknown",
        target_scope=sanitize_reference(target_scope) or "local",
        source_mode=normalize_source_mode(source_mode),
        created_at=timestamp,
        priority=normalize_priority(priority),
        retry_count=safe_int(retry_count),
        max_retries=safe_int(max_retries),
        backoff_seconds=safe_float(backoff_seconds),
        payload_summary=safe_payload_summary,
        payload_reference=reference,
        delivery_state=normalized_state,
        preview_only=True,
        destructive_action=False,
        advisory_notes=notes,
    )


def invalid_bus_envelope(reason: Any = "malformed input", *, created_at: Any = None) -> TelemetryBusEnvelope:
    return build_bus_envelope(
        topic="unknown",
        message_type="invalid",
        source_node="unknown",
        target_scope="local",
        source_mode="unknown",
        created_at=created_at,
        priority="unknown",
        retry_count=0,
        max_retries=0,
        backoff_seconds=0,
        payload_summary={"state": "invalid", "reason": sanitize_text(reason)},
        payload_reference="invalid",
        delivery_state="invalid",
        advisory_notes=["invalid envelope generated from malformed input"],
    )


def normalize_envelope(value: Any, *, generated_at: str | None = None) -> TelemetryBusEnvelope:
    if isinstance(value, TelemetryBusEnvelope):
        return value
    if not isinstance(value, dict):
        return invalid_bus_envelope("envelope input must be a dictionary", created_at=generated_at)
    try:
        return build_bus_envelope(
            topic=value.get("topic", "unknown"),
            message_type=value.get("message_type", value.get("record_type", "unknown")),
            source_node=value.get("source_node", value.get("node_id", "unknown")),
            target_scope=value.get("target_scope", "local"),
            source_mode=value.get("source_mode", value.get("data_source", "unknown")),
            created_at=value.get("created_at") or value.get("generated_at") or value.get("timestamp") or generated_at,
            priority=value.get("priority", "normal"),
            retry_count=value.get("retry_count", 0),
            max_retries=value.get("max_retries", 3),
            backoff_seconds=value.get("backoff_seconds", 0),
            payload=value.get("payload"),
            payload_summary=value.get("payload_summary") if isinstance(value.get("payload_summary"), dict) else None,
            payload_reference=value.get("payload_reference", value.get("record_id", "")),
            delivery_state=value.get("delivery_state", "queued"),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return invalid_bus_envelope(str(exc), created_at=generated_at)


def normalize_topic(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in TELEMETRY_BUS_TOPICS else "unknown"


def normalize_delivery_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in DELIVERY_STATES else "unknown"


def normalize_priority(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    if safe_value in {"medium", "default"}:
        return "normal"
    return safe_value if safe_value in PRIORITIES else "unknown"


def normalize_source_mode(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in SOURCE_MODES else "unknown"


def summarize_payload(payload: Any) -> dict[str, Any]:
    if payload is None:
        return {"payload_type": "none", "field_count": 0, "payload_digest": digest(None)[:16]}
    if isinstance(payload, dict):
        keys = sorted(sanitize_token(key) for key in payload.keys() if sanitize_token(key))
        return {
            "payload_type": "dict",
            "field_count": len(keys),
            "field_names": keys[:16],
            "payload_digest": digest(_shape(payload))[:16],
        }
    if isinstance(payload, (list, tuple, set)):
        return {
            "payload_type": "list",
            "item_count": len(payload),
            "payload_digest": digest([_shape(item) for item in list(payload)[:32]])[:16],
        }
    return {"payload_type": type(payload).__name__, "payload_digest": digest(str(type(payload)))[:16]}


def sanitize_payload_summary(summary: Any) -> dict[str, Any]:
    if not isinstance(summary, dict):
        return summarize_payload(summary)
    safe: dict[str, Any] = {}
    for key, value in summary.items():
        safe_key = sanitize_token(key)
        if not safe_key:
            continue
        if safe_key.lower() in {"payload", "raw_payload", "body", "content", "secret", "credential"}:
            safe[safe_key] = "redacted-" + digest(value)[:12]
        elif isinstance(value, dict):
            safe[safe_key] = sanitize_payload_summary(value)
        elif isinstance(value, (list, tuple, set)):
            safe[safe_key] = [sanitize_text(item) for item in list(value)[:16]]
        elif isinstance(value, (int, float, bool)) or value is None:
            safe[safe_key] = value
        else:
            safe[safe_key] = sanitize_text(value)
    safe.setdefault("raw_payload_stored", False)
    return safe


def sanitize_reference(value: Any) -> str:
    safe_value = sanitize_token(value)
    if not safe_value:
        return ""
    if looks_private(str(value)):
        return "ref-" + digest(str(value))[:12]
    return safe_value[:96]


def sanitize_token(value: Any) -> str:
    if value is None:
        return ""
    safe_value = re.sub(r"[^A-Za-z0-9_.:-]+", "-", str(value).strip())
    safe_value = re.sub(r"-{2,}", "-", safe_value).strip("-")
    return safe_value[:128]


def sanitize_text(value: Any) -> str:
    if value is None:
        return ""
    text = re.sub(r"[\r\n\t]+", " ", str(value).strip())
    if looks_private(text):
        return "redacted-" + digest(text)[:12]
    return text[:180]


def looks_private(value: str) -> bool:
    text = str(value)
    if re.search(r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text):
        return True
    if re.search(r"\b172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}\b", text):
        return True
    if re.search(r"\b192\.168\.\d{1,3}\.\d{1,3}\b", text):
        return True
    if re.search(r"\b[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}\b", text):
        return True
    if "@" in text:
        return True
    return False


def safe_int(value: Any) -> int:
    try:
        return max(0, int(value))
    except Exception:
        return 0


def safe_float(value: Any) -> float:
    try:
        return max(0.0, float(value))
    except Exception:
        return 0.0


def now_timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")).hexdigest()


def deterministic_envelope_json(record: TelemetryBusEnvelope | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, TelemetryBusEnvelope) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {sanitize_token(key): _shape(item) for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))}
    if isinstance(value, (list, tuple, set)):
        return [_shape(item) for item in list(value)[:32]]
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    return type(value).__name__
