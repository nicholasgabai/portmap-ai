from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.scaling.bus_envelopes import (
    BUS_ENVELOPE_SAFETY_FLAGS,
    digest,
    normalize_source_mode,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)
from core_engine.scaling.retention_tiers import bounded_int


RELAY_SESSION_RECORD_VERSION = 1
RELAY_TYPES = {"local_preview", "regional_preview", "enterprise_preview", "hybrid_preview", "unknown"}
RELAY_SESSION_STATES = {"ready", "degraded", "unavailable", "unknown"}
RELAY_SESSION_SAFETY_FLAGS = {
    **BUS_ENVELOPE_SAFETY_FLAGS,
    "network_connection_opened": False,
    "telemetry_forwarded": False,
    "cloud_resource_created": False,
    "relay_infrastructure_created": False,
    "saas_control_plane_enabled": False,
    "runtime_behavior_modified": False,
    "telemetry_routing_modified": False,
}


@dataclass(frozen=True)
class RelaySessionRecord:
    relay_session_id: str
    relay_name: str
    relay_type: str
    tenant_scope: str
    routing_scope: str
    estimated_nodes: int
    estimated_topics: int
    source_modes: list[str] = field(default_factory=list)
    relay_state: str = "unknown"
    advisory_notes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "relay_session",
            "record_version": RELAY_SESSION_RECORD_VERSION,
            "relay_session_id": sanitize_reference(self.relay_session_id),
            "relay_name": sanitize_text(self.relay_name) or "Unnamed relay session",
            "relay_type": normalize_relay_type(self.relay_type),
            "tenant_scope": sanitize_reference(self.tenant_scope) or "single_tenant_preview",
            "routing_scope": sanitize_reference(self.routing_scope) or "local_preview",
            "estimated_nodes": bounded_relay_count(self.estimated_nodes),
            "estimated_topics": bounded_relay_count(self.estimated_topics),
            "source_modes": normalize_relay_source_modes(self.source_modes),
            "relay_state": normalize_relay_session_state(self.relay_state),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            "preview_only": True,
            "destructive_action": False,
            "export_safe": True,
            **RELAY_SESSION_SAFETY_FLAGS,
        }


def build_relay_session(
    *,
    relay_session_id: Any = "",
    relay_name: Any = "",
    relay_type: Any = "unknown",
    tenant_scope: Any = "single_tenant_preview",
    routing_scope: Any = "local_preview",
    estimated_nodes: Any = 0,
    estimated_topics: Any = 0,
    source_modes: Iterable[Any] | None = None,
    relay_state: Any = "unknown",
    advisory_notes: list[Any] | None = None,
) -> RelaySessionRecord:
    normalized_type = normalize_relay_type(relay_type)
    normalized_state = normalize_relay_session_state(relay_state)
    modes = normalize_relay_source_modes(source_modes or ["unknown"])
    notes = [sanitize_text(note) for note in advisory_notes or [] if sanitize_text(note)]
    if normalized_type != "local_preview":
        notes.append("relay scope is preview-only; no cloud resources or network connections are created")
    if bounded_relay_count(estimated_nodes) == 0:
        notes.append("relay session has no estimated node capacity")
    notes.append("relay session is metadata-only; no telemetry forwarding is performed")
    safe_name = sanitize_text(relay_name) or f"{normalized_type} relay session"
    safe_id = sanitize_reference(relay_session_id)
    if not safe_id:
        safe_id = "relay-session-" + digest(
            {
                "relay_name": safe_name,
                "relay_type": normalized_type,
                "tenant_scope": sanitize_reference(tenant_scope),
                "routing_scope": sanitize_reference(routing_scope),
                "estimated_nodes": bounded_relay_count(estimated_nodes),
                "estimated_topics": bounded_relay_count(estimated_topics),
                "source_modes": modes,
                "relay_state": normalized_state,
            }
        )[:16]
    return RelaySessionRecord(
        relay_session_id=safe_id,
        relay_name=safe_name,
        relay_type=normalized_type,
        tenant_scope=sanitize_reference(tenant_scope) or "single_tenant_preview",
        routing_scope=sanitize_reference(routing_scope) or "local_preview",
        estimated_nodes=bounded_relay_count(estimated_nodes),
        estimated_topics=bounded_relay_count(estimated_topics),
        source_modes=modes,
        relay_state=normalized_state,
        advisory_notes=notes,
        preview_only=True,
        destructive_action=False,
    )


def normalize_relay_session(value: Any) -> RelaySessionRecord:
    if isinstance(value, RelaySessionRecord):
        return value
    if not isinstance(value, dict):
        return build_relay_session(
            relay_name="Invalid relay session",
            relay_type="unknown",
            relay_state="unknown",
            advisory_notes=["invalid relay session generated from malformed input"],
        )
    try:
        return build_relay_session(
            relay_session_id=value.get("relay_session_id", value.get("session_id", "")),
            relay_name=value.get("relay_name", value.get("name", "")),
            relay_type=value.get("relay_type", value.get("type", "unknown")),
            tenant_scope=value.get("tenant_scope", "single_tenant_preview"),
            routing_scope=value.get("routing_scope", "local_preview"),
            estimated_nodes=value.get("estimated_nodes", 0),
            estimated_topics=value.get("estimated_topics", 0),
            source_modes=value.get("source_modes") if isinstance(value.get("source_modes"), list) else [value.get("source_mode", "unknown")],
            relay_state=value.get("relay_state", value.get("state", "unknown")),
            advisory_notes=value.get("advisory_notes") if isinstance(value.get("advisory_notes"), list) else None,
        )
    except Exception as exc:
        return build_relay_session(relay_name="Invalid relay session", relay_type="unknown", advisory_notes=[str(exc)])


def default_relay_sessions(*, source_mode: Any = "unknown") -> list[RelaySessionRecord]:
    mode = normalize_source_mode(source_mode)
    return [
        build_relay_session(
            relay_name="Local relay readiness preview",
            relay_type="local_preview",
            tenant_scope="single_tenant_preview",
            routing_scope="local_cluster_preview",
            estimated_nodes=4,
            estimated_topics=6,
            source_modes=[mode],
            relay_state="ready",
        )
    ]


def relay_session_summary(sessions: Iterable[RelaySessionRecord | dict[str, Any] | Any]) -> dict[str, Any]:
    rows = [normalize_relay_session(session).to_dict() for session in list(sessions or [])]
    type_counts: dict[str, int] = {}
    state_counts: dict[str, int] = {}
    source_modes: set[str] = set()
    for row in rows:
        type_counts[row["relay_type"]] = type_counts.get(row["relay_type"], 0) + 1
        state_counts[row["relay_state"]] = state_counts.get(row["relay_state"], 0) + 1
        source_modes.update(row.get("source_modes", []))
    return {
        "session_count": len(rows),
        "type_counts": dict(sorted(type_counts.items())),
        "state_counts": dict(sorted(state_counts.items())),
        "estimated_nodes": sum(row["estimated_nodes"] for row in rows),
        "estimated_topics": sum(row["estimated_topics"] for row in rows),
        "source_modes": sorted(source_modes) or ["unknown"],
        "preview_only": True,
        "destructive_action": False,
    }


def normalize_relay_type(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in RELAY_TYPES else "unknown"


def normalize_relay_session_state(value: Any) -> str:
    safe_value = sanitize_token(value).lower()
    return safe_value if safe_value in RELAY_SESSION_STATES else "unknown"


def normalize_relay_source_modes(values: Iterable[Any]) -> list[str]:
    modes = {normalize_source_mode(value) for value in values}
    modes = {mode for mode in modes if mode}
    return sorted(modes) or ["unknown"]


def bounded_relay_count(value: Any) -> int:
    return min(100_000, bounded_int(value))


def deterministic_relay_session_json(record: RelaySessionRecord | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, RelaySessionRecord) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


__all__ = [
    "RELAY_SESSION_STATES",
    "RELAY_TYPES",
    "RelaySessionRecord",
    "bounded_relay_count",
    "build_relay_session",
    "default_relay_sessions",
    "deterministic_relay_session_json",
    "normalize_relay_session",
    "normalize_relay_session_state",
    "normalize_relay_source_modes",
    "normalize_relay_type",
    "relay_session_summary",
]
