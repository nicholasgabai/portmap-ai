from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.process_attribution import normalize_source_mode


FLOW_SESSION_RECORD_VERSION = 1
FLOW_DIRECTIONS = {"inbound", "outbound", "local_loopback", "unknown_direction"}
FLOW_SESSION_STATES = {"active", "transient", "recurring", "dormant", "unknown"}
FLOW_SAFETY_FLAGS = {
    "metadata_only": True,
    "raw_payload_stored": False,
    "payload_bytes_stored": 0,
    "packet_payload_inspected": False,
    "deep_packet_inspection": False,
    "pcap_generated": False,
    "credential_material_stored": False,
    "local_only": True,
    "advisory_only": True,
    "automatic_changes": False,
}


class FlowSessionTrackingError(ValueError):
    """Raised when bidirectional flow session records are malformed."""


def build_session_tracking_record(
    observation: dict[str, Any],
    *,
    previous_observations: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    if not isinstance(observation, dict):
        raise FlowSessionTrackingError("observation must be an object")
    timestamp = generated_at or _now()
    local_port = _safe_port(observation.get("local_port") or observation.get("port"))
    remote_port = _safe_port(observation.get("remote_port"))
    protocol = _normalize_protocol(observation.get("protocol") or observation.get("transport") or observation.get("transport_protocol"))
    local_class = _endpoint_class(observation.get("local_endpoint_class") or observation.get("local_address_class") or "unknown")
    remote_class = _endpoint_class(observation.get("remote_endpoint_class") or observation.get("remote_address_class") or "unknown")
    direction = infer_flow_direction(
        local_endpoint_class=local_class,
        remote_endpoint_class=remote_class,
        local_port=local_port,
        remote_port=remote_port,
        explicit_direction=observation.get("flow_direction") or observation.get("direction"),
    )
    observed_timestamps = _observed_timestamps(observation, generated_at=timestamp)
    previous_count = _matching_previous_count(observation, previous_observations)
    state = classify_session_state(
        transport_state=str(observation.get("transport_state") or observation.get("status") or "unknown"),
        observation_count=max(1, int(observation.get("observation_count") or 1)),
        previous_count=previous_count,
        explicit_state=observation.get("session_state"),
    )
    process = _safe_attribution(observation.get("process_attribution") or observation.get("process") or observation.get("program"))
    service = _safe_attribution(observation.get("service_attribution") or observation.get("service") or observation.get("service_name"))
    mode = normalize_source_mode(str(observation.get("source_mode") or observation.get("data_source") or "unknown"))
    record = {
        "record_type": "normalized_flow_session",
        "record_version": FLOW_SESSION_RECORD_VERSION,
        "session_id": "",
        "flow_direction": direction,
        "local_endpoint_class": local_class,
        "remote_endpoint_class": remote_class,
        "local_port": local_port,
        "remote_port": remote_port,
        "protocol": protocol,
        "transport_state": _transport_state(observation.get("transport_state") or observation.get("status")),
        "process_attribution": process,
        "service_attribution": service,
        "source_mode": mode,
        "session_state": state,
        "observed_timestamps": observed_timestamps,
        "session_duration_preview": _duration_preview(observed_timestamps),
        "confidence_score": 0.0,
        "advisory_notes": _advisory_notes(direction=direction, state=state, source_mode=mode),
        **FLOW_SAFETY_FLAGS,
    }
    record["confidence_score"] = score_session_confidence(record, previous_count=previous_count)
    record["session_id"] = "flow-session-" + _digest(
        {
            "direction": record["flow_direction"],
            "local_endpoint_class": record["local_endpoint_class"],
            "remote_endpoint_class": record["remote_endpoint_class"],
            "local_port": record["local_port"],
            "remote_port": record["remote_port"],
            "protocol": record["protocol"],
            "transport_state": record["transport_state"],
            "process_attribution": record["process_attribution"],
            "service_attribution": record["service_attribution"],
            "source_mode": record["source_mode"],
        }
    )[:16]
    return record


def normalize_socket_observations(
    observations: Iterable[dict[str, Any]],
    *,
    previous_observations: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    records = [
        build_session_tracking_record(row, previous_observations=previous_observations, generated_at=generated_at)
        for row in observations or []
        if isinstance(row, dict)
    ]
    deduped: dict[str, dict[str, Any]] = {}
    for record in records:
        existing = deduped.get(record["session_id"])
        if existing is None:
            deduped[record["session_id"]] = record
            continue
        merged = dict(existing)
        timestamps = sorted(set(existing.get("observed_timestamps") or []) | set(record.get("observed_timestamps") or []))
        merged["observed_timestamps"] = timestamps
        merged["session_duration_preview"] = _duration_preview(timestamps)
        merged["confidence_score"] = max(float(existing.get("confidence_score") or 0.0), float(record.get("confidence_score") or 0.0))
        deduped[record["session_id"]] = merged
    return sorted(deduped.values(), key=lambda item: (str(item.get("session_id") or ""), str(item.get("source_mode") or "")))


def infer_flow_direction(
    *,
    local_endpoint_class: str,
    remote_endpoint_class: str,
    local_port: int | None,
    remote_port: int | None,
    explicit_direction: Any = None,
) -> str:
    explicit = str(explicit_direction or "").lower()
    if explicit in FLOW_DIRECTIONS:
        return explicit
    local_class = _endpoint_class(local_endpoint_class)
    remote_class = _endpoint_class(remote_endpoint_class)
    if local_class == "loopback" and remote_class == "loopback":
        return "local_loopback"
    if local_port is None or remote_port is None:
        return "unknown_direction"
    local_service = local_port < 49152
    remote_service = remote_port < 49152
    if local_service and not remote_service:
        return "inbound"
    if remote_service and not local_service:
        return "outbound"
    if remote_class in {"public", "remote", "external"} and local_class in {"local", "private", "edge", "loopback"}:
        return "outbound"
    if local_class in {"local", "private", "edge"} and remote_class in {"unknown", "remote", "external", "public"}:
        return "inbound" if local_service else "unknown_direction"
    return "unknown_direction"


def classify_session_state(
    *,
    transport_state: str,
    observation_count: int,
    previous_count: int = 0,
    explicit_state: Any = None,
) -> str:
    explicit = str(explicit_state or "").lower()
    if explicit in FLOW_SESSION_STATES:
        return explicit
    state = str(transport_state or "unknown").lower()
    if state in {"closed", "time_wait", "close_wait", "fin_wait", "last_ack"}:
        return "dormant" if previous_count else "transient"
    if previous_count >= 2 or int(observation_count) >= 3:
        return "recurring"
    if state in {"established", "listen", "listening", "syn_sent", "syn_recv"}:
        return "active"
    if int(observation_count) == 1:
        return "transient"
    return "unknown"


def score_session_confidence(record: dict[str, Any], *, previous_count: int = 0) -> float:
    score = 0.25
    if record.get("flow_direction") != "unknown_direction":
        score += 0.2
    if record.get("local_port") is not None and record.get("remote_port") is not None:
        score += 0.15
    if record.get("protocol") != "unknown":
        score += 0.1
    if record.get("transport_state") != "unknown":
        score += 0.1
    if record.get("process_attribution") not in {"Unknown", "Unattributed"}:
        score += 0.08
    if record.get("service_attribution") not in {"Unknown", "Unattributed"}:
        score += 0.08
    if previous_count:
        score += min(0.04 + previous_count * 0.02, 0.14)
    return round(min(1.0, score), 3)


def deterministic_session_tracking_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _matching_previous_count(observation: dict[str, Any], previous_observations: Iterable[dict[str, Any]] | None) -> int:
    if not previous_observations:
        return 0
    target = _observation_key(observation)
    return sum(1 for row in previous_observations if isinstance(row, dict) and _observation_key(row) == target)


def _observation_key(observation: dict[str, Any]) -> tuple[Any, ...]:
    return (
        _endpoint_class(observation.get("local_endpoint_class") or observation.get("local_address_class") or "unknown"),
        _endpoint_class(observation.get("remote_endpoint_class") or observation.get("remote_address_class") or "unknown"),
        _safe_port(observation.get("local_port") or observation.get("port")),
        _safe_port(observation.get("remote_port")),
        _normalize_protocol(observation.get("protocol") or observation.get("transport") or observation.get("transport_protocol")),
        _safe_attribution(observation.get("process_attribution") or observation.get("process") or observation.get("program")),
        _safe_attribution(observation.get("service_attribution") or observation.get("service") or observation.get("service_name")),
        normalize_source_mode(str(observation.get("source_mode") or observation.get("data_source") or "unknown")),
    )


def _observed_timestamps(observation: dict[str, Any], *, generated_at: str) -> list[str]:
    timestamps = observation.get("observed_timestamps")
    if isinstance(timestamps, list):
        values = [str(item) for item in timestamps if item]
    else:
        values = [str(observation.get("timestamp") or observation.get("observed_at") or generated_at)]
    return sorted(set(values))


def _duration_preview(timestamps: list[str]) -> dict[str, Any]:
    if not timestamps:
        return {"first_seen": "", "last_seen": "", "duration_seconds": 0}
    first_seen = min(timestamps)
    last_seen = max(timestamps)
    return {"first_seen": first_seen, "last_seen": last_seen, "duration_seconds": _duration_seconds(first_seen, last_seen)}


def _duration_seconds(first_seen: str, last_seen: str) -> int:
    try:
        first = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
        last = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
    except ValueError:
        return 0
    return max(0, int((last - first).total_seconds()))


def _advisory_notes(*, direction: str, state: str, source_mode: str) -> list[str]:
    return [
        f"session direction is {direction}",
        f"session state is {state}",
        f"source mode is {source_mode}",
        "metadata-only session record; no payload inspection or PCAP generation",
    ]


def _endpoint_class(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace("-", "_")
    allowed = {"local", "private", "remote", "external", "public", "loopback", "edge", "unknown"}
    return text if text in allowed else "unknown"


def _normalize_protocol(value: Any) -> str:
    text = str(value or "unknown").strip().lower()
    return text if text in {"tcp", "udp", "icmp", "unknown"} else "unknown"


def _transport_state(value: Any) -> str:
    text = str(value or "unknown").strip().lower().replace(" ", "_")
    return text or "unknown"


def _safe_port(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def _safe_attribution(value: Any) -> str:
    if isinstance(value, dict):
        value = value.get("display_name") or value.get("service_name") or value.get("process_name") or value.get("name")
    text = str(value or "").strip()
    if not text:
        return "Unattributed"
    if text.lower() in {"unknown", "unattributed", "none"}:
        return "Unknown" if text.lower() == "unknown" else "Unattributed"
    return text[:80]


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
