from __future__ import annotations

import asyncio
from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256
from math import log2
from time import perf_counter
from typing import Any, Iterable


RELAY_RECORD_VERSION = 1
RELAY_STATUS_SEVERITY = {
    "completed": "info",
    "input_limited": "low",
    "malformed": "medium",
    "timed_out": "high",
    "unsupported": "high",
}
SAFETY_FLAGS = {
    "local_only": True,
    "operator_controlled": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


async def run_relay_simulation(
    payloads: Iterable[bytes | bytearray | memoryview | str],
    *,
    session_label: str = "sample-relay-session",
    source_ref: str = "mock-source",
    destination_ref: str = "mock-destination",
    max_messages: int = 32,
    max_payload_bytes: int = 4096,
    max_total_bytes: int = 65536,
    max_duration_seconds: float = 5.0,
    per_message_delay_seconds: float = 0.0,
) -> dict[str, Any]:
    start = perf_counter()
    normalized = _normalize_payloads(
        payloads,
        max_messages=max_messages,
        max_payload_bytes=max_payload_bytes,
        max_total_bytes=max_total_bytes,
    )
    if not normalized["ok"]:
        return _result(
            normalized["status"],
            [],
            normalized["errors"],
            session_label=session_label,
            source_ref=source_ref,
            destination_ref=destination_ref,
            started_at=start,
            max_messages=max_messages,
            max_payload_bytes=max_payload_bytes,
            max_total_bytes=max_total_bytes,
            max_duration_seconds=max_duration_seconds,
        )

    try:
        frames = await asyncio.wait_for(
            _forward_sequentially(
                normalized["_payloads"],
                source_ref=source_ref,
                destination_ref=destination_ref,
                per_message_delay_seconds=per_message_delay_seconds,
            ),
            timeout=max(float(max_duration_seconds), 0.001),
        )
    except TimeoutError:
        return _result(
            "timed_out",
            [],
            ["relay simulation exceeded max_duration_seconds"],
            session_label=session_label,
            source_ref=source_ref,
            destination_ref=destination_ref,
            started_at=start,
            max_messages=max_messages,
            max_payload_bytes=max_payload_bytes,
            max_total_bytes=max_total_bytes,
            max_duration_seconds=max_duration_seconds,
        )

    status = "input_limited" if normalized["limited"] else "completed"
    return _result(
        status,
        frames,
        normalized["errors"],
        session_label=session_label,
        source_ref=source_ref,
        destination_ref=destination_ref,
        started_at=start,
        max_messages=max_messages,
        max_payload_bytes=max_payload_bytes,
        max_total_bytes=max_total_bytes,
        max_duration_seconds=max_duration_seconds,
    )


def run_relay_simulation_sync(
    payloads: Iterable[bytes | bytearray | memoryview | str],
    **kwargs: Any,
) -> dict[str, Any]:
    return asyncio.run(run_relay_simulation(payloads, **kwargs))


def summarize_relay_result(result: dict[str, Any]) -> dict[str, Any]:
    status = str(result.get("classification") or result.get("status") or "unsupported")
    return {
        "session_id": str(result.get("session_id") or ""),
        "session_label": str(result.get("session_label") or ""),
        "classification": status,
        "severity": RELAY_STATUS_SEVERITY.get(status, "medium"),
        "message_count": int(result.get("message_count") or 0),
        "forwarded_message_count": int(result.get("forwarded_message_count") or 0),
        "input_bytes": int(result.get("input_bytes") or 0),
        "forwarded_bytes": int(result.get("forwarded_bytes") or 0),
        "duration_seconds": float(result.get("duration_seconds") or 0.0),
        "throughput_bytes_per_second": float(result.get("throughput_bytes_per_second") or 0.0),
        "error_count": len(result.get("errors") or []),
        "recommended_review": status not in {"completed"},
        **SAFETY_FLAGS,
    }


def build_relay_event(
    result: dict[str, Any],
    *,
    source: str = "diagnostics.relay_simulator",
    timestamp: str | None = None,
) -> dict[str, Any]:
    summary = summarize_relay_result(result)
    severity = summary["severity"]
    event_type = "system_notice" if severity in {"info", "low"} else "policy_review_required"
    message = _operator_summary(summary)
    return {
        "event_id": _stable_id("evt", result.get("session_id"), event_type, message),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "timestamp": timestamp or _now(),
        "message": message,
        "asset_ref": None,
        "service_ref": None,
        "flow_ref": _stable_id("flow", result.get("session_id"), "relay"),
        "snapshot_ref": None,
        "finding_ref": _stable_id("finding", result.get("session_id"), summary["classification"]),
        "metadata": {
            "diagnostic_type": "relay_orchestration",
            "classification": summary["classification"],
            "summary": summary,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_relay_finding(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_relay_result(result)
    return {
        "finding_id": _stable_id("finding", result.get("session_id"), summary["classification"], summary["message_count"]),
        "finding_type": "relay_orchestration_result",
        "category": "relay_orchestration",
        "severity": summary["severity"],
        "title": "Relay Orchestration Result",
        "summary": _operator_summary(summary),
        "evidence_refs": [f"relay:{summary['session_id']}", f"messages:{summary['message_count']}"],
        "recommended_review": summary["recommended_review"],
        "source_refs": [source_ref or f"relay:{summary['session_id']}"],
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def build_relay_storage_record(result: dict[str, Any], *, record_type: str = "relay_orchestration") -> dict[str, Any]:
    summary = summarize_relay_result(result)
    return {
        "record_id": _stable_id("storage", result.get("session_id"), record_type, summary),
        "record_type": record_type,
        "summary": summary,
        "payload": {
            "status": result.get("status"),
            "classification": result.get("classification"),
            "session_id": result.get("session_id"),
            "session_label": result.get("session_label"),
            "message_count": result.get("message_count"),
            "forwarded_message_count": result.get("forwarded_message_count"),
            "input_bytes": result.get("input_bytes"),
            "forwarded_bytes": result.get("forwarded_bytes"),
            "duration_seconds": result.get("duration_seconds"),
            "errors": list(result.get("errors") or []),
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_relay_timeline_entry(
    result: dict[str, Any],
    *,
    timestamp: str | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    summary = summarize_relay_result(result)
    text = _operator_summary(summary)
    return {
        "timeline_id": _stable_id("timeline", result.get("session_id"), text),
        "timestamp": timestamp or _now(),
        "category": "relay_orchestration",
        "severity": summary["severity"],
        "title": "Relay Orchestration",
        "summary": text,
        "asset_ref": None,
        "service_ref": None,
        "snapshot_ref": None,
        "source_refs": [source_ref or f"relay:{summary['session_id']}"],
        "recommended_review": summary["recommended_review"],
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_relay_topology_summary(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_relay_result(result)
    base_ref = source_ref or f"relay:{summary['session_id']}"
    source_node = _stable_id("relay-node", result.get("source_ref"), summary["session_id"])
    destination_node = _stable_id("relay-node", result.get("destination_ref"), summary["session_id"])
    edge_id = _stable_id("relay-edge", source_node, destination_node, summary["session_id"])
    return {
        "nodes": [
            {
                "node_id": source_node,
                "label": "Mock Source",
                "category": "relay_mock_source",
                "source_refs": [base_ref],
            },
            {
                "node_id": destination_node,
                "label": "Mock Destination",
                "category": "relay_mock_destination",
                "source_refs": [base_ref],
            },
        ],
        "edges": [
            {
                "edge_id": edge_id,
                "source": source_node,
                "target": destination_node,
                "relationship_type": "relay_forwarded",
                "observation_count": summary["forwarded_message_count"],
                "confidence": 1.0 if result.get("ok") else 0.7,
                "source_refs": [base_ref],
            }
        ],
        "node_count": 2,
        "edge_count": 1,
        "relationship_count": 1,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_relay_dashboard_summary(result: dict[str, Any]) -> dict[str, Any]:
    summary = summarize_relay_result(result)
    return {
        "panel": "relay_orchestration",
        "status": summary["classification"],
        "message_count": summary["message_count"],
        "forwarded_bytes": summary["forwarded_bytes"],
        "recommended_review": summary["recommended_review"],
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_relay_correlation_record(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    finding = build_relay_finding(result, source_ref=source_ref)
    status = str(result.get("status") or "unsupported")
    score = {"completed": 0.0, "input_limited": 0.15, "malformed": 0.35, "timed_out": 0.65, "unsupported": 0.6}.get(status, 0.4)
    return {
        **finding,
        "correlation_key": f"relay_orchestration:{finding['category']}:{finding['severity']}",
        "score": score,
        "confidence": 0.9 if status == "completed" else 0.75,
    }


async def _forward_sequentially(
    payloads: list[bytes],
    *,
    source_ref: str,
    destination_ref: str,
    per_message_delay_seconds: float,
) -> list[dict[str, Any]]:
    source_queue: asyncio.Queue[tuple[int, bytes] | None] = asyncio.Queue()
    destination_queue: asyncio.Queue[tuple[int, bytes]] = asyncio.Queue()
    frames: list[dict[str, Any]] = []

    for index, payload in enumerate(payloads):
        await source_queue.put((index, payload))
    await source_queue.put(None)

    while True:
        item = await source_queue.get()
        if item is None:
            break
        index, payload = item
        if per_message_delay_seconds > 0:
            await asyncio.sleep(per_message_delay_seconds)
        await destination_queue.put((index, payload))

    while not destination_queue.empty():
        index, forwarded = await destination_queue.get()
        frames.append(_frame_metadata(index, forwarded, source_ref=source_ref, destination_ref=destination_ref))
    return frames


def _normalize_payloads(
    payloads: Iterable[bytes | bytearray | memoryview | str],
    *,
    max_messages: int,
    max_payload_bytes: int,
    max_total_bytes: int,
) -> dict[str, Any]:
    if max_messages <= 0 or max_payload_bytes <= 0 or max_total_bytes <= 0:
        return {"ok": False, "status": "malformed", "_payloads": [], "limited": False, "errors": ["relay bounds must be positive"]}
    try:
        rows = list(payloads)
    except TypeError:
        return {"ok": False, "status": "unsupported", "_payloads": [], "limited": False, "errors": ["payloads must be iterable"]}

    normalized: list[bytes] = []
    errors: list[str] = []
    total = 0
    limited = False
    for index, payload in enumerate(rows):
        if index >= max_messages:
            errors.append(f"message count exceeds max_messages {max_messages}")
            limited = True
            break
        if isinstance(payload, str):
            raw = payload.encode("utf-8")
        elif isinstance(payload, (bytes, bytearray, memoryview)):
            raw = bytes(payload)
        else:
            return {
                "ok": False,
                "status": "unsupported",
                "_payloads": [],
                "limited": False,
                "errors": [f"payload {index} must be bytes-like or string"],
            }
        if len(raw) > max_payload_bytes:
            errors.append(f"payload {index} exceeds max_payload_bytes {max_payload_bytes}")
            limited = True
            continue
        if total + len(raw) > max_total_bytes:
            errors.append(f"payload total exceeds max_total_bytes {max_total_bytes}")
            limited = True
            break
        total += len(raw)
        normalized.append(raw)
    return {
        "ok": True,
        "status": "ok",
        "_payloads": normalized,
        "limited": limited,
        "errors": errors,
    }


def _frame_metadata(index: int, payload: bytes, *, source_ref: str, destination_ref: str) -> dict[str, Any]:
    return {
        "frame_id": f"relay-frame-{index:04d}",
        "sequence": index,
        "direction": "source_to_destination",
        "source_ref": source_ref,
        "destination_ref": destination_ref,
        "input_length": len(payload),
        "forwarded_length": len(payload),
        "entropy": _entropy(payload),
        "printable_ratio": _printable_ratio(payload),
        "hex_summary": payload[:16].hex(),
        "raw_payload_stored": False,
    }


def _result(
    status: str,
    frames: list[dict[str, Any]],
    errors: list[str],
    *,
    session_label: str,
    source_ref: str,
    destination_ref: str,
    started_at: float,
    max_messages: int,
    max_payload_bytes: int,
    max_total_bytes: int,
    max_duration_seconds: float,
) -> dict[str, Any]:
    duration = round(max(perf_counter() - started_at, 0.0), 6)
    input_bytes = sum(int(frame.get("input_length") or 0) for frame in frames)
    forwarded_bytes = sum(int(frame.get("forwarded_length") or 0) for frame in frames)
    payload = {
        "ok": status == "completed",
        "status": status,
        "classification": status,
        "record_version": RELAY_RECORD_VERSION,
        "diagnostic_type": "relay_orchestration",
        "session_label": session_label,
        "session_id": _stable_id("relay-session", session_label, source_ref, destination_ref, status, frames, errors),
        "source_ref": source_ref,
        "destination_ref": destination_ref,
        "message_count": len(frames),
        "forwarded_message_count": len(frames),
        "input_bytes": input_bytes,
        "forwarded_bytes": forwarded_bytes,
        "duration_seconds": duration,
        "throughput_bytes_per_second": round(forwarded_bytes / duration, 4) if duration else float(forwarded_bytes),
        "bounds": {
            "max_messages": max_messages,
            "max_payload_bytes": max_payload_bytes,
            "max_total_bytes": max_total_bytes,
            "max_duration_seconds": max_duration_seconds,
        },
        "frames": frames,
        "errors": errors,
        **SAFETY_FLAGS,
    }
    payload["summary"] = summarize_relay_result(payload)
    payload["integration_hooks"] = _integration_hooks(payload)
    return payload


def _integration_hooks(result: dict[str, Any]) -> dict[str, bool]:
    return {
        "event_pipeline_ready": True,
        "storage_ready": True,
        "dashboard_ready": True,
        "policy_review_ready": result.get("classification") != "completed",
        "timeline_ready": True,
        "topology_ready": True,
        "correlation_ready": True,
    }


def _operator_summary(summary: dict[str, Any]) -> str:
    status = str(summary.get("classification") or "unknown")
    count = int(summary.get("forwarded_message_count") or 0)
    byte_count = int(summary.get("forwarded_bytes") or 0)
    if status == "completed":
        return f"Relay orchestration completed with {count} forwarded messages and {byte_count} bytes."
    return f"Relay orchestration classified as {status} with {count} forwarded messages and {byte_count} bytes."


def _entropy(payload: bytes) -> float:
    if not payload:
        return 0.0
    counts = Counter(payload)
    total = len(payload)
    value = -sum((count / total) * log2(count / total) for count in counts.values())
    return round(value, 4)


def _printable_ratio(payload: bytes) -> float:
    if not payload:
        return 0.0
    printable = sum(1 for byte in payload if byte in {9, 10, 13} or 32 <= byte <= 126)
    return round(printable / len(payload), 4)


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
