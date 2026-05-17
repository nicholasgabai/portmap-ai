from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from hashlib import sha256
from math import log2
from pathlib import Path
from typing import Any, Iterable

from core_engine.streams.patterns import SAFETY_FLAGS, detect_patterns, normalize_patterns


STREAM_METADATA_RECORD_VERSION = 2
STATUS_SEVERITY = {
    "ok": "info",
    "malformed": "medium",
    "unsupported": "high",
    "input_limited": "low",
}


def parse_stream_bytes(
    data: bytes | bytearray | memoryview,
    *,
    patterns: Iterable[dict[str, Any]] | None = None,
    frame_size: int | None = None,
    delimiter: bytes | None = None,
    length_prefix_bytes: int = 0,
    max_input_bytes: int = 65536,
    max_frames: int = 128,
) -> dict[str, Any]:
    if not isinstance(data, (bytes, bytearray, memoryview)):
        return _result("unsupported", [], ["data must be bytes-like"], source="bytes")
    raw = bytes(data)
    if len(raw) > max_input_bytes:
        return _result("input_limited", [], [f"input exceeds max_input_bytes {max_input_bytes}"], source="bytes", input_length=len(raw))

    pattern_result = normalize_patterns(patterns)
    if not pattern_result["ok"]:
        return _result("unsupported", [], pattern_result["errors"], source="bytes", input_length=len(raw))

    frames, errors = _split_frames(
        raw,
        frame_size=frame_size,
        delimiter=delimiter,
        length_prefix_bytes=length_prefix_bytes,
        max_frames=max_frames,
    )
    frame_rows = [_frame_metadata(index, offset, payload, patterns) for index, offset, payload in frames]
    status = "ok" if not errors else "malformed"
    if len(frames) >= max_frames and _has_more_frames(raw, frames):
        status = "input_limited"
        errors.append(f"frame count reached max_frames {max_frames}")
    return _result(status, frame_rows, errors, source="bytes", input_length=len(raw))


def parse_stream_file(
    path: str | Path,
    *,
    patterns: Iterable[dict[str, Any]] | None = None,
    frame_size: int | None = None,
    delimiter: bytes | None = None,
    length_prefix_bytes: int = 0,
    max_input_bytes: int = 65536,
    max_frames: int = 128,
) -> dict[str, Any]:
    try:
        file_path = Path(path)
        if not file_path.exists() or not file_path.is_file():
            return _result("unsupported", [], ["local file does not exist or is not a file"], source="local_file")
        size = file_path.stat().st_size
        if size > max_input_bytes:
            return _result("input_limited", [], [f"file exceeds max_input_bytes {max_input_bytes}"], source="local_file", input_length=size)
        raw = file_path.read_bytes()
    except OSError as exc:
        return _result("unsupported", [], [f"local file could not be read: {type(exc).__name__}"], source="local_file")
    result = parse_stream_bytes(
        raw,
        patterns=patterns,
        frame_size=frame_size,
        delimiter=delimiter,
        length_prefix_bytes=length_prefix_bytes,
        max_input_bytes=max_input_bytes,
        max_frames=max_frames,
    )
    result["source"] = "local_file"
    result["file_summary"] = {
        "name": file_path.name,
        "size": len(raw),
        "path_stored": False,
    }
    result["summary"] = summarize_stream_result(result)
    result["integration_hooks"] = _integration_hooks(result)
    result["result_id"] = _stable_id("stream-result", result["source"], result["classification"], result["summary"])
    return result


def summarize_stream_result(result: dict[str, Any]) -> dict[str, Any]:
    frames = [row for row in result.get("frames") or [] if isinstance(row, dict)]
    status = str(result.get("classification") or result.get("status") or "unsupported")
    detected_markers = sorted(str(marker) for marker in result.get("detected_markers") or [])
    return {
        "classification": status,
        "severity": STATUS_SEVERITY.get(status, "medium"),
        "source": str(result.get("source") or "unknown"),
        "input_length": int(result.get("input_length") or 0),
        "frame_count": len(frames),
        "max_frame_length": max((int(frame.get("length") or 0) for frame in frames), default=0),
        "average_entropy": float((result.get("entropy_summary") or {}).get("average") or 0.0),
        "average_printable_ratio": float((result.get("printable_ratio_summary") or {}).get("average") or 0.0),
        "detected_marker_count": len(detected_markers),
        "detected_markers": detected_markers,
        "error_count": len(result.get("errors") or []),
        "recommended_review": status != "ok",
        **SAFETY_FLAGS,
    }


def build_stream_event(
    result: dict[str, Any],
    *,
    source: str = "streams.metadata_parser",
    timestamp: str | None = None,
) -> dict[str, Any]:
    summary = summarize_stream_result(result)
    severity = summary["severity"]
    event_type = "system_notice" if severity in {"info", "low"} else "policy_review_required"
    message = _operator_summary(summary)
    return {
        "event_id": _stable_id("evt", result.get("result_id"), event_type, message),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "timestamp": timestamp or _now(),
        "message": message,
        "asset_ref": None,
        "service_ref": None,
        "flow_ref": None,
        "snapshot_ref": None,
        "finding_ref": _stable_id("finding", result.get("result_id"), summary["classification"]),
        "metadata": {
            "diagnostic_type": "stream_metadata",
            "classification": summary["classification"],
            "summary": summary,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_stream_finding(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_stream_result(result)
    return {
        "finding_id": _stable_id("finding", result.get("result_id"), summary["classification"], summary["source"]),
        "finding_type": "stream_metadata_result",
        "category": "stream_metadata",
        "severity": summary["severity"],
        "title": "Stream Metadata Result",
        "summary": _operator_summary(summary),
        "evidence_refs": [f"stream:{summary['source']}", f"frames:{summary['frame_count']}"],
        "recommended_review": summary["recommended_review"],
        "source_refs": [source_ref or f"stream:{summary['source']}"],
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def build_stream_timeline_entry(
    result: dict[str, Any],
    *,
    timestamp: str | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    summary = summarize_stream_result(result)
    text = _operator_summary(summary)
    return {
        "timeline_id": _stable_id("timeline", result.get("result_id"), text),
        "timestamp": timestamp or _now(),
        "category": "stream_metadata",
        "severity": summary["severity"],
        "title": "Stream Metadata",
        "summary": text,
        "asset_ref": None,
        "service_ref": None,
        "snapshot_ref": None,
        "source_refs": [source_ref or f"stream:{summary['source']}"],
        "recommended_review": summary["recommended_review"],
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_stream_storage_record(result: dict[str, Any], *, record_type: str = "stream_metadata") -> dict[str, Any]:
    summary = summarize_stream_result(result)
    return {
        "record_id": _stable_id("storage", result.get("result_id"), record_type, summary),
        "record_type": record_type,
        "summary": summary,
        "payload": {
            "status": result.get("status"),
            "classification": result.get("classification"),
            "source": result.get("source"),
            "input_length": result.get("input_length"),
            "frame_count": result.get("frame_count"),
            "length_summary": result.get("length_summary"),
            "entropy_summary": result.get("entropy_summary"),
            "printable_ratio_summary": result.get("printable_ratio_summary"),
            "detected_markers": result.get("detected_markers"),
            "errors": list(result.get("errors") or []),
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_stream_topology_summary(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_stream_result(result)
    node_id = _stable_id("stream-node", summary["source"], summary["frame_count"])
    base_ref = source_ref or f"stream:{summary['source']}"
    marker_nodes = [
        {
            "node_id": _stable_id("marker-node", marker),
            "label": marker,
            "category": "detected_marker",
            "source_refs": [base_ref],
        }
        for marker in summary["detected_markers"]
    ]
    edges = [
        {
            "edge_id": _stable_id("stream-edge", node_id, marker["node_id"]),
            "source": node_id,
            "target": marker["node_id"],
            "relationship_type": "marker_observed",
            "confidence": 1.0,
            "source_refs": [base_ref],
        }
        for marker in marker_nodes
    ]
    return {
        "nodes": [
            {
                "node_id": node_id,
                "label": "Local Stream",
                "category": "stream_metadata",
                "source_refs": [base_ref],
            },
            *marker_nodes,
        ],
        "edges": edges,
        "node_count": 1 + len(marker_nodes),
        "edge_count": len(edges),
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_stream_correlation_record(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    finding = build_stream_finding(result, source_ref=source_ref)
    return {
        **finding,
        "correlation_key": f"stream_metadata:{finding['category']}:{finding['severity']}",
        "score": 0.0,
        "confidence": 1.0 if result.get("ok") else 0.7,
    }


def _split_frames(
    raw: bytes,
    *,
    frame_size: int | None,
    delimiter: bytes | None,
    length_prefix_bytes: int,
    max_frames: int,
) -> tuple[list[tuple[int, int, bytes]], list[str]]:
    errors: list[str] = []
    if not raw:
        return [], []
    if length_prefix_bytes:
        return _split_length_prefixed(raw, length_prefix_bytes=length_prefix_bytes, max_frames=max_frames)
    if delimiter:
        frames: list[tuple[int, int, bytes]] = []
        offset = 0
        for index, payload in enumerate(raw.split(delimiter)[:max_frames]):
            frames.append((index, offset, payload))
            offset += len(payload) + len(delimiter)
        return frames, errors
    if frame_size is not None:
        if frame_size <= 0:
            return [], ["frame_size must be positive"]
        frames = []
        for index, offset in enumerate(range(0, len(raw), frame_size)):
            if index >= max_frames:
                break
            frames.append((index, offset, raw[offset : offset + frame_size]))
        return frames, errors
    return [(0, 0, raw)], errors


def _split_length_prefixed(raw: bytes, *, length_prefix_bytes: int, max_frames: int) -> tuple[list[tuple[int, int, bytes]], list[str]]:
    if length_prefix_bytes not in {1, 2, 4}:
        return [], ["length_prefix_bytes must be 1, 2, or 4"]
    frames: list[tuple[int, int, bytes]] = []
    errors: list[str] = []
    offset = 0
    while offset < len(raw) and len(frames) < max_frames:
        if offset + length_prefix_bytes > len(raw):
            errors.append("truncated length prefix")
            break
        length = int.from_bytes(raw[offset : offset + length_prefix_bytes], "big")
        frame_offset = offset + length_prefix_bytes
        end = frame_offset + length
        if end > len(raw):
            errors.append("declared frame length exceeds remaining input")
            break
        frames.append((len(frames), frame_offset, raw[frame_offset:end]))
        offset = end
    return frames, errors


def _frame_metadata(index: int, offset: int, payload: bytes, patterns: Iterable[dict[str, Any]] | None) -> dict[str, Any]:
    markers = detect_patterns(payload, patterns)
    return {
        "frame_id": f"frame-{index:04d}",
        "offset": offset,
        "length": len(payload),
        "entropy": _entropy(payload),
        "printable_ratio": _printable_ratio(payload),
        "hex_summary": payload[:16].hex(),
        "detected_markers": markers,
        "raw_payload_stored": False,
    }


def _result(
    status: str,
    frames: list[dict[str, Any]],
    errors: list[str],
    *,
    source: str,
    input_length: int = 0,
) -> dict[str, Any]:
    lengths = [frame["length"] for frame in frames]
    entropies = [frame["entropy"] for frame in frames]
    printable = [frame["printable_ratio"] for frame in frames]
    detected = sorted({marker["name"] for frame in frames for marker in frame.get("detected_markers", [])})
    payload = {
        "ok": status == "ok",
        "status": status,
        "classification": status,
        "record_version": STREAM_METADATA_RECORD_VERSION,
        "diagnostic_type": "stream_metadata",
        "source": source,
        "input_length": input_length,
        "frame_count": len(frames),
        "length_summary": _numeric_summary(lengths),
        "entropy_summary": _numeric_summary(entropies),
        "printable_ratio_summary": _numeric_summary(printable),
        "detected_markers": detected,
        "frames": frames,
        "errors": errors,
        **SAFETY_FLAGS,
    }
    payload["summary"] = summarize_stream_result(payload)
    payload["integration_hooks"] = _integration_hooks(payload)
    payload["result_id"] = _stable_id("stream-result", source, status, input_length, payload["summary"])
    return payload


def _numeric_summary(values: list[int] | list[float]) -> dict[str, float | int]:
    if not values:
        return {"min": 0, "max": 0, "average": 0}
    return {
        "min": round(min(values), 4),
        "max": round(max(values), 4),
        "average": round(sum(values) / len(values), 4),
    }


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


def _has_more_frames(raw: bytes, frames: list[tuple[int, int, bytes]]) -> bool:
    if not frames:
        return False
    last_offset = frames[-1][1] + len(frames[-1][2])
    return last_offset < len(raw)


def _integration_hooks(result: dict[str, Any]) -> dict[str, bool]:
    return {
        "event_pipeline_ready": True,
        "storage_ready": True,
        "policy_review_ready": result.get("classification") != "ok",
        "timeline_ready": True,
        "topology_ready": True,
        "correlation_ready": True,
    }


def _operator_summary(summary: dict[str, Any]) -> str:
    classification = str(summary.get("classification") or "unknown")
    source = str(summary.get("source") or "stream")
    frame_count = int(summary.get("frame_count") or 0)
    marker_count = int(summary.get("detected_marker_count") or 0)
    if classification == "ok":
        return f"Stream metadata parsed from {source} with {frame_count} frames and {marker_count} markers."
    return f"Stream metadata from {source} classified as {classification} with {frame_count} frames and {marker_count} markers."


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
