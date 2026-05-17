from __future__ import annotations

from collections import Counter
from math import log2
from pathlib import Path
from typing import Any, Iterable

from core_engine.streams.patterns import SAFETY_FLAGS, detect_patterns, normalize_patterns


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
    return result


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
    return {
        "ok": status == "ok",
        "status": status,
        "classification": status,
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
