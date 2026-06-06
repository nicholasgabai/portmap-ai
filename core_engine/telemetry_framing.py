from __future__ import annotations

import json
import socket
from typing import Any

FRAME_DELIMITER = b"\n"
DEFAULT_MAX_FRAME_BYTES = 2 * 1024 * 1024
DEFAULT_RECV_CHUNK_BYTES = 65536
DEFAULT_FRAME_READ_TIMEOUT_SECONDS = 5.0


class TelemetryFrameError(ValueError):
    """Base class for worker telemetry frame failures."""

    reason = "frame_error"


class TelemetryFrameTooLarge(TelemetryFrameError):
    reason = "frame_too_large"


class TelemetryFrameMalformed(TelemetryFrameError):
    reason = "malformed_frame"


def encode_json_frame(payload: dict[str, Any], *, max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES) -> bytes:
    """Encode a worker telemetry payload as newline-delimited JSON."""
    if not isinstance(payload, dict):
        raise TelemetryFrameMalformed("payload_must_be_object")
    body = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    if len(body) > max_frame_bytes:
        raise TelemetryFrameTooLarge("frame_exceeds_maximum")
    return body + FRAME_DELIMITER


def decode_json_frame(frame: bytes) -> dict[str, Any]:
    """Decode a single JSON frame into a telemetry payload object."""
    if not frame:
        raise TelemetryFrameMalformed("empty_frame")
    try:
        decoded = json.loads(frame.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise TelemetryFrameMalformed("invalid_utf8") from exc
    except json.JSONDecodeError as exc:
        raise TelemetryFrameMalformed("invalid_json") from exc
    if not isinstance(decoded, dict):
        raise TelemetryFrameMalformed("payload_must_be_object")
    return decoded


def read_json_frames(
    conn,
    *,
    max_frame_bytes: int = DEFAULT_MAX_FRAME_BYTES,
    recv_chunk_bytes: int = DEFAULT_RECV_CHUNK_BYTES,
    read_timeout: float | None = DEFAULT_FRAME_READ_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Read one or more complete worker telemetry JSON frames.

    New workers send newline-delimited JSON. For compatibility with older
    workers, a complete raw JSON object without a trailing newline is accepted.
    """
    frames: list[dict[str, Any]] = []
    buffer = bytearray()
    old_timeout = _get_socket_timeout(conn)
    timeout_changed = False
    if read_timeout is not None and hasattr(conn, "settimeout"):
        try:
            conn.settimeout(read_timeout)
            timeout_changed = True
        except Exception:
            timeout_changed = False

    try:
        while True:
            chunk = conn.recv(recv_chunk_bytes)
            if not chunk:
                if not buffer:
                    return frames
                frames.append(_decode_legacy_buffer(bytes(buffer), max_frame_bytes=max_frame_bytes))
                return frames

            buffer.extend(chunk)
            if len(buffer) > max_frame_bytes and FRAME_DELIMITER not in buffer:
                raise TelemetryFrameTooLarge("frame_exceeds_maximum")

            while FRAME_DELIMITER in buffer:
                raw_frame, _, remainder = bytes(buffer).partition(FRAME_DELIMITER)
                buffer = bytearray(remainder)
                if not raw_frame:
                    continue
                if len(raw_frame) > max_frame_bytes:
                    raise TelemetryFrameTooLarge("frame_exceeds_maximum")
                frames.append(decode_json_frame(raw_frame))

            if frames and not buffer:
                return frames

            if not frames and FRAME_DELIMITER not in buffer:
                legacy_payload = _try_decode_legacy_buffer(bytes(buffer), max_frame_bytes=max_frame_bytes)
                if legacy_payload is not None:
                    return [legacy_payload]
    except socket.timeout as exc:
        if buffer:
            raise TelemetryFrameMalformed("incomplete_frame") from exc
        return frames
    finally:
        if timeout_changed:
            try:
                conn.settimeout(old_timeout)
            except Exception:
                pass


def telemetry_frame_error_summary(exc: BaseException) -> dict[str, Any]:
    """Return a sanitized frame error summary without payload bytes."""
    reason = getattr(exc, "reason", "frame_error")
    return {
        "error_type": exc.__class__.__name__,
        "reason": reason,
        "raw_payload_logged": False,
        "endpoint_metadata_logged": False,
    }


def summarize_worker_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Build a safe payload summary for logs."""
    ports = payload.get("ports") or []
    scan_snapshot = payload.get("scan_snapshot") or {}
    milestone_counters = payload.get("milestone_v_counters") or {}
    return {
        "node_id": str(payload.get("node_id") or "unknown"),
        "score": payload.get("score"),
        "ports_count": len(ports) if isinstance(ports, list) else 0,
        "snapshot_id": str(scan_snapshot.get("snapshot_id") or ""),
        "source_modes": list(scan_snapshot.get("source_modes") or []),
        "milestone_v_counters": {
            name: int(milestone_counters.get(name) or 0)
            for name in (
                "observations_seen",
                "sessions_reconstructed",
                "flows_reconstructed",
                "metadata_correlations",
                "process_correlations",
                "relationship_edges",
                "attribution_candidates",
                "drift_records",
                "topology_records",
            )
            if name in milestone_counters
        },
        "raw_payload_logged": False,
        "endpoint_metadata_logged": False,
    }


def _decode_legacy_buffer(buffer: bytes, *, max_frame_bytes: int) -> dict[str, Any]:
    if len(buffer) > max_frame_bytes:
        raise TelemetryFrameTooLarge("frame_exceeds_maximum")
    return decode_json_frame(buffer)


def _try_decode_legacy_buffer(buffer: bytes, *, max_frame_bytes: int) -> dict[str, Any] | None:
    if len(buffer) > max_frame_bytes:
        raise TelemetryFrameTooLarge("frame_exceeds_maximum")
    try:
        return decode_json_frame(buffer)
    except TelemetryFrameMalformed:
        return None


def _get_socket_timeout(conn) -> float | None:
    if not hasattr(conn, "gettimeout"):
        return None
    try:
        return conn.gettimeout()
    except Exception:
        return None
