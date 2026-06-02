from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine import platform_utils
from core_engine.telemetry.interfaces import TELEMETRY_SAFETY_FLAGS


PROCESS_ATTRIBUTION_RECORD_VERSION = 1
SENSITIVE_PROCESS_TOKENS = ("token", "secret", "password", "key", "credential")
SOURCE_MODES = frozenset({"live", "simulated", "fixture", "replay", "unknown"})

PROCESS_ATTRIBUTION_SAFETY_FLAGS = {
    **TELEMETRY_SAFETY_FLAGS,
    "metadata_only": True,
    "raw_payload_rendered": False,
    "payload_bytes_stored": 0,
    "command_line_stored": False,
    "environment_stored": False,
    "username_stored": False,
    "privilege_escalation_attempted": False,
}


def build_process_socket_inventory(
    *,
    socket_records: Iterable[dict[str, Any]] | None = None,
    process_records: Iterable[dict[str, Any]] | None = None,
    platform_status: dict[str, Any] | None = None,
    source_mode: str = "live",
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Normalize operator-provided process/socket metadata into minimized records."""
    timestamp = generated_at or _now()
    mode = normalize_source_mode(source_mode)
    status = dict(platform_status or {})
    sockets = [normalize_socket_record(row, source_mode=mode) for row in socket_records or [] if isinstance(row, dict)]
    processes = [minimize_process_metadata(row, source_mode=mode) for row in process_records or [] if isinstance(row, dict)]
    process_index = {row["process_ref"]: row for row in processes if row.get("process_ref")}
    socket_rows = []
    for row in sockets:
        owner = process_index.get(str(row.get("process_ref") or ""))
        socket_rows.append(
            {
                **row,
                "owner_process": _operator_process_display(owner) if owner else None,
                "owner_known": owner is not None,
            }
        )
    permission_denied = bool(status.get("permission_denied"))
    unsupported = bool(status.get("unsupported_platform"))
    degraded = permission_denied or unsupported or bool(status.get("degraded"))
    summary = summarize_socket_inventory(socket_rows=socket_rows, process_rows=processes, platform_status=status, source_mode=mode, generated_at=timestamp)
    dashboard = build_process_inventory_dashboard_record(summary=summary, socket_rows=socket_rows, generated_at=timestamp)
    return {
        "record_type": "process_socket_inventory",
        "record_version": PROCESS_ATTRIBUTION_RECORD_VERSION,
        "inventory_id": "process-socket-inventory-" + _digest({"generated_at": timestamp, "sockets": socket_rows, "processes": processes})[:16],
        "generated_at": timestamp,
        "source_mode": mode,
        "data_source": mode,
        "status": "degraded" if degraded else "ok",
        "platform_status": {
            "status": str(status.get("status") or "ok" if not degraded else "degraded"),
            "unsupported_platform": unsupported,
            "permission_denied": permission_denied,
            "reason": str(status.get("reason") or ""),
        },
        "socket_records": sorted(socket_rows, key=lambda item: (str(item.get("local_port") or ""), str(item.get("process_ref") or ""))),
        "process_records": sorted(processes, key=lambda item: str(item.get("process_ref") or "")),
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": build_process_inventory_api_response(summary=summary, socket_rows=socket_rows, process_rows=processes, dashboard=dashboard, generated_at=timestamp),
        **PROCESS_ATTRIBUTION_SAFETY_FLAGS,
    }


def build_process_socket_inventory_from_platform(*, generated_at: str | None = None) -> dict[str, Any]:
    """Best-effort explicit local inventory; failures degrade safely."""
    timestamp = generated_at or _now()
    try:
        raw_connections = platform_utils.net_connections(kind="inet")
    except PermissionError as exc:
        return build_process_socket_inventory(
            socket_records=[],
            process_records=[],
            platform_status={"permission_denied": True, "reason": str(exc)},
            source_mode="live",
            generated_at=timestamp,
        )
    except Exception as exc:
        return build_process_socket_inventory(
            socket_records=[],
            process_records=[],
            platform_status={"degraded": True, "reason": str(exc)},
            source_mode="live",
            generated_at=timestamp,
        )
    socket_rows = []
    process_rows = []
    for conn in raw_connections:
        row = _socket_from_platform_connection(conn)
        socket_rows.append(row)
        pid = row.get("pid")
        if pid:
            process_rows.append({"pid": pid, "name": platform_utils.process_name(pid)})
    unsupported = not raw_connections and platform_utils.psutil is None
    return build_process_socket_inventory(
        socket_records=socket_rows,
        process_records=process_rows,
        platform_status={"unsupported_platform": unsupported, "reason": "psutil unavailable" if unsupported else ""},
        source_mode="live",
        generated_at=timestamp,
    )


def minimize_process_metadata(record: dict[str, Any], *, source_mode: str = "live") -> dict[str, Any]:
    mode = normalize_source_mode(record.get("source_mode") or record.get("data_source") or source_mode)
    pid = _safe_int(record.get("pid"))
    name = _sanitize_process_name(record.get("name") or record.get("process_name") or "unknown")
    process_ref = str(record.get("process_ref") or _process_ref(pid=pid, name=name))
    return {
        "record_type": "minimized_process_metadata",
        "record_version": PROCESS_ATTRIBUTION_RECORD_VERSION,
        "process_ref": process_ref,
        "pid_known": pid is not None,
        "pid_ref": _pid_ref(pid) if pid is not None else "",
        "process_name": name,
        "display_name": name,
        "source_mode": mode,
        "data_source": mode,
        "metadata_minimized": True,
        "command_line_stored": False,
        "environment_stored": False,
        "username_stored": False,
        "sensitive_fields_removed": sorted(
            field for field in ("cmdline", "command_line", "username", "user", "environment", "env") if field in record
        ),
        **PROCESS_ATTRIBUTION_SAFETY_FLAGS,
    }


def normalize_socket_record(record: dict[str, Any], *, source_mode: str = "live") -> dict[str, Any]:
    mode = normalize_source_mode(record.get("source_mode") or record.get("data_source") or source_mode)
    pid = _safe_int(record.get("pid"))
    process_name = _sanitize_process_name(record.get("process_name") or record.get("name") or "")
    process_ref = str(record.get("process_ref") or _process_ref(pid=pid, name=process_name))
    status = str(record.get("status") or record.get("state") or "unknown").lower()
    return {
        "record_type": "listening_socket_ownership",
        "record_version": PROCESS_ATTRIBUTION_RECORD_VERSION,
        "socket_id": "socket-" + _digest(
            {
                "local_ip": record.get("local_ip") or record.get("laddr_ip") or record.get("bind_address"),
                "local_port": record.get("local_port") or record.get("port"),
                "transport_protocol": record.get("transport_protocol") or record.get("transport"),
                "process_ref": process_ref,
                "status": status,
            }
        )[:16],
        "transport_protocol": str(record.get("transport_protocol") or record.get("transport") or "tcp").lower(),
        "local_ip": str(record.get("local_ip") or record.get("laddr_ip") or record.get("bind_address") or ""),
        "local_port": _safe_int(record.get("local_port") or record.get("port")),
        "remote_ip": str(record.get("remote_ip") or record.get("raddr_ip") or ""),
        "remote_port": _safe_int(record.get("remote_port")),
        "status": status,
        "listening": status in {"listen", "listening"},
        "process_ref": process_ref,
        "pid_ref": _pid_ref(pid) if pid is not None else "",
        "process_name_hint": process_name or "unknown",
        "source_mode": mode,
        "data_source": mode,
        **PROCESS_ATTRIBUTION_SAFETY_FLAGS,
    }


def attribute_process_to_flow(
    flow_observation: dict[str, Any],
    inventory: dict[str, Any],
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    observation = dict(flow_observation or {})
    mode = normalize_source_mode(observation.get("source_mode") or observation.get("data_source") or inventory.get("source_mode") or inventory.get("data_source") or "live")
    socket_rows = [dict(row) for row in inventory.get("socket_records") or [] if isinstance(row, dict)]
    match = _best_socket_match(observation, socket_rows)
    platform_status = inventory.get("platform_status") if isinstance(inventory.get("platform_status"), dict) else {}
    unsupported = bool(platform_status.get("unsupported_platform"))
    permission_denied = bool(platform_status.get("permission_denied"))
    status = "unsupported" if unsupported else "permission_denied" if permission_denied else "matched" if match else "unmatched"
    confidence = _process_confidence(match=match, status=status)
    return {
        "record_type": "process_port_attribution",
        "record_version": PROCESS_ATTRIBUTION_RECORD_VERSION,
        "generated_at": timestamp,
        "flow_ref": str(observation.get("flow_ref") or ""),
        "source_mode": mode,
        "data_source": mode,
        "status": status,
        "process_ref": str(match.get("process_ref") if match else ""),
        "socket_ref": str(match.get("socket_id") if match else ""),
        "local_port": match.get("local_port") if match else _observed_service_port(observation),
        "transport_protocol": str(observation.get("transport_protocol") or "unknown"),
        "process_display": _operator_process_display_with_source(match.get("owner_process") if isinstance(match, dict) else None, status=status, source_mode=mode),
        "confidence": confidence,
        "confidence_level": _confidence_level(confidence),
        "match_reasons": _match_reasons(match=match, status=status),
        "permission_denied": permission_denied,
        "unsupported_platform": unsupported,
        **PROCESS_ATTRIBUTION_SAFETY_FLAGS,
    }


def summarize_socket_inventory(
    *,
    socket_rows: Iterable[dict[str, Any]],
    process_rows: Iterable[dict[str, Any]],
    platform_status: dict[str, Any],
    source_mode: str = "live",
    generated_at: str | None = None,
) -> dict[str, Any]:
    sockets = [dict(row) for row in socket_rows or [] if isinstance(row, dict)]
    processes = [dict(row) for row in process_rows or [] if isinstance(row, dict)]
    return {
        "record_type": "process_socket_inventory_summary",
        "record_version": PROCESS_ATTRIBUTION_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "source_mode": normalize_source_mode(source_mode),
        "data_source": normalize_source_mode(source_mode),
        "socket_count": len(sockets),
        "listening_socket_count": sum(1 for row in sockets if row.get("listening")),
        "process_count": len(processes),
        "owned_socket_count": sum(1 for row in sockets if row.get("owner_known")),
        "permission_denied": bool(platform_status.get("permission_denied")),
        "unsupported_platform": bool(platform_status.get("unsupported_platform")),
        "by_transport": _count_by(sockets, "transport_protocol"),
        "by_status": _count_by(sockets, "status"),
        **PROCESS_ATTRIBUTION_SAFETY_FLAGS,
    }


def build_process_inventory_dashboard_record(
    *,
    summary: dict[str, Any],
    socket_rows: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in socket_rows or [] if isinstance(row, dict)]
    status = "degraded" if summary.get("permission_denied") or summary.get("unsupported_platform") else "ok"
    return {
        "record_type": "process_inventory_dashboard",
        "panel": "process_socket_inventory",
        "status": status,
        "generated_at": generated_at or _now(),
        "metrics": {
            "socket_count": int(summary.get("socket_count") or 0),
            "listening_socket_count": int(summary.get("listening_socket_count") or 0),
            "process_count": int(summary.get("process_count") or 0),
            "owned_socket_count": int(summary.get("owned_socket_count") or 0),
        },
        "rows": [_socket_display(row) for row in sorted(rows, key=lambda item: (str(item.get("local_port") or ""), str(item.get("process_ref") or "")))],
        "recommended_review": status == "degraded",
        **PROCESS_ATTRIBUTION_SAFETY_FLAGS,
    }


def build_process_inventory_api_response(
    *,
    summary: dict[str, Any],
    socket_rows: Iterable[dict[str, Any]],
    process_rows: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "process_inventory_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "socket_records": [dict(row) for row in socket_rows or [] if isinstance(row, dict)],
        "process_records": [dict(row) for row in process_rows or [] if isinstance(row, dict)],
        "dashboard": dict(dashboard),
        **PROCESS_ATTRIBUTION_SAFETY_FLAGS,
    }


def deterministic_process_attribution_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _best_socket_match(observation: dict[str, Any], socket_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    service_port = _observed_service_port(observation)
    transport = str(observation.get("transport_protocol") or "unknown").lower()
    responder = observation.get("responder") if isinstance(observation.get("responder"), dict) else {}
    responder_ip = str(responder.get("ip") or "")
    candidates = []
    for row in socket_rows:
        if service_port is not None and row.get("local_port") != service_port:
            continue
        if transport != "unknown" and str(row.get("transport_protocol") or "").lower() != transport:
            continue
        score = 0
        if row.get("listening"):
            score += 2
        if row.get("owner_known"):
            score += 2
        if responder_ip and str(row.get("local_ip") or "") in {responder_ip, "", "0.0.0.0", "::"}:
            score += 1
        candidates.append((score, row))
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: (-item[0], str(item[1].get("socket_id") or "")))[0][1]


def _observed_service_port(observation: dict[str, Any]) -> int | None:
    hint = observation.get("service_port_hint") if isinstance(observation.get("service_port_hint"), dict) else {}
    port = _safe_int(hint.get("service_port"))
    if port is not None:
        return port
    responder = observation.get("responder") if isinstance(observation.get("responder"), dict) else {}
    return _safe_int(responder.get("port"))


def _process_confidence(*, match: dict[str, Any] | None, status: str) -> float:
    if status in {"unsupported", "permission_denied"}:
        return 0.0
    if not match:
        return 0.2
    score = 0.45
    if match.get("listening"):
        score += 0.2
    if match.get("owner_known"):
        score += 0.25
    if match.get("process_ref"):
        score += 0.05
    return round(min(1.0, score), 3)


def _confidence_level(score: float) -> str:
    if score >= 0.8:
        return "high"
    if score >= 0.5:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _match_reasons(*, match: dict[str, Any] | None, status: str) -> list[str]:
    if status == "unsupported":
        return ["platform_socket_inventory_unavailable"]
    if status == "permission_denied":
        return ["socket_inventory_permission_denied"]
    if not match:
        return ["no_matching_socket_record"]
    reasons = ["port_and_transport_match"]
    if match.get("listening"):
        reasons.append("listening_socket")
    if match.get("owner_known"):
        reasons.append("owner_process_known")
    return sorted(reasons)


def _operator_process_display(record: dict[str, Any] | None) -> dict[str, Any]:
    return _operator_process_display_with_source(record, status="unknown", source_mode="live")


def _operator_process_display_with_source(record: dict[str, Any] | None, *, status: str, source_mode: str) -> dict[str, Any]:
    mode = normalize_source_mode(source_mode)
    if not record:
        display_name = "Unattributed" if status == "unmatched" else "Unknown"
        return {
            "process_ref": "",
            "display_name": display_name,
            "source_mode": mode,
            "metadata_minimized": True,
            "command_line_stored": False,
            "username_stored": False,
        }
    return {
        "process_ref": str(record.get("process_ref") or ""),
        "display_name": str(record.get("display_name") or record.get("process_name") or "unknown"),
        "source_mode": normalize_source_mode(record.get("source_mode") or record.get("data_source") or mode),
        "metadata_minimized": True,
        "command_line_stored": False,
        "username_stored": False,
    }


def _socket_display(record: dict[str, Any]) -> dict[str, Any]:
    owner = record.get("owner_process") if isinstance(record.get("owner_process"), dict) else {}
    return {
        "socket_ref": record.get("socket_id"),
        "transport_protocol": record.get("transport_protocol"),
        "local_port": record.get("local_port"),
        "status": record.get("status"),
        "process_ref": record.get("process_ref"),
        "source_mode": record.get("source_mode") or record.get("data_source") or "unknown",
        "process_display": _operator_process_display_with_source(owner, status="matched" if owner else "unmatched", source_mode=str(record.get("source_mode") or record.get("data_source") or "unknown")),
    }


def _socket_from_platform_connection(conn: Any) -> dict[str, Any]:
    laddr = getattr(conn, "laddr", None)
    raddr = getattr(conn, "raddr", None)
    return {
        "transport_protocol": "tcp" if str(getattr(conn, "type", "")).endswith("SOCK_STREAM") else "udp",
        "local_ip": getattr(laddr, "ip", None) or (laddr[0] if laddr else ""),
        "local_port": getattr(laddr, "port", None) or (laddr[1] if laddr and len(laddr) > 1 else None),
        "remote_ip": getattr(raddr, "ip", None) or (raddr[0] if raddr else ""),
        "remote_port": getattr(raddr, "port", None) or (raddr[1] if raddr and len(raddr) > 1 else None),
        "status": str(getattr(conn, "status", "") or "unknown").lower(),
        "pid": getattr(conn, "pid", None),
    }


def _sanitize_process_name(value: Any) -> str:
    text = str(value or "unknown").strip() or "unknown"
    lowered = text.lower()
    if any(token in lowered for token in SENSITIVE_PROCESS_TOKENS):
        return "redacted-process"
    return text[:80]


def normalize_source_mode(value: Any) -> str:
    mode = str(value or "unknown").strip().lower()
    return mode if mode in SOURCE_MODES else "unknown"


def _process_ref(*, pid: int | None, name: str) -> str:
    return "process-" + _digest({"pid": pid, "name": name})[:16]


def _pid_ref(pid: int) -> str:
    return "pid-" + _digest({"pid": pid})[:12]


def _safe_int(value: Any) -> int | None:
    if value in {None, ""}:
        return None
    try:
        integer = int(value)
    except (TypeError, ValueError):
        return None
    return integer if integer >= 0 else None


def _count_by(rows: Iterable[dict[str, Any]], field_name: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in rows:
        value = str(row.get(field_name) or "unknown")
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
