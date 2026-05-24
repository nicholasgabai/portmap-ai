from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.interfaces import (
    TELEMETRY_SAFETY_FLAGS,
    build_interface_resource_budget_summary,
    enumerate_local_interfaces,
)


CAPTURE_SESSION_RECORD_VERSION = 1
CAPTURE_SESSION_MODES = frozenset({"dry-run", "metadata-preview"})
DEFAULT_PACKET_BUDGET = 0
DEFAULT_DURATION_SECONDS = 0


class PassiveCaptureSessionError(ValueError):
    """Raised when a passive capture session plan is malformed."""


def build_passive_capture_session_plan(
    *,
    selected_interfaces: Iterable[str] | None = None,
    interface_inventory: dict[str, Any] | None = None,
    interfaces: dict[str, Iterable[dict[str, Any]]] | None = None,
    session_mode: str = "dry-run",
    duration_seconds: int = DEFAULT_DURATION_SECONDS,
    max_packets: int = DEFAULT_PACKET_BUDGET,
    edge_device: bool = False,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Build a passive capture session plan without opening a capture source."""
    timestamp = generated_at or _now()
    mode = _session_mode(session_mode)
    inventory = interface_inventory or enumerate_local_interfaces(interfaces=interfaces, generated_at=timestamp)
    interface_rows = [dict(row) for row in inventory.get("interfaces") or [] if isinstance(row, dict)]
    selected = _selected_interface_names(selected_interfaces, interface_rows)
    targets = build_capture_targets(selected_interfaces=selected, interfaces=interface_rows, generated_at=timestamp)
    resource_budget = build_interface_resource_budget_summary(
        interface_count=len(interface_rows),
        selected_interface_count=len(targets),
        edge_device=edge_device,
        generated_at=timestamp,
    )
    validation = validate_capture_session_plan_inputs(targets=targets, duration_seconds=duration_seconds, max_packets=max_packets)
    if not validation["ok"]:
        raise PassiveCaptureSessionError("; ".join(validation["errors"]))
    summary = summarize_capture_plan(targets=targets, resource_budget=resource_budget, generated_at=timestamp)
    dashboard = build_capture_plan_dashboard_record(summary=summary, targets=targets, generated_at=timestamp)
    api = build_capture_plan_api_response(summary=summary, targets=targets, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "passive_capture_session_plan",
        "record_version": CAPTURE_SESSION_RECORD_VERSION,
        "session_plan_id": _stable_id("passive-capture-plan", timestamp, selected, duration_seconds, max_packets),
        "session_mode": mode,
        "generated_at": timestamp,
        "duration_seconds": int(duration_seconds),
        "max_packets": int(max_packets),
        "selected_interfaces": selected,
        "capture_targets": targets,
        "interface_inventory_summary": dict(inventory.get("summary") or {}),
        "resource_budget": resource_budget,
        "validation": validation,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_capture_targets(
    *,
    selected_interfaces: Iterable[str],
    interfaces: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    rows_by_name = {str(row.get("interface_name") or ""): dict(row) for row in interfaces or [] if isinstance(row, dict)}
    targets = []
    for name in sorted(set(str(item) for item in selected_interfaces or [] if str(item).strip())):
        interface = rows_by_name.get(name, {})
        selectable = bool(interface.get("operator_selectable", True))
        targets.append(
            {
                "record_type": "passive_capture_target",
                "record_version": CAPTURE_SESSION_RECORD_VERSION,
                "target_id": _stable_id("capture-target", name, interface.get("interface_id")),
                "interface_name": name,
                "interface_id": str(interface.get("interface_id") or ""),
                "classification": str(interface.get("classification") or "unknown"),
                "operator_selected": True,
                "operator_selectable": selectable,
                "passive_mode": True,
                "capture_allowed": selectable,
                "address_family_summary": dict(interface.get("address_family_summary") or {}),
                "loopback": bool(interface.get("loopback")),
                "broadcast_capable": bool(interface.get("broadcast_capable")),
                "multicast_capable": bool(interface.get("multicast_capable")),
                "generated_at": timestamp,
                **TELEMETRY_SAFETY_FLAGS,
            }
        )
    return targets


def summarize_capture_plan(
    *,
    targets: Iterable[dict[str, Any]],
    resource_budget: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in targets or [] if isinstance(row, dict)]
    selected = len(rows)
    allowed = sum(1 for row in rows if row.get("capture_allowed"))
    return {
        "record_type": "passive_capture_plan_summary",
        "record_version": CAPTURE_SESSION_RECORD_VERSION,
        "generated_at": timestamp,
        "selected_interface_count": selected,
        "capture_allowed_count": allowed,
        "blocked_target_count": selected - allowed,
        "passive_mode_enforced": True,
        "dry_run": True,
        "packets_planned": 0,
        "packets_captured": 0,
        "resource_status": str(resource_budget.get("status") or "unknown"),
        "operator_summary": _operator_summary(selected, allowed, resource_budget),
        **TELEMETRY_SAFETY_FLAGS,
    }


def validate_capture_session_plan_inputs(
    *,
    targets: Iterable[dict[str, Any]],
    duration_seconds: int,
    max_packets: int,
) -> dict[str, Any]:
    errors: list[str] = []
    warnings: list[str] = []
    if int(duration_seconds) < 0:
        errors.append("duration_seconds cannot be negative")
    if int(max_packets) < 0:
        errors.append("max_packets cannot be negative")
    rows = [dict(row) for row in targets or [] if isinstance(row, dict)]
    if not rows:
        warnings.append("no interfaces selected")
    if any(not row.get("capture_allowed") for row in rows):
        warnings.append("one or more selected interfaces are not capture selectable")
    return {
        "ok": not errors,
        "errors": errors,
        "warnings": warnings,
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_capture_plan_dashboard_record(
    *,
    summary: dict[str, Any],
    targets: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "passive_capture_plan_dashboard",
        "panel": "passive_capture_plan",
        "status": "ok" if int(summary.get("blocked_target_count") or 0) == 0 else "review_required",
        "generated_at": timestamp,
        "metrics": {
            "selected_interface_count": int(summary.get("selected_interface_count") or 0),
            "capture_allowed_count": int(summary.get("capture_allowed_count") or 0),
            "blocked_target_count": int(summary.get("blocked_target_count") or 0),
            "packets_captured": 0,
        },
        "rows": [
            {
                "interface_name": row.get("interface_name"),
                "classification": row.get("classification"),
                "capture_allowed": row.get("capture_allowed"),
            }
            for row in sorted([dict(target) for target in targets or [] if isinstance(target, dict)], key=lambda item: str(item.get("interface_name") or ""))
        ],
        "recommended_review": bool(int(summary.get("blocked_target_count") or 0)),
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_capture_plan_api_response(
    *,
    summary: dict[str, Any],
    targets: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in targets or [] if isinstance(row, dict)]
    return {
        "record_type": "passive_capture_plan_api",
        "status": str(dashboard.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "targets": rows,
        "dashboard": dict(dashboard),
        **TELEMETRY_SAFETY_FLAGS,
    }


def deterministic_capture_plan_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _selected_interface_names(selected: Iterable[str] | None, interfaces: list[dict[str, Any]]) -> list[str]:
    requested = sorted(set(str(item) for item in selected or [] if str(item).strip()))
    if requested:
        return requested
    return [str(row.get("interface_name") or "") for row in interfaces if row.get("operator_selectable")][:1]


def _session_mode(value: str) -> str:
    mode = str(value or "dry-run")
    if mode not in CAPTURE_SESSION_MODES:
        raise PassiveCaptureSessionError(f"unsupported session_mode: {value}")
    return mode


def _operator_summary(selected: int, allowed: int, resource_budget: dict[str, Any]) -> str:
    if selected == 0:
        return "No passive capture interfaces selected; dry-run plan captures no packets."
    if selected != allowed:
        return f"Passive capture plan selected {selected} interface(s), with {selected - allowed} requiring review."
    if resource_budget.get("status") == "review_required":
        return f"Passive capture plan selected {selected} interface(s), but resource budget requires review."
    return f"Passive capture plan selected {selected} interface(s) in dry-run mode; no packets will be captured."


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
