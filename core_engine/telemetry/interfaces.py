from __future__ import annotations

import ipaddress
import json
import socket
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine import platform_utils
from core_engine.runtime.health import DEFAULT_RESOURCE_BUDGETS, RASPBERRY_PI_RESOURCE_BUDGETS
from core_engine.runtime.session_state import SAFETY_FLAGS


INTERFACE_RECORD_VERSION = 1
TELEMETRY_SAFETY_FLAGS = {
    **SAFETY_FLAGS,
    "local_only": True,
    "passive_first": True,
    "operator_controlled": True,
    "advisory_only": True,
    "capture_started": False,
    "packets_captured": 0,
    "raw_payload_stored": False,
    "privilege_escalation_attempted": False,
    "live_sniffing_loop_started": False,
    "external_transmission_enabled": False,
    "api_compatible": True,
}


class TelemetryInterfaceError(ValueError):
    """Raised when telemetry interface metadata is malformed."""


def enumerate_local_interfaces(
    *,
    interfaces: dict[str, Iterable[dict[str, Any]]] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    """Enumerate local interface metadata without starting packet capture."""
    timestamp = generated_at or _now()
    source = interfaces if interfaces is not None else platform_utils.network_interfaces()
    rows = [normalize_interface_metadata(name, addresses, generated_at=timestamp) for name, addresses in sorted(dict(source or {}).items())]
    summary = summarize_interfaces(rows, generated_at=timestamp)
    dashboard = build_interface_dashboard_record(summary=summary, interfaces=rows, generated_at=timestamp)
    api = build_interface_api_response(summary=summary, interfaces=rows, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "local_interface_inventory",
        "record_version": INTERFACE_RECORD_VERSION,
        "inventory_id": _stable_id("interface-inventory", timestamp, [row["interface_name"] for row in rows], summary),
        "generated_at": timestamp,
        "interfaces": rows,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **TELEMETRY_SAFETY_FLAGS,
    }


def normalize_interface_metadata(
    interface_name: str,
    addresses: Iterable[dict[str, Any]] | None,
    *,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    name = str(interface_name or "")
    if not name.strip():
        raise TelemetryInterfaceError("interface_name is required")
    address_rows = [normalize_interface_address(row) for row in addresses or [] if isinstance(row, dict)]
    family_summary = summarize_interface_address_families(address_rows)
    capability_summary = classify_interface_capabilities(name, address_rows)
    return {
        "record_type": "local_interface_summary",
        "record_version": INTERFACE_RECORD_VERSION,
        "interface_id": _stable_id("interface", name, address_rows),
        "interface_name": name,
        "display_name": name,
        "addresses": address_rows,
        "address_count": len(address_rows),
        "address_family_summary": family_summary,
        "loopback": capability_summary["loopback"],
        "broadcast_capable": capability_summary["broadcast_capable"],
        "multicast_capable": capability_summary["multicast_capable"],
        "link_local_only": capability_summary["link_local_only"],
        "classification": capability_summary["classification"],
        "operator_selectable": not capability_summary["unsupported_for_passive_capture"],
        "source_refs": [f"interface:{name}"],
        "generated_at": timestamp,
        **TELEMETRY_SAFETY_FLAGS,
    }


def normalize_interface_address(address: dict[str, Any]) -> dict[str, Any]:
    raw_family = address.get("family")
    raw_address = str(address.get("address") or "")
    family = normalize_address_family(raw_family, raw_address)
    parsed = _parse_ip(raw_address)
    broadcast = str(address.get("broadcast") or "")
    netmask = str(address.get("netmask") or "")
    return {
        "record_type": "interface_address",
        "family": family,
        "address": raw_address,
        "netmask": netmask,
        "broadcast": broadcast,
        "is_loopback": bool(parsed and parsed.is_loopback),
        "is_link_local": bool(parsed and parsed.is_link_local),
        "is_private": bool(parsed and parsed.is_private),
        "is_multicast": bool(parsed and parsed.is_multicast),
        "is_unspecified": bool(parsed and parsed.is_unspecified),
        "has_broadcast": bool(broadcast),
        **TELEMETRY_SAFETY_FLAGS,
    }


def normalize_address_family(raw_family: Any, address: str = "") -> str:
    text = str(raw_family or "")
    if "AF_INET6" in text or text in {str(socket.AF_INET6), "AddressFamily.AF_INET6"}:
        return "ipv6"
    if "AF_INET" in text or text in {str(socket.AF_INET), "AddressFamily.AF_INET"}:
        return "ipv4"
    try:
        parsed = ipaddress.ip_address(str(address))
    except ValueError:
        return "other"
    return "ipv6" if parsed.version == 6 else "ipv4"


def summarize_interface_address_families(addresses: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = [dict(row) for row in addresses or [] if isinstance(row, dict)]
    by_family: dict[str, int] = {}
    for row in rows:
        family = str(row.get("family") or "other")
        by_family[family] = by_family.get(family, 0) + 1
    return {
        "record_type": "interface_address_family_summary",
        "ipv4_count": by_family.get("ipv4", 0),
        "ipv6_count": by_family.get("ipv6", 0),
        "other_count": by_family.get("other", 0),
        "by_family": dict(sorted(by_family.items())),
        **TELEMETRY_SAFETY_FLAGS,
    }


def classify_interface_capabilities(interface_name: str, addresses: Iterable[dict[str, Any]]) -> dict[str, Any]:
    rows = [dict(row) for row in addresses or [] if isinstance(row, dict)]
    name = str(interface_name or "").lower()
    has_loopback = name.startswith(("lo", "loopback")) or any(row.get("is_loopback") for row in rows)
    has_broadcast = any(row.get("has_broadcast") for row in rows)
    has_multicast = any(row.get("is_multicast") for row in rows)
    has_link_local = bool(rows) and all(row.get("is_link_local") for row in rows if row.get("family") in {"ipv4", "ipv6"})
    classification = "loopback" if has_loopback else "link_local" if has_link_local else "network"
    return {
        "loopback": bool(has_loopback),
        "broadcast_capable": bool(has_broadcast),
        "multicast_capable": bool(has_multicast or not has_loopback),
        "link_local_only": bool(has_link_local),
        "classification": classification,
        "unsupported_for_passive_capture": False,
        **TELEMETRY_SAFETY_FLAGS,
    }


def summarize_interfaces(interfaces: Iterable[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    timestamp = generated_at or _now()
    rows = [dict(row) for row in interfaces or [] if isinstance(row, dict)]
    by_classification: dict[str, int] = {}
    for row in rows:
        classification = str(row.get("classification") or "unknown")
        by_classification[classification] = by_classification.get(classification, 0) + 1
    return {
        "record_type": "local_interface_inventory_summary",
        "generated_at": timestamp,
        "interface_count": len(rows),
        "operator_selectable_count": sum(1 for row in rows if row.get("operator_selectable")),
        "loopback_count": sum(1 for row in rows if row.get("loopback")),
        "broadcast_capable_count": sum(1 for row in rows if row.get("broadcast_capable")),
        "multicast_capable_count": sum(1 for row in rows if row.get("multicast_capable")),
        "ipv4_interface_count": sum(1 for row in rows if int((row.get("address_family_summary") or {}).get("ipv4_count") or 0)),
        "ipv6_interface_count": sum(1 for row in rows if int((row.get("address_family_summary") or {}).get("ipv6_count") or 0)),
        "by_classification": dict(sorted(by_classification.items())),
        "operator_summary": _inventory_operator_summary(rows),
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_interface_resource_budget_summary(
    *,
    interface_count: int,
    selected_interface_count: int = 0,
    edge_device: bool = False,
    max_interfaces: int | None = None,
    max_selected_interfaces: int | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    budgets = RASPBERRY_PI_RESOURCE_BUDGETS if edge_device else DEFAULT_RESOURCE_BUDGETS
    interface_limit = int(max_interfaces or (8 if edge_device else 16))
    selected_limit = int(max_selected_interfaces or (1 if edge_device else 4))
    warnings = []
    if int(interface_count) > interface_limit:
        warnings.append("interface_count_exceeds_budget")
    if int(selected_interface_count) > selected_limit:
        warnings.append("selected_interface_count_exceeds_budget")
    return {
        "record_type": "interface_resource_budget_summary",
        "generated_at": timestamp,
        "edge_device": bool(edge_device),
        "interface_count": int(interface_count),
        "selected_interface_count": int(selected_interface_count),
        "max_interfaces": interface_limit,
        "max_selected_interfaces": selected_limit,
        "event_queue_warning_depth": int(budgets["event_queue_warning_depth"]),
        "status": "within_budget" if not warnings else "review_required",
        "warnings": warnings,
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_interface_dashboard_record(
    *,
    summary: dict[str, Any],
    interfaces: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    return {
        "record_type": "interface_inventory_dashboard",
        "panel": "passive_interfaces",
        "status": "ok",
        "generated_at": timestamp,
        "metrics": {
            "interface_count": int(summary.get("interface_count") or 0),
            "operator_selectable_count": int(summary.get("operator_selectable_count") or 0),
            "loopback_count": int(summary.get("loopback_count") or 0),
            "ipv4_interface_count": int(summary.get("ipv4_interface_count") or 0),
            "ipv6_interface_count": int(summary.get("ipv6_interface_count") or 0),
        },
        "rows": [
            {
                "interface_name": row.get("interface_name"),
                "classification": row.get("classification"),
                "address_count": row.get("address_count"),
                "operator_selectable": row.get("operator_selectable"),
            }
            for row in sorted([dict(item) for item in interfaces or [] if isinstance(item, dict)], key=lambda item: str(item.get("interface_name") or ""))
        ],
        "recommended_review": False,
        **TELEMETRY_SAFETY_FLAGS,
    }


def build_interface_api_response(
    *,
    summary: dict[str, Any],
    interfaces: Iterable[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    rows = [dict(row) for row in interfaces or [] if isinstance(row, dict)]
    return {
        "record_type": "interface_inventory_api",
        "status": "ok",
        "generated_at": generated_at or _now(),
        "count": len(rows),
        "summary": dict(summary),
        "interfaces": rows,
        "dashboard": dict(dashboard),
        **TELEMETRY_SAFETY_FLAGS,
    }


def deterministic_interface_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _inventory_operator_summary(rows: list[dict[str, Any]]) -> str:
    selectable = sum(1 for row in rows if row.get("operator_selectable"))
    return f"Passive interface discovery found {len(rows)} interface(s), {selectable} selectable for dry-run capture planning."


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(str(value).split("%", 1)[0])
    except ValueError:
        return None


def _stable_id(prefix: str, *parts: Any) -> str:
    material = json.dumps(parts, sort_keys=True, default=str, separators=(",", ":"))
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
