from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.firewall_plugins import PLUGIN_MAP
from core_engine.platform.capabilities import CAPABILITY_STATUSES, PLATFORM_CAPABILITY_SAFETY_FLAGS
from core_engine.remediation_safety import enforce_remediation_command_safety


FIREWALL_PROVIDER_RECORD_VERSION = 1

FIREWALL_PROVIDER_SAFETY_FLAGS = {
    **PLATFORM_CAPABILITY_SAFETY_FLAGS,
    "firewall_readiness_only": True,
    "dry_run_only": True,
    "rule_preview_only": True,
    "rule_applied": False,
    "firewall_rules_changed": False,
    "windows_defender_modified": False,
    "pf_modified": False,
    "nftables_modified": False,
    "ufw_modified": False,
    "iptables_modified": False,
    "automatic_blocking": False,
    "provider_install_attempted": False,
    "admin_elevation_requested": False,
}


DEFAULT_FIREWALL_PROVIDERS_BY_PLATFORM = {
    "windows": ("windows_defender_firewall",),
    "macos": ("pf",),
    "linux": ("nftables", "ufw", "iptables"),
    "raspberry-pi-linux-arm": ("nftables", "ufw", "iptables"),
}


def build_firewall_provider_summary(
    *,
    platform_record: dict[str, Any] | None = None,
    provider_statuses: dict[str, str] | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    platform_family = str((platform_record or {}).get("platform_family") or "unknown")
    providers = [
        build_firewall_provider_record(
            provider_name=name,
            platform_family=platform_family,
            status=(provider_statuses or {}).get(name),
            generated_at=timestamp,
        )
        for name in DEFAULT_FIREWALL_PROVIDERS_BY_PLATFORM.get(platform_family, ("unknown_firewall_provider",))
    ]
    summary = summarize_firewall_providers(providers, generated_at=timestamp)
    dashboard = build_firewall_provider_dashboard_record(summary=summary, providers=providers, generated_at=timestamp)
    api = build_firewall_provider_api_response(summary=summary, providers=providers, dashboard=dashboard, generated_at=timestamp)
    return {
        "record_type": "firewall_provider_summary",
        "record_version": FIREWALL_PROVIDER_RECORD_VERSION,
        "provider_summary_id": "firewall-providers-" + _digest({"generated_at": timestamp, "platform_family": platform_family, "providers": providers})[:16],
        "generated_at": timestamp,
        "platform_family": platform_family,
        "providers": sorted(providers, key=lambda item: str(item.get("provider_name") or "")),
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **FIREWALL_PROVIDER_SAFETY_FLAGS,
    }


def build_firewall_provider_record(
    *,
    provider_name: str,
    platform_family: str,
    status: str | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    normalized_name = str(provider_name or "unknown_firewall_provider")
    default_status, warnings = _default_provider_status(normalized_name, platform_family)
    normalized_status = _status(status or default_status)
    details = _provider_details(normalized_name, platform_family)
    record = {
        "record_type": "firewall_provider_readiness",
        "record_version": FIREWALL_PROVIDER_RECORD_VERSION,
        "provider_name": normalized_name,
        "platform_family": str(platform_family or "unknown"),
        "status": normalized_status,
        "provider_label": details["provider_label"],
        "registry_plugin": details["registry_plugin"],
        "registered_plugin_available": details["registry_plugin"] in PLUGIN_MAP,
        "requires_manual_permission": details["requires_manual_permission"],
        "requires_admin_or_root_for_future_rules": details["requires_admin_or_root_for_future_rules"],
        "preview_command_family": details["preview_command_family"],
        "warnings": sorted(set(warnings + _status_warnings(normalized_status))),
        "generated_at": timestamp,
        **FIREWALL_PROVIDER_SAFETY_FLAGS,
    }
    record["provider_id"] = "firewall-provider-" + _digest(record)[:16]
    return record


def build_firewall_rule_preview(
    *,
    provider_name: str,
    decision: str = "block",
    protocol: str = "tcp",
    port: int | str = "<service-port>",
    target_ref: str = "<endpoint-ref>",
    reason: str = "operator-review-placeholder",
    generated_at: str | None = None,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    command = enforce_remediation_command_safety(
        {
            "type": "firewall_rule_preview",
            "decision": str(decision or "block"),
            "protocol": str(protocol or "tcp"),
            "port": str(port),
            "target_ref": str(target_ref or "<endpoint-ref>"),
            "reason": str(reason or "operator-review-placeholder"),
            "dry_run": True,
            "confirmed": False,
            "metadata": {
                "provider_name": str(provider_name or "unknown_firewall_provider"),
                "preview_only": True,
            },
        },
        {"firewall": {"dry_run": True}, "remediation_safety": {"active_enforcement_enabled": False}},
    )
    record = {
        "record_type": "firewall_rule_preview",
        "record_version": FIREWALL_PROVIDER_RECORD_VERSION,
        "preview_id": "firewall-rule-preview-" + _digest({"provider": provider_name, "command": command, "generated_at": timestamp})[:16],
        "generated_at": timestamp,
        "provider_name": str(provider_name or "unknown_firewall_provider"),
        "preview_command": _provider_preview_command(str(provider_name or ""), command),
        "command": command,
        "operator_review_required": True,
        "rule_safety_warnings": [
            "dry_run_preview_only",
            "manual_operator_review_required",
            "automatic_blocking_disabled",
        ],
        **FIREWALL_PROVIDER_SAFETY_FLAGS,
    }
    return record


def summarize_firewall_providers(providers: list[dict[str, Any]], *, generated_at: str | None = None) -> dict[str, Any]:
    rows = [dict(row) for row in providers or [] if isinstance(row, dict)]
    counts = {status: sum(1 for row in rows if row.get("status") == status) for status in sorted(CAPABILITY_STATUSES)}
    if counts["supported"]:
        status = "supported" if not counts["degraded"] and not counts["unavailable"] and not counts["unknown"] else "degraded"
    elif counts["degraded"]:
        status = "degraded"
    elif counts["unavailable"]:
        status = "unavailable"
    else:
        status = "unknown"
    warnings = sorted({warning for row in rows for warning in row.get("warnings") or []})
    return {
        "record_type": "firewall_provider_rollup",
        "record_version": FIREWALL_PROVIDER_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        "status": status,
        "provider_count": len(rows),
        "supported_count": counts["supported"],
        "degraded_count": counts["degraded"],
        "unavailable_count": counts["unavailable"],
        "unknown_count": counts["unknown"],
        "providers_by_status": counts,
        "warnings": warnings,
        **FIREWALL_PROVIDER_SAFETY_FLAGS,
    }


def build_firewall_provider_dashboard_record(
    *,
    summary: dict[str, Any],
    providers: list[dict[str, Any]],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "firewall_provider_dashboard",
        "panel": "firewall_providers",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "metrics": {
            "provider_count": int(summary.get("provider_count") or 0),
            "supported_count": int(summary.get("supported_count") or 0),
            "degraded_count": int(summary.get("degraded_count") or 0),
            "unavailable_count": int(summary.get("unavailable_count") or 0),
            "unknown_count": int(summary.get("unknown_count") or 0),
        },
        "rows": [
            {
                "provider_name": row.get("provider_name"),
                "provider_label": row.get("provider_label"),
                "status": row.get("status"),
                "registered_plugin_available": row.get("registered_plugin_available"),
                "warning_count": len(row.get("warnings") or []),
            }
            for row in sorted(providers, key=lambda item: str(item.get("provider_name") or ""))
        ],
        "recommended_review": True,
        **FIREWALL_PROVIDER_SAFETY_FLAGS,
    }


def build_firewall_provider_api_response(
    *,
    summary: dict[str, Any],
    providers: list[dict[str, Any]],
    dashboard: dict[str, Any],
    generated_at: str | None = None,
) -> dict[str, Any]:
    return {
        "record_type": "firewall_provider_api",
        "status": str(summary.get("status") or "unknown"),
        "generated_at": generated_at or _now(),
        "summary": dict(summary),
        "providers": sorted([dict(row) for row in providers], key=lambda item: str(item.get("provider_name") or "")),
        "dashboard": dict(dashboard),
        **FIREWALL_PROVIDER_SAFETY_FLAGS,
    }


def deterministic_firewall_provider_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _default_provider_status(provider_name: str, platform_family: str) -> tuple[str, list[str]]:
    if platform_family == "windows":
        return "degraded", ["windows_defender_firewall_preview_only"]
    if platform_family == "macos":
        return "degraded", ["pf_preview_only"]
    if platform_family == "linux":
        if provider_name == "iptables":
            return "degraded", ["linux_iptables_plugin_available_dry_run_only"]
        return "degraded", ["linux_firewall_provider_preview_only"]
    if platform_family == "raspberry-pi-linux-arm":
        if provider_name == "iptables":
            return "degraded", ["linux_iptables_plugin_available_dry_run_only", "edge_device_resource_review_required"]
        return "degraded", ["linux_firewall_provider_preview_only", "edge_device_resource_review_required"]
    return "unknown", ["platform_family_unknown"]


def _provider_details(provider_name: str, platform_family: str) -> dict[str, Any]:
    labels = {
        "windows_defender_firewall": "Windows Defender Firewall",
        "pf": "macOS pf",
        "nftables": "Linux nftables",
        "ufw": "Linux ufw",
        "iptables": "Linux iptables",
    }
    registry_plugin = "linux_iptables" if provider_name == "iptables" else "noop" if provider_name == "unknown_firewall_provider" else ""
    return {
        "provider_label": labels.get(provider_name, provider_name),
        "registry_plugin": registry_plugin,
        "requires_manual_permission": platform_family in {"windows", "macos", "linux", "raspberry-pi-linux-arm"},
        "requires_admin_or_root_for_future_rules": platform_family in {"windows", "macos", "linux", "raspberry-pi-linux-arm"},
        "preview_command_family": provider_name.replace("_", "-"),
    }


def _provider_preview_command(provider_name: str, command: dict[str, Any]) -> str:
    protocol = str(command.get("protocol") or "tcp")
    port = str(command.get("port") or "<service-port>")
    if provider_name == "windows_defender_firewall":
        return f"<windows-defender-firewall-preview> protocol={protocol} port={port} action=block"
    if provider_name == "pf":
        return f"<pf-preview> block {protocol} to port {port}"
    if provider_name == "nftables":
        return f"<nftables-preview> add rule inet filter output {protocol} dport {port} drop"
    if provider_name == "ufw":
        return f"<ufw-preview> deny {port}/{protocol}"
    if provider_name == "iptables":
        return f"<iptables-preview> -p {protocol} --dport {port} -j DROP"
    return "<firewall-provider-preview>"


def _status(value: str) -> str:
    return value if value in CAPABILITY_STATUSES else "unknown"


def _status_warnings(status: str) -> list[str]:
    if status == "supported":
        return ["provider_still_preview_only"]
    if status == "degraded":
        return ["provider_requires_operator_review"]
    if status == "unavailable":
        return ["provider_unavailable"]
    return ["provider_state_unknown"]


def _digest(payload: Any) -> str:
    return sha256(deterministic_firewall_provider_json(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "DEFAULT_FIREWALL_PROVIDERS_BY_PLATFORM",
    "FIREWALL_PROVIDER_RECORD_VERSION",
    "FIREWALL_PROVIDER_SAFETY_FLAGS",
    "build_firewall_provider_api_response",
    "build_firewall_provider_dashboard_record",
    "build_firewall_provider_record",
    "build_firewall_provider_summary",
    "build_firewall_rule_preview",
    "deterministic_firewall_provider_json",
    "summarize_firewall_providers",
]
