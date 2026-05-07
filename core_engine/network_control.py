from __future__ import annotations

import ipaddress
import re
from typing import Any

from core_engine import platform_utils
from core_engine.modules.scanner import basic_scan
from core_engine.risky_ports import port_metadata


WILDCARD_HOSTS = {"0.0.0.0", "::", "*", ""}
LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost"}


def _parse_linux_gateway(output: str) -> dict[str, str] | None:
    for line in output.splitlines():
        parts = line.split()
        if not parts or parts[0] != "default":
            continue
        gateway = ""
        interface = ""
        if "via" in parts:
            gateway = parts[parts.index("via") + 1]
        if "dev" in parts:
            interface = parts[parts.index("dev") + 1]
        if gateway or interface:
            return {"gateway_ip": gateway, "interface": interface, "source": "ip route"}
    return None


def _parse_darwin_gateway(output: str) -> dict[str, str] | None:
    gateway = ""
    interface = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("gateway:"):
            gateway = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
    if gateway or interface:
        return {"gateway_ip": gateway, "interface": interface, "source": "route get default"}
    return None


def _parse_windows_gateway(output: str) -> dict[str, str] | None:
    for line in output.splitlines():
        if "0.0.0.0" not in line:
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
            return {"gateway_ip": parts[2], "interface": parts[3], "source": "route print"}
    return None


def detect_default_gateway() -> dict[str, str]:
    info = platform_utils.get_platform_info()
    candidates: list[tuple[list[str], Any]] = []
    if info.is_linux and platform_utils.find_executable("ip"):
        candidates.append((["ip", "route", "show", "default"], _parse_linux_gateway))
    elif info.is_macos and platform_utils.find_executable("route"):
        candidates.append((["route", "-n", "get", "default"], _parse_darwin_gateway))
    elif info.is_windows and platform_utils.find_executable("route"):
        candidates.append((["route", "print", "0.0.0.0"], _parse_windows_gateway))

    for command, parser in candidates:
        try:
            result = platform_utils.run_command(command, check=False, capture_output=True, text=True, timeout=3)
        except Exception:
            continue
        parsed = parser((result.stdout or "") + "\n" + (result.stderr or ""))
        if parsed:
            return parsed
    return {"gateway_ip": "", "interface": "", "source": "unavailable"}


def local_networks() -> list[dict[str, Any]]:
    networks: list[dict[str, Any]] = []
    for name, addresses in platform_utils.network_interfaces().items():
        for address in addresses:
            raw = address.get("address")
            netmask = address.get("netmask")
            if not raw or not netmask or ":" in str(raw):
                continue
            try:
                ip = ipaddress.ip_address(str(raw))
                network = ipaddress.ip_network(f"{raw}/{netmask}", strict=False)
            except ValueError:
                continue
            if ip.is_loopback or ip.is_link_local:
                continue
            networks.append(
                {
                    "interface": name,
                    "address": str(ip),
                    "network": str(network),
                    "private": ip.is_private,
                }
            )
    return networks


def _extract_host(endpoint: Any) -> str:
    if not endpoint or endpoint == "-":
        return ""
    value = str(endpoint)
    if value.startswith("[") and "]:" in value:
        return value[1:].split("]:", 1)[0]
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    return value


def _exposure_level(host: str) -> str:
    if host in WILDCARD_HOSTS:
        return "all_interfaces"
    if host in LOOPBACK_HOSTS:
        return "loopback_only"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    if ip.is_loopback:
        return "loopback_only"
    if ip.is_private:
        return "lan_interface"
    return "public_interface"


def _recommend_for_service(row: dict[str, Any], exposure: str) -> str:
    port = row.get("port", "-")
    program = row.get("program") or "unknown"
    metadata = port_metadata(port)
    service = (metadata or {}).get("service") or row.get("service_name") or row.get("protocol") or "service"
    if exposure == "all_interfaces":
        return f"Review {program} exposing {service} on port {port} to all interfaces; bind to a specific LAN IP or localhost if not intentionally shared."
    if exposure == "public_interface":
        return f"Review {program} on port {port}; it appears bound to a public interface."
    if metadata and metadata.get("severity") in {"high", "critical"}:
        return f"Confirm {service} on port {port} is expected and protected by firewall policy."
    return f"Confirm {program} on port {port} is expected for this host."


def exposed_services(scan_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    exposed: list[dict[str, Any]] = []
    for row in scan_rows:
        if str(row.get("status") or "").upper() != "LISTEN":
            continue
        host = _extract_host(row.get("local"))
        exposure = _exposure_level(host)
        if exposure == "loopback_only":
            continue
        metadata = port_metadata(row.get("port"))
        item = {
            "program": row.get("program") or "unknown",
            "pid": row.get("pid", 0),
            "port": row.get("port", 0),
            "protocol": row.get("protocol") or "Unknown",
            "service_name": row.get("service_name") or (metadata or {}).get("service") or "",
            "local": row.get("local") or "-",
            "exposure": exposure,
            "severity": (metadata or {}).get("severity", "unknown"),
            "recommendation": _recommend_for_service(row, exposure),
        }
        exposed.append(item)
    return exposed


def network_recommendations(gateway: dict[str, str], services: list[dict[str, Any]]) -> list[str]:
    recommendations: list[str] = []
    if not gateway.get("gateway_ip"):
        recommendations.append("No default gateway was detected; verify host network configuration before relying on network posture results.")
    else:
        recommendations.append("Review router administration settings manually; PortMap-AI does not change router configuration.")

    if not services:
        recommendations.append("No non-loopback listening services were detected in the current local scan.")
    else:
        high = [item for item in services if item.get("severity") in {"high", "critical"}]
        if high:
            ports = ", ".join(str(item.get("port")) for item in high[:5])
            recommendations.append(f"Prioritize review of high-risk exposed ports: {ports}.")
        recommendations.append("Confirm each exposed service is expected, patched, and limited by host/router firewall policy.")

    recommendations.append("Keep remediation advisory-only unless an explicit policy and confirmation flow enables active enforcement.")
    return recommendations


def assess_network_posture(scan_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    rows = scan_rows if scan_rows is not None else basic_scan()
    gateway = detect_default_gateway()
    services = exposed_services(rows)
    return {
        "advisory_only": True,
        "automatic_changes": False,
        "gateway": gateway,
        "local_networks": local_networks(),
        "exposed_services": services,
        "recommendations": network_recommendations(gateway, services),
        "safety_notes": [
            "No router settings are changed.",
            "No firewall rules are changed by this assessment.",
            "LAN-wide scanning should remain opt-in, scoped, and rate-limited.",
        ],
    }


def summarize_posture(posture: dict[str, Any]) -> str:
    gateway = posture.get("gateway") or {}
    services = posture.get("exposed_services") or []
    lines = [
        "PortMap-AI Network Posture",
        f"Gateway: {gateway.get('gateway_ip') or '-'} ({gateway.get('interface') or '-'})",
        f"Local networks: {len(posture.get('local_networks') or [])}",
        f"Exposed services: {len(services)}",
        "Mode: advisory only; no automatic changes",
    ]
    for item in services[:8]:
        lines.append(
            f"- {item.get('program')} {item.get('protocol')}:{item.get('port')} "
            f"{item.get('exposure')} severity={item.get('severity')}"
        )
    lines.append("Recommendations:")
    for recommendation in posture.get("recommendations") or []:
        lines.append(f"- {recommendation}")
    return "\n".join(lines)


__all__ = [
    "assess_network_posture",
    "detect_default_gateway",
    "exposed_services",
    "local_networks",
    "network_recommendations",
    "summarize_posture",
]
