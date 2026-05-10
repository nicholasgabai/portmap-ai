from __future__ import annotations

import errno
import ipaddress
import json
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Protocol

from core_engine import platform_utils
from core_engine.modules.ip_utils import TargetAddress, expand_targets, normalize_ip_version
from core_engine.modules.ipv6_scanner import SocketFactory, scan_tcp_port
from core_engine.network_control import detect_default_gateway, local_networks


ASSET_STATUSES = {"reachable", "unreachable", "unknown"}
DEFAULT_DISCOVERY_PORTS = (22, 80, 443)
DEFAULT_TIMEOUT = 1.0
DEFAULT_MAX_TARGETS = 256
DEFAULT_RATE_DELAY = 0.01
AGGRESSIVE_MAX_TARGETS = 4096


class CommandResult(Protocol):
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[..., CommandResult]


@dataclass
class NetworkAsset:
    host: str
    ip_version: int
    status: str = "unknown"
    target_source: str = "unknown"
    private: bool = False
    loopback: bool = False
    methods: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    mac: str = ""
    interface: str = ""
    open_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "asset_type": "network_asset",
            "host": self.host,
            "ip_version": self.ip_version,
            "status": self.status,
            "target_source": self.target_source,
            "private": self.private,
            "loopback": self.loopback,
            "methods": list(self.methods),
            "evidence": list(self.evidence),
            "mac": self.mac,
            "interface": self.interface,
            "open_ports": list(self.open_ports),
            "closed_ports": list(self.closed_ports),
        }

    def to_orchestrator_telemetry(self, *, node_id: str | None = None) -> dict[str, Any]:
        payload = {
            "type": "asset_inventory",
            "source": "portmap.asset_inventory",
            "target": self.host,
            "asset": self.to_dict(),
        }
        if node_id:
            payload["node_id"] = node_id
        return payload


def _append_method(asset: NetworkAsset, method: str) -> None:
    if method not in asset.methods:
        asset.methods.append(method)


def _append_evidence(asset: NetworkAsset, evidence: dict[str, Any]) -> None:
    method = str(evidence.get("method") or "unknown")
    _append_method(asset, method)
    asset.evidence.append(evidence)


def _normalize_methods(methods: Iterable[str] | None) -> list[str]:
    selected = [str(method).strip().lower() for method in (methods or ("arp", "tcp")) if str(method).strip()]
    allowed = {"arp", "ping", "tcp"}
    unknown = sorted(set(selected) - allowed)
    if unknown:
        raise ValueError(f"unsupported discovery method(s): {', '.join(unknown)}")
    return selected or ["arp", "tcp"]


def _classify_status(asset: NetworkAsset, negative_evidence_seen: bool) -> None:
    if any(item.get("reachable") is True for item in asset.evidence):
        asset.status = "reachable"
    elif negative_evidence_seen:
        asset.status = "unreachable"
    else:
        asset.status = "unknown"


def parse_arp_table(output: str) -> list[dict[str, str]]:
    """Parse common macOS, Linux, and Windows ARP/neighbor table formats."""
    rows: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    mac_pattern = re.compile(r"(?:[0-9a-fA-F]{1,2}[:-]){5}[0-9a-fA-F]{1,2}")
    ipv4_pattern = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    for line in output.splitlines():
        mac_match = mac_pattern.search(line)
        ip_match = ipv4_pattern.search(line)
        if not mac_match or not ip_match:
            continue
        ip_text = ip_match.group(0)
        try:
            ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        mac = mac_match.group(0).replace("-", ":").lower()
        interface = ""
        on_match = re.search(r"\bon\s+([^\s]+)", line)
        dev_match = re.search(r"\bdev\s+([^\s]+)", line)
        if on_match:
            interface = on_match.group(1)
        elif dev_match:
            interface = dev_match.group(1)
        key = (ip_text, mac)
        if key in seen:
            continue
        seen.add(key)
        rows.append({"host": ip_text, "mac": mac, "interface": interface, "source": "arp"})
    return rows


def collect_arp_inventory(
    *,
    arp_output: str | None = None,
    command_runner: CommandRunner | None = None,
) -> list[dict[str, str]]:
    """Read the local ARP/neighbor table without sending probes."""
    if arp_output is not None:
        return parse_arp_table(arp_output)
    runner = command_runner or platform_utils.run_command
    commands: list[list[str]] = []
    if platform_utils.find_executable("arp"):
        commands.append(["arp", "-a"])
    if platform_utils.find_executable("ip"):
        commands.append(["ip", "neigh", "show"])
    for command in commands:
        try:
            result = runner(command, check=False, capture_output=True, text=True, timeout=3)
        except Exception:
            continue
        output = (getattr(result, "stdout", "") or "") + "\n" + (getattr(result, "stderr", "") or "")
        rows = parse_arp_table(output)
        if rows:
            return rows
    return []


def broadcast_candidates(ranges: Iterable[str]) -> list[dict[str, str]]:
    candidates: list[dict[str, str]] = []
    for raw in ranges:
        value = str(raw).strip()
        if "/" not in value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            continue
        if network.version != 4 or network.num_addresses <= 1:
            continue
        candidates.append({
            "network": str(network),
            "broadcast": str(network.broadcast_address),
            "method": "broadcast_candidate",
        })
    return candidates


def local_network_ranges() -> list[str]:
    return [str(item["network"]) for item in local_networks() if item.get("network")]


def local_topology_snapshot(*, include_arp: bool = True) -> dict[str, Any]:
    networks = local_networks()
    ranges = [str(item["network"]) for item in networks if item.get("network")]
    return {
        "gateway": detect_default_gateway(),
        "local_networks": networks,
        "broadcast_candidates": broadcast_candidates(ranges),
        "arp_inventory": collect_arp_inventory() if include_arp else [],
        "advisory_only": True,
        "automatic_changes": False,
    }


def ping_reachability(
    target: TargetAddress,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    command_runner: CommandRunner | None = None,
) -> dict[str, Any]:
    """Check reachability through the platform ping utility when available."""
    if timeout <= 0:
        raise ValueError("ping timeout must be greater than 0")
    runner = command_runner or platform_utils.run_command
    info = platform_utils.get_platform_info()
    timeout_ms = max(1, int(timeout * 1000))
    timeout_seconds = max(1, int(round(timeout)))
    command: list[str] | None = None
    if info.is_windows and platform_utils.find_executable("ping"):
        command = ["ping", "-n", "1", "-w", str(timeout_ms), target.host]
    elif target.version == 6 and platform_utils.find_executable("ping6"):
        command = ["ping6", "-c", "1", "-W", str(timeout_seconds), target.host]
    elif platform_utils.find_executable("ping"):
        command = ["ping"]
        if target.version == 6:
            command.append("-6")
        command.extend(["-c", "1", "-W", str(timeout_seconds), target.host])
    if not command:
        return {"method": "ping", "reachable": None, "reason": "ping_unavailable"}
    try:
        result = runner(command, check=False, capture_output=True, text=True, timeout=timeout + 1)
    except Exception as exc:
        return {"method": "ping", "reachable": None, "reason": type(exc).__name__}
    return {
        "method": "ping",
        "reachable": getattr(result, "returncode", 1) == 0,
        "reason": "ping_success" if getattr(result, "returncode", 1) == 0 else "ping_failed",
    }


def tcp_reachability(
    target: TargetAddress,
    ports: Iterable[int] = DEFAULT_DISCOVERY_PORTS,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    socket_factory: SocketFactory | None = None,
) -> tuple[list[dict[str, Any]], list[int], list[int]]:
    evidence: list[dict[str, Any]] = []
    open_ports: list[int] = []
    closed_ports: list[int] = []
    for port in ports:
        row = scan_tcp_port(
            target,
            int(port),
            timeout=timeout,
            socket_factory=socket_factory if socket_factory is not None else socket.socket,
        )
        state = row.get("tcp_state")
        reachable = state in {"open", "closed"}
        if state == "open":
            open_ports.append(int(port))
        elif state == "closed":
            closed_ports.append(int(port))
        evidence.append({
            "method": "tcp",
            "port": int(port),
            "reachable": reachable,
            "state": state,
            "reason": row.get("reason", "unknown"),
        })
    return evidence, open_ports, closed_ports


def _targets_from_ranges(
    ranges: Iterable[str] | None,
    *,
    include_local: bool,
    ip_version: str | int | None,
    max_targets: int,
) -> list[TargetAddress]:
    selected_ranges = list(ranges or [])
    if include_local:
        selected_ranges.extend(local_network_ranges())
    if not selected_ranges:
        raise ValueError("at least one authorized range or --local-networks is required")
    return expand_targets(selected_ranges, ip_version=ip_version, max_targets=max_targets, resolve_names=True)


def inventory_network_assets(
    ranges: Iterable[str] | None = None,
    *,
    include_local_networks: bool = False,
    methods: Iterable[str] | None = None,
    tcp_ports: Iterable[int] = DEFAULT_DISCOVERY_PORTS,
    ip_version: str | int | None = "auto",
    timeout: float = DEFAULT_TIMEOUT,
    max_targets: int = DEFAULT_MAX_TARGETS,
    rate_delay: float = DEFAULT_RATE_DELAY,
    aggressive: bool = False,
    arp_output: str | None = None,
    command_runner: CommandRunner | None = None,
    socket_factory: SocketFactory | None = None,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    """Build a conservative inventory of assets in authorized ranges."""
    if timeout <= 0:
        raise ValueError("discovery timeout must be greater than 0")
    if rate_delay < 0:
        raise ValueError("discovery rate_delay must be 0 or greater")
    version = normalize_ip_version(ip_version)
    target_limit = max(max_targets, AGGRESSIVE_MAX_TARGETS) if aggressive else max_targets
    selected_methods = _normalize_methods(methods)
    targets = _targets_from_ranges(
        ranges,
        include_local=include_local_networks,
        ip_version=version,
        max_targets=target_limit,
    )
    if not aggressive and len(targets) > max_targets:
        raise ValueError(f"asset inventory limited to {max_targets} targets by default; enable aggressive mode to override")
    arp_rows = collect_arp_inventory(arp_output=arp_output, command_runner=command_runner) if "arp" in selected_methods else []
    arp_by_host = {row["host"]: row for row in arp_rows}

    assets: list[NetworkAsset] = []
    for index, target in enumerate(targets):
        asset = NetworkAsset(
            host=target.host,
            ip_version=target.version,
            target_source=target.source,
            private=target.private,
            loopback=target.loopback,
        )
        negative_seen = False
        arp_match = arp_by_host.get(target.host)
        if arp_match:
            asset.mac = arp_match.get("mac", "")
            asset.interface = arp_match.get("interface", "")
            _append_evidence(
                asset,
                {
                    "method": "arp",
                    "reachable": True,
                    "mac": asset.mac,
                    "interface": asset.interface,
                    "reason": "arp_table_entry",
                },
            )
        if "ping" in selected_methods:
            evidence = ping_reachability(target, timeout=timeout, command_runner=command_runner)
            _append_evidence(asset, evidence)
            if evidence.get("reachable") is False:
                negative_seen = True
        if "tcp" in selected_methods:
            tcp_evidence, open_ports, closed_ports = tcp_reachability(
                target,
                tcp_ports,
                timeout=timeout,
                socket_factory=socket_factory,
            )
            asset.open_ports.extend(open_ports)
            asset.closed_ports.extend(closed_ports)
            for evidence in tcp_evidence:
                _append_evidence(asset, evidence)
                if evidence.get("reachable") is False:
                    negative_seen = True
        _classify_status(asset, negative_seen)
        assets.append(asset)
        if logger:
            logger.info("asset_inventory_result %s", json.dumps(asset.to_dict(), sort_keys=True))
        if rate_delay and index < len(targets) - 1:
            time.sleep(rate_delay)
    return [asset.to_dict() for asset in assets]


def asset_telemetry_events(assets: Iterable[dict[str, Any]], *, node_id: str | None = None) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for asset in assets:
        event = {
            "type": "asset_inventory",
            "source": "portmap.asset_inventory",
            "target": asset.get("host", ""),
            "asset": asset,
        }
        if node_id:
            event["node_id"] = node_id
        events.append(event)
    return events


__all__ = [
    "AGGRESSIVE_MAX_TARGETS",
    "ASSET_STATUSES",
    "DEFAULT_DISCOVERY_PORTS",
    "NetworkAsset",
    "asset_telemetry_events",
    "broadcast_candidates",
    "collect_arp_inventory",
    "inventory_network_assets",
    "local_network_ranges",
    "local_topology_snapshot",
    "parse_arp_table",
    "ping_reachability",
    "tcp_reachability",
]
