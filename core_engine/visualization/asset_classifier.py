from __future__ import annotations

from typing import Any

from core_engine.visualization.topology_models import ASSET_CATEGORIES, clamp_score, normalize_asset_category


SERVER_PORTS = {22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8000, 8080, 8443}
ROUTER_PORTS = {53, 67, 68, 123, 161, 162, 500, 4500}
NAS_PORTS = {111, 139, 445, 548, 873, 2049, 5000, 5001}
PRINTER_PORTS = {515, 631, 9100}
PHONE_PORTS = {5060, 5061}
IOT_PORTS = {1883, 5683, 8883}


def classify_asset(observation: dict[str, Any] | None) -> str:
    if not isinstance(observation, dict):
        return "UNKNOWN"
    explicit = normalize_asset_category(
        observation.get("asset_category")
        or observation.get("device_category")
        or observation.get("asset_type")
    )
    if explicit in ASSET_CATEGORIES and explicit != "UNKNOWN":
        return explicit

    text = _combined_text(observation)
    ports = _ports(observation)
    endpoint_class = str(
        observation.get("endpoint_class")
        or observation.get("local_endpoint_class")
        or observation.get("remote_endpoint_class")
        or observation.get("node_class")
        or ""
    ).lower()

    if endpoint_class in {"router", "gateway", "firewall"}:
        return "ROUTER"
    if endpoint_class in {"switch"}:
        return "SWITCH"
    if endpoint_class in {"server", "master", "worker", "orchestrator"}:
        return "SERVER"
    if endpoint_class in {"workstation", "desktop", "laptop", "client"}:
        return "WORKSTATION"

    if any(word in text for word in {"router", "gateway", "firewall", "dns_resolver", "dhcp"}):
        return "ROUTER"
    if any(word in text for word in {"switch", "span", "mirror_port"}):
        return "SWITCH"
    if any(word in text for word in {"nas", "smb", "nfs", "storage", "fileserver"}):
        return "NAS"
    if any(word in text for word in {"printer", "ipp", "print"}):
        return "PRINTER"
    if any(word in text for word in {"phone", "voip", "sip"}):
        return "PHONE"
    if any(word in text for word in {"iot", "mqtt", "sensor", "camera", "thermostat"}):
        return "IOT"
    if any(word in text for word in {"server", "orchestrator", "master", "worker", "database", "http", "https", "ssh"}):
        return "SERVER"
    if any(word in text for word in {"workstation", "desktop", "laptop", "browser", "client"}):
        return "WORKSTATION"

    if endpoint_class in {"workstation", "client", "local", "private"} and _has_ephemeral_client_port(ports):
        return "WORKSTATION"

    if ports & PRINTER_PORTS:
        return "PRINTER"
    if ports & PHONE_PORTS:
        return "PHONE"
    if ports & IOT_PORTS:
        return "IOT"
    if ports & NAS_PORTS:
        return "NAS"
    if ports & ROUTER_PORTS and not ports - ROUTER_PORTS:
        return "ROUTER"
    if ports & SERVER_PORTS:
        return "SERVER"
    return "UNKNOWN"


def score_asset_confidence(observation: dict[str, Any] | None, *, asset_category: str | None = None) -> float:
    if not isinstance(observation, dict):
        return 0.0
    category = normalize_asset_category(asset_category or classify_asset(observation))
    score = 0.25
    if normalize_asset_category(observation.get("asset_category") or observation.get("device_category") or observation.get("asset_type")) == category and category != "UNKNOWN":
        score += 0.35
    if _ports(observation):
        score += 0.18
    if observation.get("service_hint") or observation.get("service") or observation.get("service_attribution"):
        score += 0.12
    if observation.get("process_hint") or observation.get("process") or observation.get("process_attribution"):
        score += 0.08
    if observation.get("node_class") or observation.get("endpoint_class") or observation.get("local_endpoint_class") or observation.get("remote_endpoint_class"):
        score += 0.07
    if category == "UNKNOWN":
        score = min(score, 0.45)
    return clamp_score(score)


def _combined_text(observation: dict[str, Any]) -> str:
    values = [
        observation.get("asset_category"),
        observation.get("device_category"),
        observation.get("asset_type"),
        observation.get("role_hint"),
        observation.get("node_role"),
        observation.get("node_class"),
        observation.get("service_hint"),
        observation.get("service"),
        observation.get("service_attribution"),
        observation.get("process_hint"),
        observation.get("process"),
        observation.get("process_attribution"),
        observation.get("protocol"),
        observation.get("transport"),
    ]
    return " ".join(str(value).lower().replace("-", "_") for value in values if value is not None)


def _ports(observation: dict[str, Any]) -> set[int]:
    values = [
        observation.get("port"),
        observation.get("local_port"),
        observation.get("remote_port"),
        observation.get("service_port"),
    ]
    ports: set[int] = set()
    for value in values:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535:
            ports.add(port)
    return ports


def _has_ephemeral_client_port(ports: set[int]) -> bool:
    return any(port >= 49152 for port in ports)
