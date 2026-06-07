from __future__ import annotations

from typing import Any

from core_engine.visualization.asset_classifier import classify_asset, score_asset_confidence
from core_engine.visualization.topology_models import clamp_score


ASSET_ROLES = {
    "workstation",
    "server",
    "router",
    "switch",
    "printer",
    "nas",
    "phone",
    "iot",
    "dns_resolver",
    "cloud_service",
    "external_service",
    "unknown",
}
ROLE_PORTS = {
    "dns_resolver": {53},
    "server": {22, 25, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 5432, 6379, 8000, 8080, 8443},
    "router": {67, 68, 123, 161, 162, 500, 4500},
    "printer": {515, 631, 9100},
    "nas": {111, 139, 445, 548, 873, 2049, 5000, 5001},
    "phone": {5060, 5061},
    "iot": {1883, 5683, 8883},
}


def classify_asset_role(record: dict[str, Any] | None) -> str:
    if not isinstance(record, dict):
        return "unknown"
    explicit = normalize_asset_role(record.get("asset_role") or record.get("role") or record.get("role_hint"))
    if explicit != "unknown":
        return explicit
    text = _combined_text(record)
    endpoint_class = str(
        record.get("endpoint_class")
        or record.get("node_class")
        or record.get("local_endpoint_class")
        or record.get("remote_endpoint_class")
        or ""
    ).lower()
    ports = _ports(record)

    if endpoint_class in {"external", "public", "remote"}:
        if any(marker in text for marker in {"cloud", "cdn", "saas"}):
            return "cloud_service"
        return "external_service"
    if endpoint_class in {"router", "gateway", "firewall"}:
        return "router"
    if endpoint_class == "switch":
        return "switch"
    if endpoint_class in {"workstation", "desktop", "laptop", "client"}:
        return "workstation"
    if endpoint_class in {"server", "master", "worker", "orchestrator"}:
        return "server"

    if any(marker in text for marker in {"dns", "resolver"}):
        return "dns_resolver"
    if any(marker in text for marker in {"cloud", "cdn", "saas"}):
        return "cloud_service"
    if any(marker in text for marker in {"external", "public", "remote"}):
        return "external_service"
    if any(marker in text for marker in {"router", "gateway", "firewall"}):
        return "router"
    if "switch" in text:
        return "switch"
    if any(marker in text for marker in {"printer", "ipp", "print"}):
        return "printer"
    if any(marker in text for marker in {"nas", "storage", "smb", "nfs"}):
        return "nas"
    if any(marker in text for marker in {"phone", "voip", "sip"}):
        return "phone"
    if any(marker in text for marker in {"iot", "mqtt", "sensor", "camera"}):
        return "iot"
    if any(marker in text for marker in {"server", "http", "https", "ssh", "database"}):
        return "server"
    if any(marker in text for marker in {"workstation", "desktop", "laptop", "browser", "client"}):
        return "workstation"

    for role, role_ports in ROLE_PORTS.items():
        if ports & role_ports:
            return role
    category_role = _role_from_asset_category(classify_asset(record))
    if category_role != "unknown":
        return category_role
    return "unknown"


def score_asset_role_confidence(record: dict[str, Any] | None, *, role: str | None = None) -> float:
    if not isinstance(record, dict):
        return 0.0
    normalized_role = normalize_asset_role(role or classify_asset_role(record))
    score = score_asset_confidence(record) * 0.45
    if normalize_asset_role(record.get("asset_role") or record.get("role") or record.get("role_hint")) == normalized_role and normalized_role != "unknown":
        score += 0.25
    if _ports(record):
        score += 0.12
    if record.get("observed_service_count") or record.get("service_hint") or record.get("service"):
        score += 0.08
    if record.get("observed_flow_count") or record.get("flow_direction") or record.get("relationship_type"):
        score += 0.06
    if record.get("recurrence_score") or record.get("observation_count"):
        score += 0.04
    if normalized_role == "unknown":
        score = min(score, 0.45)
    return clamp_score(score)


def build_role_evidence(record: dict[str, Any] | None, *, role: str | None = None) -> dict[str, Any]:
    row = record if isinstance(record, dict) else {}
    normalized_role = normalize_asset_role(role or classify_asset_role(row))
    return {
        "role": normalized_role,
        "endpoint_class": _safe_token(row.get("endpoint_class") or row.get("node_class") or row.get("local_endpoint_class") or row.get("remote_endpoint_class") or "unknown"),
        "service_hint_present": bool(row.get("service_hint") or row.get("service") or row.get("service_attribution")),
        "flow_direction": _safe_token(row.get("flow_direction") or row.get("direction") or "unknown"),
        "common_port_match": bool(_ports(row) & set().union(*ROLE_PORTS.values())),
        "recurrence_present": bool(row.get("recurrence_score") or int(row.get("observation_count") or 0) >= 3),
        "confidence_score": score_asset_role_confidence(row, role=normalized_role),
        "metadata_only": True,
        "private_identifier_exported": False,
    }


def normalize_asset_role(value: Any) -> str:
    role = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return role if role in ASSET_ROLES else "unknown"


def _role_from_asset_category(category: str) -> str:
    mapping = {
        "WORKSTATION": "workstation",
        "SERVER": "server",
        "ROUTER": "router",
        "SWITCH": "switch",
        "NAS": "nas",
        "PRINTER": "printer",
        "PHONE": "phone",
        "IOT": "iot",
    }
    return mapping.get(str(category or "UNKNOWN").upper(), "unknown")


def _ports(record: dict[str, Any]) -> set[int]:
    values = [record.get("port"), record.get("local_port"), record.get("remote_port"), record.get("service_port")]
    ports: set[int] = set()
    for value in values:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535:
            ports.add(port)
    return ports


def _combined_text(record: dict[str, Any]) -> str:
    keys = (
        "asset_role",
        "role",
        "role_hint",
        "asset_category",
        "node_class",
        "endpoint_class",
        "service_hint",
        "service",
        "service_attribution",
        "process_hint",
        "protocol",
        "relationship_type",
    )
    return " ".join(str(record.get(key) or "").lower().replace("-", "_") for key in keys)


def _safe_token(value: Any) -> str:
    token = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    safe = "".join(char for char in token if char.isalnum() or char == "_")
    return safe[:64] or "unknown"
