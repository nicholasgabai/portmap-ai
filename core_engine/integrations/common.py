from __future__ import annotations

from hashlib import sha256
from typing import Any

from core_engine.time_utils import utc_now_iso


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def utc_timestamp() -> str:
    return utc_now_iso()


def normalize_alert_event(event: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise ValueError("alert event must be an object")
    severity = normalize_severity(event.get("severity") or event.get("priority") or event.get("risk"))
    title = str(event.get("title") or event.get("summary") or event.get("event_type") or "PortMap-AI alert")
    source = str(event.get("source") or "portmap-ai")
    normalized = {
        "alert_id": str(event.get("alert_id") or _alert_id(event)),
        "timestamp": str(event.get("timestamp") or utc_timestamp()),
        "source": source,
        "severity": severity,
        "title": title,
        "description": str(event.get("description") or event.get("summary") or title),
        "event_type": str(event.get("event_type") or "security_alert"),
        "node_id": event.get("node_id"),
        "target": event.get("target") or event.get("host"),
        "risk_score": _float(event.get("risk_score") or event.get("priority_score")),
        "details": _json_safe(event.get("details") or event),
    }
    return normalized


def normalize_severity(value: Any) -> str:
    text = str(value or "").strip().lower()
    if text in SEVERITY_RANK:
        return text
    try:
        score = float(value)
    except (TypeError, ValueError):
        return "info"
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    if score > 0:
        return "low"
    return "info"


def delivery_result(
    *,
    ok: bool,
    destination: str,
    integration: str,
    status: str,
    detail: str = "",
    dry_run: bool = False,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "integration": integration,
        "destination": destination,
        "status": status,
        "detail": detail,
        "dry_run": dry_run,
    }


def _alert_id(event: dict[str, Any]) -> str:
    seed = "|".join(str(event.get(key) or "") for key in ("timestamp", "event_type", "node_id", "target", "summary", "title"))
    return sha256(seed.encode("utf-8")).hexdigest()[:16]


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
