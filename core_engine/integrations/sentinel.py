from __future__ import annotations

from typing import Any

from core_engine.integrations.common import normalize_alert_event


def format_sentinel_event(event: dict[str, Any]) -> dict[str, Any]:
    alert = normalize_alert_event(event)
    return {
        "TimeGenerated": alert["timestamp"],
        "SourceSystem": "PortMap-AI",
        "AlertName": alert["title"],
        "AlertSeverity": alert["severity"],
        "Description": alert["description"],
        "ProviderName": alert["source"],
        "VendorName": "PortMap-AI",
        "ProductName": "PortMap-AI",
        "SystemAlertId": alert["alert_id"],
        "CompromisedEntity": alert.get("target") or alert.get("node_id") or "",
        "ExtendedProperties": alert["details"],
    }


def format_sentinel_batch(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [format_sentinel_event(event) for event in events if isinstance(event, dict)]
