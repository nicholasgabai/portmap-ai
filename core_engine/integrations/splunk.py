from __future__ import annotations

from typing import Any

from core_engine.integrations.common import normalize_alert_event
from core_engine.integrations.webhook import send_webhook_alert


def format_splunk_hec_event(
    event: dict[str, Any],
    *,
    index: str | None = None,
    sourcetype: str = "portmap:alert",
) -> dict[str, Any]:
    alert = normalize_alert_event(event)
    payload: dict[str, Any] = {
        "time": _epoch_seconds(alert["timestamp"]),
        "host": alert.get("node_id") or alert.get("target") or "portmap-ai",
        "source": alert["source"],
        "sourcetype": sourcetype,
        "event": alert,
    }
    if index:
        payload["index"] = index
    return payload


def send_splunk_hec(
    url: str,
    token: str,
    event: dict[str, Any],
    *,
    dry_run: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    return send_webhook_alert(
        url,
        event,
        headers={"Authorization": f"Splunk {token}"},
        dry_run=dry_run,
        **kwargs,
    )


def _epoch_seconds(timestamp: str) -> float:
    try:
        from datetime import datetime

        return datetime.fromisoformat(timestamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0
