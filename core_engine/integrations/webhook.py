from __future__ import annotations

import json
from typing import Any, Callable
from urllib import request

from core_engine.integrations.common import delivery_result, normalize_alert_event


UrlOpen = Callable[..., Any]


def format_webhook_alert(event: dict[str, Any], *, style: str = "generic") -> dict[str, Any]:
    alert = normalize_alert_event(event)
    if style == "slack":
        return {
            "text": f"[{alert['severity'].upper()}] {alert['title']}",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{alert['title']}*\n{alert['description']}"}},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": f"source={alert['source']} alert_id={alert['alert_id']}"}]},
            ],
            "metadata": {"event_type": alert["event_type"], "event_payload": alert},
        }
    if style == "teams":
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": alert["title"],
            "themeColor": _teams_color(alert["severity"]),
            "title": f"{alert['severity'].upper()}: {alert['title']}",
            "text": alert["description"],
            "sections": [{"facts": [{"name": "Alert ID", "value": alert["alert_id"]}, {"name": "Source", "value": alert["source"]}]}],
        }
    return {"alert": alert}


def send_webhook_alert(
    url: str,
    payload: dict[str, Any],
    *,
    headers: dict[str, str] | None = None,
    timeout: float = 5.0,
    dry_run: bool = True,
    opener: UrlOpen = request.urlopen,
) -> dict[str, Any]:
    if dry_run:
        return delivery_result(ok=True, destination=url, integration="webhook", status="dry_run", dry_run=True)
    try:
        body = json.dumps(payload, sort_keys=True).encode("utf-8")
        req = request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        with opener(req, timeout=timeout) as response:
            status_code = getattr(response, "status", getattr(response, "code", 200))
            return delivery_result(ok=200 <= int(status_code) < 300, destination=url, integration="webhook", status=str(status_code))
    except Exception as exc:
        return delivery_result(ok=False, destination=url, integration="webhook", status="failed", detail=str(exc))


def _teams_color(severity: str) -> str:
    return {
        "critical": "8B0000",
        "high": "D13438",
        "medium": "FFB900",
        "low": "0078D4",
        "info": "737373",
    }.get(severity, "737373")
