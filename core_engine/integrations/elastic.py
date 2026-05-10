from __future__ import annotations

import json
from typing import Any

from core_engine.integrations.common import normalize_alert_event
from core_engine.integrations.webhook import send_webhook_alert


def format_elastic_document(event: dict[str, Any], *, data_stream: str = "logs-portmap.alerts-default") -> dict[str, Any]:
    alert = normalize_alert_event(event)
    return {
        "@timestamp": alert["timestamp"],
        "data_stream": {"type": "logs", "dataset": data_stream, "namespace": "default"},
        "event": {"kind": "alert", "category": ["network"], "type": [alert["event_type"]], "severity": alert["severity"]},
        "portmap": alert,
    }


def format_elastic_bulk(events: list[dict[str, Any]], *, index: str = "portmap-alerts") -> str:
    lines: list[str] = []
    for event in events:
        lines.append(json.dumps({"index": {"_index": index}}, sort_keys=True))
        lines.append(json.dumps(format_elastic_document(event), sort_keys=True))
    return "\n".join(lines) + ("\n" if lines else "")


def send_elastic_bulk(
    url: str,
    bulk_body: str,
    *,
    api_key: str | None = None,
    dry_run: bool = True,
    **kwargs: Any,
) -> dict[str, Any]:
    headers = {"Content-Type": "application/x-ndjson"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    return send_webhook_alert(url, {"bulk": bulk_body}, headers=headers, dry_run=dry_run, **kwargs)
