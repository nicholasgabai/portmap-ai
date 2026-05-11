import json

from core_engine.integrations.elastic import format_elastic_bulk, format_elastic_document
from core_engine.integrations.email import format_email_alert, send_email_alert
from core_engine.integrations.sentinel import format_sentinel_event
from core_engine.integrations.splunk import format_splunk_hec_event
from core_engine.integrations.webhook import format_webhook_alert, send_webhook_alert


def _timestamp(date, *parts):
    return f"{date}T{':'.join(parts)}Z"


EVENT = {
    "timestamp": _timestamp("2026-05-10", "12", "00", "00"),
    "event_type": "vulnerability_alert",
    "severity": "critical",
    "title": "Critical Apache vulnerability",
    "summary": "Apache HTTP Server requires immediate review.",
    "source": "portmap-ai",
    "node_id": "worker-1",
    "target": "203.0.113.10",
    "risk_score": 0.95,
}


def test_webhook_formats_generic_slack_and_teams_payloads():
    generic = format_webhook_alert(EVENT)
    slack = format_webhook_alert(EVENT, style="slack")
    teams = format_webhook_alert(EVENT, style="teams")

    assert generic["alert"]["severity"] == "critical"
    assert slack["text"].startswith("[CRITICAL]")
    assert slack["metadata"]["event_payload"]["target"] == "203.0.113.10"
    assert teams["summary"] == "Critical Apache vulnerability"
    assert teams["themeColor"] == "8B0000"


def test_webhook_delivery_dry_run_and_failure_isolation():
    dry_run = send_webhook_alert("https://example.test/hook", {"ok": True}, dry_run=True)

    def failing_opener(req, timeout=5.0):
        raise OSError("network unavailable")

    failed = send_webhook_alert("https://example.test/hook", {"ok": True}, dry_run=False, opener=failing_opener)

    assert dry_run["ok"] is True
    assert dry_run["status"] == "dry_run"
    assert failed["ok"] is False
    assert failed["status"] == "failed"
    assert "network unavailable" in failed["detail"]


def test_webhook_delivery_uses_json_post_body():
    seen = {}

    class Response:
        status = 202

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def opener(req, timeout=5.0):
        seen["method"] = req.get_method()
        seen["content_type"] = req.headers["Content-type"]
        seen["body"] = json.loads(req.data.decode("utf-8"))
        seen["timeout"] = timeout
        return Response()

    result = send_webhook_alert("https://example.test/hook", {"alert": {"id": "a1"}}, dry_run=False, opener=opener, timeout=2.0)

    assert result["ok"] is True
    assert result["status"] == "202"
    assert seen == {
        "method": "POST",
        "content_type": "application/json",
        "body": {"alert": {"id": "a1"}},
        "timeout": 2.0,
    }


def test_splunk_elastic_and_sentinel_formats_are_json_serializable():
    splunk = format_splunk_hec_event(EVENT, index="security")
    elastic = format_elastic_document(EVENT)
    bulk = format_elastic_bulk([EVENT], index="portmap-alerts")
    sentinel = format_sentinel_event(EVENT)

    assert splunk["index"] == "security"
    assert splunk["event"]["alert_id"]
    assert elastic["@timestamp"] == EVENT["timestamp"]
    assert '"_index": "portmap-alerts"' in bulk
    assert sentinel["SystemAlertId"] == splunk["event"]["alert_id"]
    json.dumps(splunk)
    json.dumps(elastic)
    json.dumps(sentinel)


def test_email_format_and_delivery_failure_isolation():
    message = format_email_alert(
        EVENT,
        sender="alerts@example.test",
        recipients=["ops@example.test"],
    )

    class FailingSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def send_message(self, message, from_addr=None, to_addrs=None):
            raise OSError("smtp unavailable")

    result = send_email_alert(
        smtp_host="smtp.example.test",
        sender="alerts@example.test",
        recipients=["ops@example.test"],
        message=message,
        dry_run=False,
        smtp_factory=FailingSMTP,
    )

    assert message["Subject"].startswith("[PortMap-AI] CRITICAL")
    assert result["ok"] is False
    assert result["status"] == "failed"
    assert "smtp unavailable" in result["detail"]
