from __future__ import annotations

from email.message import EmailMessage
import smtplib
from typing import Any, Callable

from core_engine.integrations.common import delivery_result, normalize_alert_event


SMTPFactory = Callable[..., Any]


def format_email_alert(
    event: dict[str, Any],
    *,
    sender: str,
    recipients: list[str],
    subject_prefix: str = "[PortMap-AI]",
) -> EmailMessage:
    alert = normalize_alert_event(event)
    message = EmailMessage()
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message["Subject"] = f"{subject_prefix} {alert['severity'].upper()} {alert['title']}"
    message.set_content(
        "\n".join([
            alert["description"],
            "",
            f"Alert ID: {alert['alert_id']}",
            f"Severity: {alert['severity']}",
            f"Source: {alert['source']}",
            f"Target: {alert.get('target') or '-'}",
        ])
    )
    return message


def send_email_alert(
    *,
    smtp_host: str,
    sender: str,
    recipients: list[str],
    message: EmailMessage,
    smtp_port: int = 25,
    timeout: float = 5.0,
    dry_run: bool = True,
    smtp_factory: SMTPFactory = smtplib.SMTP,
) -> dict[str, Any]:
    destination = f"{smtp_host}:{smtp_port}"
    if dry_run:
        return delivery_result(ok=True, destination=destination, integration="email", status="dry_run", dry_run=True)
    try:
        with smtp_factory(smtp_host, smtp_port, timeout=timeout) as smtp:
            smtp.send_message(message, from_addr=sender, to_addrs=recipients)
        return delivery_result(ok=True, destination=destination, integration="email", status="sent")
    except Exception as exc:
        return delivery_result(ok=False, destination=destination, integration="email", status="failed", detail=str(exc))
