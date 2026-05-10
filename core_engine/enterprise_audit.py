from __future__ import annotations

import time
from typing import Any

from core_engine.security import scrub_secrets


def build_enterprise_audit_event(
    *,
    actor: str,
    action: str,
    status: str,
    resource: str | None = None,
    roles: list[str] | None = None,
    tenant_id: str | None = None,
    metadata: dict[str, Any] | None = None,
    timestamp: float | None = None,
) -> dict[str, Any]:
    return {
        "timestamp": float(timestamp if timestamp is not None else time.time()),
        "event_type": "enterprise_security",
        "actor": actor,
        "action": action,
        "status": status,
        "resource": resource,
        "roles": list(roles or []),
        "tenant_id": tenant_id,
        "metadata": scrub_secrets(metadata or {}),
    }
