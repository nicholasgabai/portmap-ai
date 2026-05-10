from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import re
import secrets
import time
from typing import Any

from core_engine.security import token_fingerprint


AGENT_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{3,128}$")
AGENT_ROLES = {"agent", "worker", "master"}
SECRET_BYTES = 32


@dataclass(frozen=True)
class EnterpriseAgentIdentity:
    agent_id: str
    tenant_id: str
    role: str = "agent"
    secret_fingerprint: str = ""
    certificate_fingerprint: str | None = None
    issued_at: int = field(default_factory=lambda: int(time.time()))
    mtls_ready: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "tenant_id": self.tenant_id,
            "role": self.role,
            "secret_fingerprint": self.secret_fingerprint,
            "certificate_fingerprint": self.certificate_fingerprint,
            "issued_at": self.issued_at,
            "mtls_ready": self.mtls_ready,
        }


def generate_agent_secret() -> str:
    return secrets.token_urlsafe(SECRET_BYTES)


def build_enterprise_agent_identity(
    *,
    agent_id: str,
    tenant_id: str,
    role: str = "agent",
    shared_secret: str | None = None,
    certificate_fingerprint: str | None = None,
    issued_at: int | None = None,
) -> tuple[EnterpriseAgentIdentity, str | None]:
    secret = shared_secret or generate_agent_secret()
    identity = EnterpriseAgentIdentity(
        agent_id=agent_id,
        tenant_id=tenant_id,
        role=role,
        secret_fingerprint=token_fingerprint(secret),
        certificate_fingerprint=certificate_fingerprint,
        issued_at=int(issued_at if issued_at is not None else time.time()),
        mtls_ready=bool(certificate_fingerprint),
    )
    errors = validate_enterprise_agent_identity(identity)
    if errors:
        raise ValueError("; ".join(errors))
    return identity, None if shared_secret else secret


def validate_enterprise_agent_identity(identity: EnterpriseAgentIdentity | dict[str, Any]) -> list[str]:
    data = identity.to_dict() if isinstance(identity, EnterpriseAgentIdentity) else identity
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["agent identity must be an object"]
    for field_name in ("agent_id", "tenant_id"):
        value = data.get(field_name)
        if not isinstance(value, str) or not AGENT_ID_PATTERN.match(value):
            errors.append(f"{field_name} must be 3-128 characters using letters, numbers, dot, underscore, colon, or dash")
    role = data.get("role")
    if role not in AGENT_ROLES:
        errors.append(f"role must be one of: {', '.join(sorted(AGENT_ROLES))}")
    if data.get("certificate_fingerprint") is not None and not isinstance(data.get("certificate_fingerprint"), str):
        errors.append("certificate_fingerprint must be a string when provided")
    if not isinstance(data.get("secret_fingerprint"), str):
        errors.append("secret_fingerprint must be a string")
    return errors


def sign_agent_message(agent_id: str, shared_secret: str, timestamp: int, body: str) -> str:
    message = f"{agent_id}.{timestamp}.{body}".encode("utf-8")
    return hmac.new(shared_secret.encode("utf-8"), message, "sha256").hexdigest()


def verify_agent_message_signature(
    *,
    agent_id: str,
    shared_secret: str,
    timestamp: int,
    body: str,
    signature: str,
    now: int | None = None,
    max_skew_seconds: int = 300,
) -> dict[str, Any]:
    current = int(now if now is not None else time.time())
    errors: list[str] = []
    if abs(current - int(timestamp)) > max_skew_seconds:
        errors.append("agent signature timestamp outside allowed skew")
    expected = sign_agent_message(agent_id, shared_secret, int(timestamp), body)
    if not hmac.compare_digest(expected, str(signature)):
        errors.append("invalid agent message signature")
    return {
        "ok": not errors,
        "agent_id": agent_id,
        "errors": errors,
        "secret_fingerprint": token_fingerprint(shared_secret),
    }
