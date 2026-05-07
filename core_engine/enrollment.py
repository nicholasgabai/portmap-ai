from __future__ import annotations

from dataclasses import dataclass, field
import re
import time
from typing import Any
from urllib.parse import urlparse

from core_engine.security import redact_secret, token_fingerprint


ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,126}[A-Za-z0-9]$")
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_.~:-]{16,256}$")
VALID_AGENT_ROLES = {"standalone", "master", "worker"}
ENROLLMENT_SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class TenantIdentity:
    tenant_id: str
    org_id: str
    environment: str = "local"

    def to_dict(self) -> dict[str, str]:
        return {
            "tenant_id": self.tenant_id,
            "org_id": self.org_id,
            "environment": self.environment,
        }


@dataclass(frozen=True)
class EnrollmentRequest:
    tenant: TenantIdentity
    node_id: str
    role: str
    public_endpoint: str | None = None
    capabilities: list[str] = field(default_factory=list)
    requested_at: int = field(default_factory=lambda: int(time.time()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant.to_dict(),
            "node_id": self.node_id,
            "role": self.role,
            "public_endpoint": self.public_endpoint,
            "capabilities": list(self.capabilities),
            "requested_at": self.requested_at,
        }


@dataclass(frozen=True)
class EnrollmentPackage:
    tenant: TenantIdentity
    node_id: str
    role: str
    enrollment_token: str
    control_plane_url: str
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant": self.tenant.to_dict(),
            "node_id": self.node_id,
            "role": self.role,
            "enrollment_token": self.enrollment_token,
            "control_plane_url": self.control_plane_url,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class AgentIdentity:
    tenant: TenantIdentity
    node_id: str
    role: str
    control_plane_url: str | None = None
    enrollment_token_fingerprint: str = ""
    schema_version: str = ENROLLMENT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "tenant": self.tenant.to_dict(),
            "node_id": self.node_id,
            "role": self.role,
            "control_plane_url": self.control_plane_url,
            "enrollment_token_fingerprint": self.enrollment_token_fingerprint,
        }


def _validate_id(name: str, value: Any) -> list[str]:
    if not isinstance(value, str) or not ID_PATTERN.match(value):
        return [f"{name} must be 3-128 characters using letters, numbers, dot, underscore, colon, or dash"]
    return []


def _validate_control_plane_url(value: Any, *, required: bool) -> list[str]:
    if value in {None, ""}:
        return ["control_plane_url must be provided"] if required else []
    if not isinstance(value, str):
        return ["control_plane_url must be an http(s) URL"]
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ["control_plane_url must be an http(s) URL"]
    return []


def validate_tenant_identity(tenant: TenantIdentity | dict[str, Any]) -> list[str]:
    data = tenant.to_dict() if isinstance(tenant, TenantIdentity) else tenant
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["tenant must be an object"]
    errors.extend(_validate_id("tenant_id", data.get("tenant_id")))
    errors.extend(_validate_id("org_id", data.get("org_id")))
    environment = data.get("environment", "local")
    if not isinstance(environment, str) or not environment:
        errors.append("environment must be a non-empty string")
    return errors


def validate_enrollment_request(request: EnrollmentRequest | dict[str, Any]) -> list[str]:
    data = request.to_dict() if isinstance(request, EnrollmentRequest) else request
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["enrollment request must be an object"]
    errors.extend(validate_tenant_identity(data.get("tenant")))
    errors.extend(_validate_id("node_id", data.get("node_id")))
    role = data.get("role")
    if role not in VALID_AGENT_ROLES:
        errors.append(f"role must be one of: {', '.join(sorted(VALID_AGENT_ROLES))}")
    capabilities = data.get("capabilities", [])
    if capabilities is not None:
        if not isinstance(capabilities, list) or any(not isinstance(item, str) or not item for item in capabilities):
            errors.append("capabilities must be a list of non-empty strings")
    endpoint = data.get("public_endpoint")
    if endpoint is not None and not isinstance(endpoint, str):
        errors.append("public_endpoint must be a string when provided")
    return errors


def validate_enrollment_package(package: EnrollmentPackage | dict[str, Any]) -> list[str]:
    data = package.to_dict() if isinstance(package, EnrollmentPackage) else package
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["enrollment package must be an object"]
    errors.extend(validate_tenant_identity(data.get("tenant")))
    errors.extend(_validate_id("node_id", data.get("node_id")))
    role = data.get("role")
    if role not in VALID_AGENT_ROLES:
        errors.append(f"role must be one of: {', '.join(sorted(VALID_AGENT_ROLES))}")
    token = data.get("enrollment_token")
    if not isinstance(token, str) or not TOKEN_PATTERN.match(token):
        errors.append("enrollment_token must be 16-256 URL-safe characters")
    errors.extend(_validate_control_plane_url(data.get("control_plane_url"), required=True))
    expires_at = data.get("expires_at")
    if expires_at is not None and not isinstance(expires_at, int):
        errors.append("expires_at must be an integer timestamp when provided")
    return errors


def validate_agent_identity(identity: AgentIdentity | dict[str, Any]) -> list[str]:
    data = identity.to_dict() if isinstance(identity, AgentIdentity) else identity
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["agent identity must be an object"]
    schema_version = data.get("schema_version", ENROLLMENT_SCHEMA_VERSION)
    if schema_version != ENROLLMENT_SCHEMA_VERSION:
        errors.append(f"schema_version must be {ENROLLMENT_SCHEMA_VERSION}")
    errors.extend(validate_tenant_identity(data.get("tenant")))
    errors.extend(_validate_id("node_id", data.get("node_id")))
    role = data.get("role")
    if role not in VALID_AGENT_ROLES:
        errors.append(f"role must be one of: {', '.join(sorted(VALID_AGENT_ROLES))}")
    errors.extend(_validate_control_plane_url(data.get("control_plane_url"), required=False))
    fingerprint = data.get("enrollment_token_fingerprint", "")
    if fingerprint is not None and not isinstance(fingerprint, str):
        errors.append("enrollment_token_fingerprint must be a string")
    return errors


def build_local_enrollment_request(
    *,
    tenant_id: str,
    org_id: str,
    node_id: str,
    role: str,
    capabilities: list[str] | None = None,
    environment: str = "local",
) -> EnrollmentRequest:
    return EnrollmentRequest(
        tenant=TenantIdentity(tenant_id=tenant_id, org_id=org_id, environment=environment),
        node_id=node_id,
        role=role,
        capabilities=capabilities or [],
    )


def build_agent_identity(package: EnrollmentPackage | dict[str, Any]) -> AgentIdentity:
    data = package.to_dict() if isinstance(package, EnrollmentPackage) else package
    errors = validate_enrollment_package(data)
    if errors:
        raise ValueError("; ".join(errors))
    tenant_data = data["tenant"]
    return AgentIdentity(
        tenant=TenantIdentity(
            tenant_id=tenant_data["tenant_id"],
            org_id=tenant_data["org_id"],
            environment=tenant_data.get("environment", "local"),
        ),
        node_id=data["node_id"],
        role=data["role"],
        control_plane_url=data["control_plane_url"],
        enrollment_token_fingerprint=token_fingerprint(data.get("enrollment_token")),
    )


def redact_enrollment_package(package: EnrollmentPackage | dict[str, Any]) -> dict[str, Any]:
    data = package.to_dict() if isinstance(package, EnrollmentPackage) else dict(package)
    if "enrollment_token" in data:
        data["enrollment_token"] = redact_secret(data["enrollment_token"])
    return data
