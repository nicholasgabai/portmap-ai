from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


VALID_LICENSE_TIERS = {"community", "team", "enterprise"}


@dataclass(frozen=True)
class LicenseMetadata:
    license_id: str
    tenant_id: str
    tier: str = "community"
    features: list[str] = field(default_factory=list)
    quotas: dict[str, int] = field(default_factory=dict)
    issued_at: int = field(default_factory=lambda: int(time.time()))
    expires_at: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "license_id": self.license_id,
            "tenant_id": self.tenant_id,
            "tier": self.tier,
            "features": sorted(set(self.features)),
            "quotas": dict(self.quotas),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
        }


@dataclass(frozen=True)
class UsageCounters:
    tenant_id: str
    counters: dict[str, int] = field(default_factory=dict)
    period_start: int = field(default_factory=lambda: int(time.time()))
    period_end: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "counters": {key: int(value) for key, value in self.counters.items()},
            "period_start": self.period_start,
            "period_end": self.period_end,
        }


def validate_license(metadata: LicenseMetadata | dict[str, Any]) -> list[str]:
    data = metadata.to_dict() if isinstance(metadata, LicenseMetadata) else metadata
    if not isinstance(data, dict):
        return ["license metadata must be an object"]
    errors: list[str] = []
    for field_name in ("license_id", "tenant_id"):
        if not isinstance(data.get(field_name), str) or not data.get(field_name):
            errors.append(f"{field_name} is required")
    if data.get("tier", "community") not in VALID_LICENSE_TIERS:
        errors.append(f"tier must be one of: {', '.join(sorted(VALID_LICENSE_TIERS))}")
    if not isinstance(data.get("features", []), list):
        errors.append("features must be a list")
    if not isinstance(data.get("quotas", {}), dict):
        errors.append("quotas must be an object")
    return errors


def usage_summary(license_metadata: LicenseMetadata | dict[str, Any], usage: UsageCounters | dict[str, Any]) -> dict[str, Any]:
    license_data = license_metadata.to_dict() if isinstance(license_metadata, LicenseMetadata) else dict(license_metadata)
    usage_data = usage.to_dict() if isinstance(usage, UsageCounters) else dict(usage)
    errors = validate_license(license_data)
    if errors:
        raise ValueError("; ".join(errors))
    if license_data["tenant_id"] != usage_data.get("tenant_id"):
        raise ValueError("license and usage must belong to the same tenant")
    quota_rows = []
    counters = usage_data.get("counters") or {}
    for name, limit in sorted((license_data.get("quotas") or {}).items()):
        used = int(counters.get(name, 0) or 0)
        quota = int(limit)
        remaining = max(quota - used, 0)
        quota_rows.append({
            "name": name,
            "used": used,
            "quota": quota,
            "remaining": remaining,
            "exceeded": used > quota,
        })
    return {
        "ok": True,
        "tenant_id": license_data["tenant_id"],
        "license_id": license_data["license_id"],
        "tier": license_data.get("tier", "community"),
        "features": sorted(set(license_data.get("features") or [])),
        "quotas": quota_rows,
        "period_start": usage_data.get("period_start"),
        "period_end": usage_data.get("period_end"),
        "license_expired": _expired(license_data.get("expires_at")),
    }


def feature_enabled(license_metadata: LicenseMetadata | dict[str, Any], feature: str) -> dict[str, Any]:
    data = license_metadata.to_dict() if isinstance(license_metadata, LicenseMetadata) else dict(license_metadata)
    errors = validate_license(data)
    if errors:
        raise ValueError("; ".join(errors))
    enabled = feature in set(data.get("features") or []) and not _expired(data.get("expires_at"))
    return {
        "ok": enabled,
        "feature": feature,
        "enabled": enabled,
        "tier": data.get("tier", "community"),
        "license_expired": _expired(data.get("expires_at")),
    }


def check_quota(license_metadata: LicenseMetadata | dict[str, Any], usage: UsageCounters | dict[str, Any], quota_name: str) -> dict[str, Any]:
    summary = usage_summary(license_metadata, usage)
    for row in summary["quotas"]:
        if row["name"] == quota_name:
            return {"ok": not row["exceeded"], **row}
    return {"ok": True, "name": quota_name, "used": 0, "quota": None, "remaining": None, "exceeded": False}


def _expired(expires_at: Any) -> bool:
    try:
        return expires_at is not None and int(expires_at) <= int(time.time())
    except (TypeError, ValueError):
        return False


__all__ = [
    "VALID_LICENSE_TIERS",
    "LicenseMetadata",
    "UsageCounters",
    "check_quota",
    "feature_enabled",
    "usage_summary",
    "validate_license",
]
