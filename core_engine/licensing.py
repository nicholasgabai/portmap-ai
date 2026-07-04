from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


LICENSE_RECORD_VERSION = 1

SUPPORTED_LICENSE_STATUSES = frozenset(
    {"valid", "expired", "invalid", "missing", "grace_period", "unknown"}
)
SUPPORTED_LICENSE_EDITIONS = frozenset(
    {"community", "professional", "enterprise", "trial", "development"}
)
ACCEPTED_SIGNATURE_STATUSES = frozenset({"valid", "placeholder_valid"})

LICENSE_SAFETY_FLAGS = {
    "metadata_only": True,
    "read_only": True,
    "local_validation_only": True,
    "network_called": False,
    "remote_license_server_contacted": False,
    "billing_contacted": False,
    "customer_provisioning_contacted": False,
    "runtime_state_mutated": False,
    "enforcement_enabled": False,
    "cloud_dependency": False,
}

DEFAULT_EDITION_FEATURES = {
    "community": {"local_dashboard", "basic_attribution"},
    "professional": {
        "local_dashboard",
        "basic_attribution",
        "advanced_attribution",
        "behavior_graph",
    },
    "enterprise": {
        "local_dashboard",
        "basic_attribution",
        "advanced_attribution",
        "behavior_graph",
        "federated_intelligence",
        "commercial_support",
    },
    "trial": {"local_dashboard", "basic_attribution", "advanced_attribution"},
    "development": {
        "local_dashboard",
        "basic_attribution",
        "advanced_attribution",
        "behavior_graph",
        "developer_tools",
    },
}

DEFAULT_EDITION_LIMITS = {
    "community": {"nodes": 1, "workers": 1, "exports_per_day": 5},
    "professional": {"nodes": 10, "workers": 10, "exports_per_day": 50},
    "enterprise": {"nodes": 500, "workers": 500, "exports_per_day": 1000},
    "trial": {"nodes": 3, "workers": 3, "exports_per_day": 10},
    "development": {"nodes": 25, "workers": 25, "exports_per_day": 250},
}


@dataclass(frozen=True)
class LicenseRecord:
    license_id: str
    edition: str
    status: str
    issued_to: str
    issued_at: str
    expires_at: str
    features: list[str] = field(default_factory=list)
    limits: dict[str, Any] = field(default_factory=dict)
    signature_status: str = "unknown"
    validation_reason: str = ""
    grace_period: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "license_validation_summary",
            "record_version": LICENSE_RECORD_VERSION,
            "license_id": self.license_id,
            "edition": self.edition,
            "status": self.status,
            "issued_to": self.issued_to,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "features": list(self.features),
            "limits": dict(self.limits),
            "signature_status": self.signature_status,
            "validation_reason": self.validation_reason,
            "grace_period": self.grace_period,
            "metadata": dict(self.metadata),
            **LICENSE_SAFETY_FLAGS,
        }


def load_license(path: str | Path | None) -> dict[str, Any]:
    """Load a local license JSON file without contacting external services."""
    if path is None:
        return _load_error("missing", "license file path is missing")

    license_path = Path(path)
    if not license_path.exists():
        return _load_error("missing", "license file is missing")
    if not license_path.is_file():
        return _load_error("malformed", "license path is not a file")

    try:
        loaded = json.loads(license_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _load_error("malformed", "license file is malformed")

    if not isinstance(loaded, dict):
        return _load_error("malformed", "license file must contain a JSON object")
    return deepcopy(loaded)


def validate_license(
    license_data: dict[str, Any] | None,
    *,
    current_time: str | datetime | None = None,
) -> LicenseRecord:
    """Validate local entitlement metadata deterministically."""
    now = _coerce_datetime(current_time) or _now()
    source = deepcopy(license_data) if isinstance(license_data, dict) else None
    if source is None:
        return _missing_license("license data is missing")

    load_status = source.get("__license_load_status")
    if load_status == "missing":
        return _missing_license(str(source.get("validation_reason") or "license file is missing"))
    if load_status == "malformed":
        return _invalid_license(
            validation_reason=str(source.get("validation_reason") or "license file is malformed")
        )

    license_id = _safe_text(source.get("license_id"))
    edition = normalize_license_edition(source.get("edition"))
    issued_to = _safe_text(source.get("issued_to"))
    issued_at = _safe_text(source.get("issued_at"))
    expires_at = _safe_text(source.get("expires_at"))
    signature_status = normalize_signature_status(source.get("signature_status"))
    grace_period = _normalize_grace_period(source.get("grace_period"))
    features = _normalize_features(source.get("features"), edition=edition)
    limits = _normalize_limits(source.get("limits"), edition=edition)
    metadata = _normalize_metadata(source.get("metadata"))

    missing = [
        name
        for name, value in {
            "license_id": license_id,
            "edition": edition if edition in SUPPORTED_LICENSE_EDITIONS else "",
            "issued_to": issued_to,
            "issued_at": issued_at,
        }.items()
        if not value
    ]
    if missing:
        status = "invalid"
        reason = "license is missing required fields: " + ", ".join(sorted(missing))
    elif source.get("status") == "invalid":
        status = "invalid"
        reason = "license status is explicitly invalid"
    elif signature_status not in ACCEPTED_SIGNATURE_STATUSES:
        status = "invalid"
        reason = "license signature placeholder is not valid"
    else:
        expiry = _coerce_datetime(expires_at)
        if expires_at and expiry is None:
            status = "invalid"
            reason = "license expiration timestamp is malformed"
        elif expiry and expiry < now:
            grace_deadline = expiry + timedelta(days=grace_period)
            if grace_period > 0 and now <= grace_deadline:
                status = "grace_period"
                reason = "license is expired but within the configured grace period"
            else:
                status = "expired"
                reason = "license is expired"
        else:
            status = "valid"
            reason = "license is valid for local entitlement checks"

    return LicenseRecord(
        license_id=license_id or "license-unknown",
        edition=edition,
        status=status,
        issued_to=issued_to or "unknown",
        issued_at=issued_at,
        expires_at=expires_at,
        features=features,
        limits=limits,
        signature_status=signature_status,
        validation_reason=reason,
        grace_period=grace_period,
        metadata=metadata,
    )


def is_feature_enabled(license_data: dict[str, Any] | LicenseRecord | None, feature: str) -> bool:
    summary = summarize_license(license_data)
    if summary["status"] not in {"valid", "grace_period"}:
        return False
    return _safe_text(feature) in set(summary["features"])


def get_license_limit(
    license_data: dict[str, Any] | LicenseRecord | None,
    limit_name: str,
    default: Any = None,
) -> Any:
    summary = summarize_license(license_data)
    if summary["status"] not in {"valid", "grace_period"}:
        return default
    return summary["limits"].get(_safe_text(limit_name), default)


def summarize_license(
    license_data: dict[str, Any] | LicenseRecord | None,
    *,
    current_time: str | datetime | None = None,
) -> dict[str, Any]:
    if isinstance(license_data, LicenseRecord):
        return license_data.to_dict()
    if isinstance(license_data, dict) and license_data.get("record_type") == "license_validation_summary":
        return deepcopy(license_data)
    return validate_license(license_data, current_time=current_time).to_dict()


def normalize_license_status(value: Any) -> str:
    normalized = _safe_text(value).lower()
    return normalized if normalized in SUPPORTED_LICENSE_STATUSES else "unknown"


def normalize_license_edition(value: Any) -> str:
    normalized = _safe_text(value).lower()
    return normalized if normalized in SUPPORTED_LICENSE_EDITIONS else "unknown"


def normalize_signature_status(value: Any) -> str:
    normalized = _safe_text(value).lower()
    allowed = {"valid", "invalid", "missing", "placeholder_valid", "unknown"}
    return normalized if normalized in allowed else "unknown"


def deterministic_license_json(license_data: dict[str, Any] | LicenseRecord | None) -> str:
    return json.dumps(summarize_license(license_data), sort_keys=True, separators=(",", ":"))


def _load_error(status: str, reason: str) -> dict[str, Any]:
    return {
        "__license_load_status": status,
        "validation_reason": reason,
        **LICENSE_SAFETY_FLAGS,
    }


def _missing_license(reason: str) -> LicenseRecord:
    return LicenseRecord(
        license_id="license-missing",
        edition="unknown",
        status="missing",
        issued_to="unknown",
        issued_at="",
        expires_at="",
        features=[],
        limits={},
        signature_status="missing",
        validation_reason=reason,
        grace_period=0,
        metadata={},
    )


def _invalid_license(validation_reason: str) -> LicenseRecord:
    return LicenseRecord(
        license_id="license-invalid",
        edition="unknown",
        status="invalid",
        issued_to="unknown",
        issued_at="",
        expires_at="",
        features=[],
        limits={},
        signature_status="unknown",
        validation_reason=validation_reason,
        grace_period=0,
        metadata={},
    )


def _normalize_features(features: Any, *, edition: str) -> list[str]:
    normalized = set(DEFAULT_EDITION_FEATURES.get(edition, set()))
    if isinstance(features, dict):
        normalized.update(_safe_text(key) for key, value in features.items() if value)
    elif isinstance(features, (list, tuple, set)):
        normalized.update(_safe_text(feature) for feature in features)
    elif isinstance(features, str):
        normalized.add(_safe_text(features))
    return sorted(feature for feature in normalized if feature)


def _normalize_limits(limits: Any, *, edition: str) -> dict[str, Any]:
    normalized = dict(DEFAULT_EDITION_LIMITS.get(edition, {}))
    if isinstance(limits, dict):
        for key, value in sorted(limits.items(), key=lambda item: _safe_text(item[0])):
            safe_key = _safe_text(key)
            if safe_key:
                normalized[safe_key] = value
    return dict(sorted(normalized.items()))


def _normalize_metadata(metadata: Any) -> dict[str, Any]:
    if not isinstance(metadata, dict):
        return {}
    normalized: dict[str, Any] = {}
    for key, value in sorted(metadata.items(), key=lambda item: _safe_text(item[0])):
        safe_key = _safe_text(key)
        if safe_key:
            normalized[safe_key] = value
    return normalized


def _normalize_grace_period(value: Any) -> int:
    if isinstance(value, bool):
        return 14 if value else 0
    if isinstance(value, (int, float)):
        return max(0, min(int(value), 90))
    if isinstance(value, str):
        try:
            return max(0, min(int(value.strip()), 90))
        except ValueError:
            return 0
    return 0


def _coerce_datetime(value: str | datetime | None) -> datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(UTC) if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _now() -> datetime:
    return datetime.now(UTC)


def _safe_text(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).strip().split())
