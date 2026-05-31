from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.history.snapshots import HISTORICAL_SNAPSHOT_SAFETY_FLAGS


AGING_POLICY_RECORD_VERSION = 1

AGING_POLICY_SAFETY_FLAGS = {
    **HISTORICAL_SNAPSHOT_SAFETY_FLAGS,
    "aging_policy_only": True,
    "metadata_only": True,
    "local_first": True,
    "dry_run_safe": True,
    "advisory_only": True,
    "automatic_enforcement": False,
    "external_services_used": False,
    "firewall_changes": False,
}

SAFE_DEFAULT_AGING_PROFILES = {
    "default": {
        "profile_label": "default",
        "inactive_after_days": 14,
        "stale_after_days": 30,
        "dormant_after_days": 60,
        "mature_after_observations": 5,
        "mature_after_days": 21,
        "decay_rate": 0.5,
        "minimum_confidence": 0.1,
    },
    "raspberry_pi": {
        "profile_label": "raspberry_pi",
        "inactive_after_days": 7,
        "stale_after_days": 21,
        "dormant_after_days": 45,
        "mature_after_observations": 4,
        "mature_after_days": 14,
        "decay_rate": 0.55,
        "minimum_confidence": 0.1,
    },
    "long_term": {
        "profile_label": "long_term",
        "inactive_after_days": 30,
        "stale_after_days": 90,
        "dormant_after_days": 180,
        "mature_after_observations": 10,
        "mature_after_days": 60,
        "decay_rate": 0.35,
        "minimum_confidence": 0.08,
    },
}


class AgingPolicyError(ValueError):
    """Raised when a baseline aging policy is malformed."""


def build_aging_policy_record(
    *,
    profile_label: str = "default",
    inactive_after_days: int | None = None,
    stale_after_days: int | None = None,
    dormant_after_days: int | None = None,
    mature_after_observations: int | None = None,
    mature_after_days: int | None = None,
    decay_rate: float | None = None,
    minimum_confidence: float | None = None,
    generated_at: str | None = None,
) -> dict[str, Any]:
    base = dict(SAFE_DEFAULT_AGING_PROFILES.get(profile_label) or SAFE_DEFAULT_AGING_PROFILES["default"])
    values = {
        "profile_label": str(profile_label or base["profile_label"]),
        "inactive_after_days": inactive_after_days if inactive_after_days is not None else base["inactive_after_days"],
        "stale_after_days": stale_after_days if stale_after_days is not None else base["stale_after_days"],
        "dormant_after_days": dormant_after_days if dormant_after_days is not None else base["dormant_after_days"],
        "mature_after_observations": mature_after_observations if mature_after_observations is not None else base["mature_after_observations"],
        "mature_after_days": mature_after_days if mature_after_days is not None else base["mature_after_days"],
        "decay_rate": decay_rate if decay_rate is not None else base["decay_rate"],
        "minimum_confidence": minimum_confidence if minimum_confidence is not None else base["minimum_confidence"],
    }
    _validate_values(values)
    record = {
        "record_type": "baseline_aging_policy",
        "record_version": AGING_POLICY_RECORD_VERSION,
        "generated_at": generated_at or _now(),
        **values,
        **AGING_POLICY_SAFETY_FLAGS,
    }
    record["policy_id"] = "aging-policy-" + _digest(values)[:16]
    return record


def get_safe_default_aging_profile(profile_label: str = "default", *, generated_at: str | None = None) -> dict[str, Any]:
    return build_aging_policy_record(profile_label=profile_label, generated_at=generated_at)


def deterministic_aging_policy_json(record: dict[str, Any]) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def _validate_values(values: dict[str, Any]) -> None:
    for key in ("inactive_after_days", "stale_after_days", "dormant_after_days", "mature_after_observations", "mature_after_days"):
        if int(values[key]) <= 0:
            raise AgingPolicyError(f"{key} must be positive")
    if int(values["inactive_after_days"]) > int(values["stale_after_days"]):
        raise AgingPolicyError("inactive_after_days must be less than or equal to stale_after_days")
    if int(values["stale_after_days"]) > int(values["dormant_after_days"]):
        raise AgingPolicyError("stale_after_days must be less than or equal to dormant_after_days")
    if not 0.0 <= float(values["decay_rate"]) <= 1.0:
        raise AgingPolicyError("decay_rate must be between 0 and 1")
    if not 0.0 <= float(values["minimum_confidence"]) <= 1.0:
        raise AgingPolicyError("minimum_confidence must be between 0 and 1")


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
