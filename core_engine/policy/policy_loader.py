from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any

from core_engine.policy.models import PolicyError
from core_engine.policy.runtime_engine import (
    RuntimePolicy,
    create_runtime_policy,
    runtime_policy_to_dict,
)


@dataclass(slots=True)
class PolicyValidationRecord:
    policy_ref: str
    validation_state: str
    message: str
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "policy_validation_record",
            "policy_ref": self.policy_ref,
            "validation_state": self.validation_state,
            "message": self.message,
            "preview_only": self.preview_only,
            "destructive_action": self.destructive_action,
            "automatic_changes": False,
            "raw_payload_stored": False,
            "credentials_stored": False,
        }


@dataclass(slots=True)
class PolicyBundle:
    bundle_id: str
    policies: list[RuntimePolicy] = field(default_factory=list)
    validation_records: list[PolicyValidationRecord] = field(default_factory=list)
    loaded_at: str = field(default_factory=lambda: _now())
    source_mode: str = "fixture"
    preview_only: bool = True
    destructive_action: bool = False


def load_policy_bundle(source: dict[str, Any] | list[Any] | str, *, source_mode: str = "fixture", now: str | None = None) -> PolicyBundle:
    timestamp = now or _now()
    payload, parse_records = _parse_source(source)
    raw_policies = _extract_policies(payload)
    policies: list[RuntimePolicy] = []
    records: list[PolicyValidationRecord] = list(parse_records)

    for index, raw_policy in enumerate(raw_policies):
        policy_ref = _policy_ref(raw_policy, index)
        if not isinstance(raw_policy, dict):
            records.append(_validation(policy_ref, "invalid", "policy_must_be_object"))
            continue
        try:
            policy = _policy_from_dict(raw_policy)
        except PolicyError as exc:
            records.append(_validation(policy_ref, "invalid", str(exc)))
            continue
        policies.append(policy)
        state = "disabled" if not policy.enabled else "valid"
        message = "policy_disabled" if not policy.enabled else "policy_loaded"
        records.append(_validation(policy.policy_id, state, message))

    bundle_id = _stable_bundle_id(policies, records)
    return PolicyBundle(
        bundle_id=bundle_id,
        policies=policies,
        validation_records=records,
        loaded_at=timestamp,
        source_mode=source_mode,
    )


def policy_bundle_to_dict(bundle: PolicyBundle) -> dict[str, Any]:
    return {
        "record_type": "policy_bundle",
        "bundle_id": bundle.bundle_id,
        "loaded_at": bundle.loaded_at,
        "source_mode": bundle.source_mode,
        "policy_count": len(bundle.policies),
        "valid_policy_count": sum(1 for record in bundle.validation_records if record.validation_state == "valid"),
        "disabled_policy_count": sum(1 for record in bundle.validation_records if record.validation_state == "disabled"),
        "invalid_policy_count": sum(1 for record in bundle.validation_records if record.validation_state == "invalid"),
        "policies": [runtime_policy_to_dict(policy) for policy in bundle.policies],
        "validation_records": [record.to_dict() for record in bundle.validation_records],
        "preview_only": bundle.preview_only,
        "destructive_action": bundle.destructive_action,
        "automatic_changes": False,
        "raw_payload_stored": False,
        "credentials_stored": False,
        "remote_policy_loading": False,
        "filesystem_writes": False,
    }


def deterministic_policy_bundle_json(bundle: PolicyBundle | dict[str, Any]) -> str:
    payload = policy_bundle_to_dict(bundle) if isinstance(bundle, PolicyBundle) else bundle
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _parse_source(source: dict[str, Any] | list[Any] | str) -> tuple[Any, list[PolicyValidationRecord]]:
    if isinstance(source, str):
        try:
            return json.loads(source), []
        except json.JSONDecodeError:
            return [], [_validation("bundle", "invalid", "invalid_json")]
    return source, []


def _extract_policies(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if isinstance(payload.get("policies"), list):
            return payload["policies"]
        return [payload]
    return []


def _policy_from_dict(payload: dict[str, Any]) -> RuntimePolicy:
    required = ("policy_id", "policy_name", "policy_type")
    for key in required:
        if not payload.get(key):
            raise PolicyError(f"missing required field: {key}")
    if payload.get("destructive_action") is True:
        raise PolicyError("destructive_action is not allowed")
    return create_runtime_policy(
        policy_id=str(payload["policy_id"]),
        policy_name=str(payload["policy_name"]),
        policy_type=str(payload["policy_type"]),
        enabled=bool(payload.get("enabled", True)),
        severity=str(payload.get("severity") or "medium").lower(),
        match_conditions=dict(payload.get("match_conditions") or {}),
        recommended_action=str(payload.get("recommended_action") or "operator_review"),
        approval_required=bool(payload.get("approval_required", True)),
        enforcement_mode=str(payload.get("enforcement_mode") or "dry_run"),
        source_mode=str(payload.get("source_mode") or "fixture"),
        advisory_notes=[str(item) for item in payload.get("advisory_notes") or []],
    )


def _policy_ref(payload: Any, index: int) -> str:
    if isinstance(payload, dict) and payload.get("policy_id"):
        return str(payload["policy_id"])
    return f"policy-index-{index}"


def _validation(policy_ref: str, state: str, message: str) -> PolicyValidationRecord:
    return PolicyValidationRecord(policy_ref=policy_ref, validation_state=state, message=message)


def _stable_bundle_id(policies: list[RuntimePolicy], records: list[PolicyValidationRecord]) -> str:
    material = json.dumps(
        {
            "policies": [runtime_policy_to_dict(policy) for policy in policies],
            "records": [record.to_dict() for record in records],
        },
        sort_keys=True,
        default=str,
    )
    return "policy-bundle-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
