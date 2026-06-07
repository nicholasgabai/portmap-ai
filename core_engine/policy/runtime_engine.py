from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.policy.models import PolicyError, SEVERITY_ORDER

POLICY_TYPES = frozenset(
    {
        "port_exposure",
        "service_behavior",
        "flow_behavior",
        "application_attribution",
        "drift_behavior",
        "topology_relationship",
        "runtime_health",
    }
)
EVALUATION_STATES = frozenset({"matched", "not_matched", "degraded", "invalid", "unknown"})
SAFE_ENFORCEMENT_MODES = frozenset({"monitor", "advisory", "dry_run", "supervised_preview"})
UNSAFE_ACTION_TOKENS = frozenset(
    {
        "block",
        "quarantine",
        "isolate",
        "disable",
        "stop",
        "kill",
        "delete",
        "rollback",
        "enforce",
    }
)


@dataclass(slots=True)
class RuntimePolicy:
    policy_id: str
    policy_name: str
    policy_type: str
    enabled: bool = True
    severity: str = "medium"
    match_conditions: dict[str, Any] = field(default_factory=dict)
    recommended_action: str = "operator_review"
    approval_required: bool = True
    enforcement_mode: str = "dry_run"
    source_mode: str = "unknown"
    advisory_notes: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        _required_str(self.policy_id, "policy_id")
        _required_str(self.policy_name, "policy_name")
        if self.policy_type not in POLICY_TYPES:
            raise PolicyError(f"unsupported policy_type: {self.policy_type}")
        if not isinstance(self.enabled, bool):
            raise PolicyError("enabled must be boolean")
        if self.severity not in SEVERITY_ORDER:
            raise PolicyError(f"unsupported severity: {self.severity}")
        if not isinstance(self.match_conditions, dict):
            raise PolicyError("match_conditions must be an object")
        _validate_safe_action(self.recommended_action)
        if not isinstance(self.approval_required, bool):
            raise PolicyError("approval_required must be boolean")
        if self.enforcement_mode not in SAFE_ENFORCEMENT_MODES:
            raise PolicyError(f"unsafe enforcement_mode: {self.enforcement_mode}")
        _required_str(self.source_mode, "source_mode")
        if not isinstance(self.advisory_notes, list) or not all(isinstance(item, str) for item in self.advisory_notes):
            raise PolicyError("advisory_notes must be a list of strings")


@dataclass(slots=True)
class PolicyEvaluation:
    evaluation_id: str
    policy_id: str
    matched: bool
    match_reason: str
    confidence_score: float
    recommended_action: str
    approval_required: bool
    enforcement_mode: str
    evaluation_state: str
    destructive_action: bool = False
    preview_only: bool = True
    source_mode: str = "unknown"
    policy_type: str = "unknown"
    evaluated_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.evaluation_id, "evaluation_id")
        _required_str(self.policy_id, "policy_id")
        if not isinstance(self.matched, bool):
            raise PolicyError("matched must be boolean")
        _required_str(self.match_reason, "match_reason")
        self.confidence_score = _clamp(self.confidence_score)
        _validate_safe_action(self.recommended_action)
        if not isinstance(self.approval_required, bool):
            raise PolicyError("approval_required must be boolean")
        if self.enforcement_mode not in SAFE_ENFORCEMENT_MODES:
            raise PolicyError(f"unsafe enforcement_mode: {self.enforcement_mode}")
        if self.evaluation_state not in EVALUATION_STATES:
            raise PolicyError(f"unsupported evaluation_state: {self.evaluation_state}")
        if self.destructive_action:
            raise PolicyError("policy evaluations cannot be destructive")
        if not self.preview_only:
            raise PolicyError("policy evaluations must remain preview_only")


def create_runtime_policy(
    *,
    policy_id: str,
    policy_name: str,
    policy_type: str,
    enabled: bool = True,
    severity: str = "medium",
    match_conditions: dict[str, Any] | None = None,
    recommended_action: str = "operator_review",
    approval_required: bool = True,
    enforcement_mode: str = "dry_run",
    source_mode: str = "unknown",
    advisory_notes: list[str] | None = None,
) -> RuntimePolicy:
    return RuntimePolicy(
        policy_id=policy_id,
        policy_name=policy_name,
        policy_type=policy_type,
        enabled=enabled,
        severity=str(severity or "medium").lower(),
        match_conditions=match_conditions or {},
        recommended_action=recommended_action,
        approval_required=approval_required,
        enforcement_mode=enforcement_mode,
        source_mode=source_mode,
        advisory_notes=advisory_notes or [],
    )


def runtime_policy_to_dict(policy: RuntimePolicy) -> dict[str, Any]:
    return {
        "record_type": "policy_runtime_record",
        "policy_id": policy.policy_id,
        "policy_name": policy.policy_name,
        "policy_type": policy.policy_type,
        "enabled": policy.enabled,
        "severity": policy.severity,
        "match_conditions": _json_safe(policy.match_conditions),
        "recommended_action": policy.recommended_action,
        "approval_required": policy.approval_required,
        "enforcement_mode": policy.enforcement_mode,
        "source_mode": policy.source_mode,
        "advisory_notes": list(policy.advisory_notes),
        "destructive_action": False,
        "preview_only": True,
        "automatic_changes": False,
        "raw_payload_stored": False,
        "credentials_stored": False,
        "firewall_changes": False,
        "service_changes": False,
    }


def policy_evaluation_to_dict(evaluation: PolicyEvaluation) -> dict[str, Any]:
    return {
        "record_type": "policy_runtime_evaluation",
        "evaluation_id": evaluation.evaluation_id,
        "policy_id": evaluation.policy_id,
        "policy_type": evaluation.policy_type,
        "matched": evaluation.matched,
        "evaluation_state": evaluation.evaluation_state,
        "match_reason": evaluation.match_reason,
        "confidence_score": evaluation.confidence_score,
        "recommended_action": evaluation.recommended_action,
        "approval_required": evaluation.approval_required,
        "enforcement_mode": evaluation.enforcement_mode,
        "destructive_action": evaluation.destructive_action,
        "preview_only": evaluation.preview_only,
        "source_mode": evaluation.source_mode,
        "evaluated_at": evaluation.evaluated_at,
        "automatic_changes": False,
        "raw_payload_stored": False,
        "credentials_stored": False,
        "firewall_changes": False,
        "service_changes": False,
    }


def evaluate_policy(policy: RuntimePolicy, context: dict[str, Any] | None, *, now: str | None = None) -> PolicyEvaluation:
    timestamp = now or _now()
    if not policy.enabled:
        return _evaluation(policy, False, "policy_disabled", 0.0, "not_matched", timestamp)
    if not isinstance(context, dict):
        return _evaluation(policy, False, "context_unavailable", 0.0, "degraded", timestamp)

    context_type = str(context.get("policy_type") or context.get("context_type") or context.get("record_type") or "")
    if context_type and not _type_matches(policy.policy_type, context_type):
        return _evaluation(policy, False, "context_type_not_applicable", 0.0, "not_matched", timestamp)

    try:
        matched, total, confidence = _match_conditions(policy.match_conditions, context)
    except PolicyError as exc:
        return _evaluation(policy, False, str(exc), 0.0, "invalid", timestamp)

    if total == 0:
        return _evaluation(policy, False, "no_match_conditions", 0.0, "unknown", timestamp)
    if matched == total:
        return _evaluation(policy, True, f"matched {matched}/{total} conditions", confidence, "matched", timestamp)
    return _evaluation(policy, False, f"matched {matched}/{total} conditions", confidence, "not_matched", timestamp)


def evaluate_policies(
    policies: Iterable[RuntimePolicy],
    context: dict[str, Any] | None,
    *,
    now: str | None = None,
) -> list[PolicyEvaluation]:
    return [evaluate_policy(policy, context, now=now) for policy in policies]


def build_policy_runtime_summary(evaluations: Iterable[PolicyEvaluation]) -> dict[str, Any]:
    rows = list(evaluations or [])
    by_state: dict[str, int] = {}
    for evaluation in rows:
        by_state[evaluation.evaluation_state] = by_state.get(evaluation.evaluation_state, 0) + 1
    return {
        "record_type": "policy_runtime_summary",
        "evaluation_count": len(rows),
        "matched_count": sum(1 for row in rows if row.matched),
        "by_state": dict(sorted(by_state.items())),
        "approval_required_count": sum(1 for row in rows if row.approval_required and row.matched),
        "destructive_action": False,
        "preview_only": True,
        "automatic_changes": False,
        "raw_payload_stored": False,
        "credentials_stored": False,
        "firewall_changes": False,
        "service_changes": False,
    }


def deterministic_policy_runtime_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _evaluation(
    policy: RuntimePolicy,
    matched: bool,
    reason: str,
    confidence: float,
    state: str,
    timestamp: str,
) -> PolicyEvaluation:
    material = "|".join([policy.policy_id, reason, state, timestamp])
    return PolicyEvaluation(
        evaluation_id="policy-eval-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        policy_id=policy.policy_id,
        matched=matched,
        match_reason=reason,
        confidence_score=confidence,
        recommended_action=policy.recommended_action,
        approval_required=policy.approval_required,
        enforcement_mode=policy.enforcement_mode,
        evaluation_state=state,
        source_mode=policy.source_mode,
        policy_type=policy.policy_type,
        evaluated_at=timestamp,
    )


def _match_conditions(conditions: dict[str, Any], context: dict[str, Any]) -> tuple[int, int, float]:
    if not conditions:
        return 0, 0, 0.0
    matched = 0
    total = 0
    for key, expected in sorted(conditions.items()):
        if key == "equals" and isinstance(expected, dict):
            for path, value in sorted(expected.items()):
                total += 1
                matched += int(_lookup(context, str(path)) == value)
        elif key == "contains" and isinstance(expected, dict):
            for path, value in sorted(expected.items()):
                total += 1
                observed = _lookup(context, str(path))
                matched += int(_contains(observed, value))
        elif key == "minimums" and isinstance(expected, dict):
            for path, value in sorted(expected.items()):
                total += 1
                matched += int(_number(_lookup(context, str(path))) >= _number(value))
        elif key == "maximums" and isinstance(expected, dict):
            for path, value in sorted(expected.items()):
                total += 1
                matched += int(_number(_lookup(context, str(path))) <= _number(value))
        elif key == "severity_at_least":
            total += 1
            observed = str(_lookup(context, "severity") or context.get("drift_severity") or "info").lower()
            expected_severity = str(expected or "info").lower()
            if observed not in SEVERITY_ORDER or expected_severity not in SEVERITY_ORDER:
                raise PolicyError("invalid severity condition")
            matched += int(SEVERITY_ORDER[observed] >= SEVERITY_ORDER[expected_severity])
        else:
            total += 1
            matched += int(_lookup(context, key) == expected)
    confidence = _clamp(matched / total if total else 0.0)
    context_confidence = _first_number(context, ("confidence_score", "metadata_confidence", "reconstruction_confidence"))
    if context_confidence is not None and total:
        confidence = _clamp((confidence + _clamp(context_confidence)) / 2)
    return matched, total, confidence


def _type_matches(policy_type: str, context_type: str) -> bool:
    normalized = context_type.lower()
    if policy_type == "port_exposure":
        return any(token in normalized for token in ("port", "socket", "service", "worker_scan"))
    if policy_type == "service_behavior":
        return "service" in normalized
    if policy_type == "flow_behavior":
        return "flow" in normalized or "session" in normalized
    if policy_type == "application_attribution":
        return "attribution" in normalized or "application" in normalized
    if policy_type == "drift_behavior":
        return "drift" in normalized or "anomaly" in normalized
    if policy_type == "topology_relationship":
        return "topology" in normalized or "relationship" in normalized or "dependency" in normalized
    if policy_type == "runtime_health":
        return "health" in normalized or "runtime" in normalized
    return False


def _lookup(row: dict[str, Any], path: str) -> Any:
    if path in row:
        return row[path]
    current: Any = row
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _contains(observed: Any, expected: Any) -> bool:
    if isinstance(observed, (list, tuple, set)):
        return expected in observed
    if isinstance(observed, str):
        return str(expected) in observed
    return False


def _number(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise PolicyError("numeric condition could not be evaluated") from exc


def _first_number(row: dict[str, Any], keys: Iterable[str]) -> float | None:
    for key in keys:
        value = _lookup(row, key)
        if value is not None:
            try:
                return float(value)
            except (TypeError, ValueError):
                return None
    return None


def _validate_safe_action(action: str) -> None:
    _required_str(action, "recommended_action")
    lowered = action.lower()
    if any(token in lowered for token in UNSAFE_ACTION_TOKENS):
        raise PolicyError(f"unsafe recommended_action: {action}")


def _required_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyError(f"{field_name} must be a non-empty string")
    return value


def _clamp(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0.0
    return round(max(0.0, min(1.0, numeric)), 3)


def _json_safe(value: Any) -> Any:
    if isinstance(value, RuntimePolicy):
        return runtime_policy_to_dict(value)
    if isinstance(value, PolicyEvaluation):
        return policy_evaluation_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
