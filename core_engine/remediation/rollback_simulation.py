from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable


ROLLBACK_SIMULATION_STATES = frozenset({"ready", "degraded", "blocked", "unavailable", "unknown"})


class RollbackSimulationError(ValueError):
    """Raised when rollback simulation preview input is malformed or unsafe."""


@dataclass(slots=True)
class RollbackSimulationPreview:
    rollback_simulation_id: str
    target_action: str
    rollback_available: bool
    rollback_confidence: float
    rollback_steps: list[str] = field(default_factory=list)
    validation_steps: list[str] = field(default_factory=list)
    failure_modes: list[str] = field(default_factory=list)
    required_backups: list[str] = field(default_factory=list)
    operator_actions: list[str] = field(default_factory=list)
    simulation_state: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False
    source_mode: str = "unknown"
    created_at: str = field(default_factory=lambda: _now())

    def __post_init__(self) -> None:
        _required_str(self.rollback_simulation_id, "rollback_simulation_id")
        _required_str(self.target_action, "target_action")
        if not isinstance(self.rollback_available, bool):
            raise RollbackSimulationError("rollback_available must be boolean")
        self.rollback_confidence = _clamp(self.rollback_confidence)
        for field_name in (
            "rollback_steps",
            "validation_steps",
            "failure_modes",
            "required_backups",
            "operator_actions",
        ):
            if not _is_string_list(getattr(self, field_name)):
                raise RollbackSimulationError(f"{field_name} must be a list of strings")
        if self.simulation_state not in ROLLBACK_SIMULATION_STATES:
            raise RollbackSimulationError(f"unsupported simulation_state: {self.simulation_state}")
        if not self.preview_only:
            raise RollbackSimulationError("rollback simulations must remain preview_only")
        if self.destructive_action:
            raise RollbackSimulationError("rollback simulations cannot be destructive")
        _required_str(self.source_mode, "source_mode")


def build_rollback_simulation(
    *,
    target_action: str,
    rollback_available: bool | None = None,
    rollback_confidence: float = 0.0,
    required_backups: Iterable[str] | None = None,
    validation_steps: Iterable[str] | None = None,
    failure_modes: Iterable[str] | None = None,
    source_mode: str = "unknown",
    now: str | None = None,
) -> RollbackSimulationPreview:
    available = bool(rollback_available) if rollback_available is not None else bool(required_backups)
    confidence = _clamp(rollback_confidence)
    backups = _strings(required_backups) or ["operator_approved_backup_reference_required"]
    validations = _strings(validation_steps) or ["validate_preview_state", "confirm_operator_approval"]
    failures = _strings(failure_modes)
    if not available:
        state = "unavailable"
        failures = sorted(set(failures + ["rollback_plan_missing"]))
    elif confidence < 0.35:
        state = "blocked"
        failures = sorted(set(failures + ["rollback_confidence_too_low"]))
    elif confidence < 0.65:
        state = "degraded"
    else:
        state = "ready"
    steps = _rollback_steps(target_action, available)
    operator_actions = ["review_rollback_preview", "confirm_required_backups", "confirm_validation_steps"]
    if state in {"blocked", "unavailable"}:
        operator_actions.append("resolve_rollback_blockers")
    material = deterministic_rollback_simulation_json(
        {
            "target_action": target_action,
            "state": state,
            "confidence": confidence,
            "source_mode": source_mode,
            "created_at": now or _now(),
        }
    )
    return RollbackSimulationPreview(
        rollback_simulation_id="rollback-sim-" + sha256(material.encode("utf-8")).hexdigest()[:16],
        target_action=target_action,
        rollback_available=available,
        rollback_confidence=confidence,
        rollback_steps=steps,
        validation_steps=validations,
        failure_modes=failures,
        required_backups=backups,
        operator_actions=operator_actions,
        simulation_state=state,
        preview_only=True,
        destructive_action=False,
        source_mode=source_mode,
        created_at=now or _now(),
    )


def rollback_simulation_to_dict(simulation: RollbackSimulationPreview) -> dict[str, Any]:
    return {
        "record_type": "rollback_simulation_preview",
        "rollback_simulation_id": simulation.rollback_simulation_id,
        "target_action": simulation.target_action,
        "rollback_available": simulation.rollback_available,
        "rollback_confidence": simulation.rollback_confidence,
        "rollback_steps": list(simulation.rollback_steps),
        "validation_steps": list(simulation.validation_steps),
        "failure_modes": list(simulation.failure_modes),
        "required_backups": list(simulation.required_backups),
        "operator_actions": list(simulation.operator_actions),
        "simulation_state": simulation.simulation_state,
        "preview_only": simulation.preview_only,
        "destructive_action": simulation.destructive_action,
        "source_mode": simulation.source_mode,
        "created_at": simulation.created_at,
        "automatic_changes": False,
        "rollback_executed": False,
        "backups_created": False,
        "files_restored": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def build_rollback_simulation_summary(simulations: Iterable[RollbackSimulationPreview]) -> dict[str, Any]:
    rows = list(simulations or [])
    by_state: dict[str, int] = {}
    for row in rows:
        by_state[row.simulation_state] = by_state.get(row.simulation_state, 0) + 1
    return {
        "record_type": "rollback_simulation_summary",
        "simulation_count": len(rows),
        "by_state": dict(sorted(by_state.items())),
        "ready_count": by_state.get("ready", 0),
        "blocked_count": by_state.get("blocked", 0) + by_state.get("unavailable", 0),
        "preview_only": True,
        "destructive_action": False,
        "automatic_changes": False,
        "rollback_executed": False,
        "backups_created": False,
        "files_restored": False,
        "firewall_changes": False,
        "service_changes": False,
        "process_changes": False,
        "credentials_stored": False,
        "raw_payload_stored": False,
    }


def deterministic_rollback_simulation_json(payload: Any) -> str:
    return json.dumps(_json_safe(payload), sort_keys=True, separators=(",", ":"), default=str)


def _rollback_steps(target_action: str, available: bool) -> list[str]:
    if not available:
        return ["define_manual_rollback_plan", "collect_required_backup_references"]
    return [f"preview_rollback_for_{_safe_token(target_action)}", "validate_preview_only_state", "confirm_no_action_executed"]


def _safe_token(value: str) -> str:
    return "".join(ch if ch.isalnum() or ch in {"_", "-"} else "_" for ch in str(value).lower())[:48] or "unknown"


def _strings(values: Iterable[str] | None) -> list[str]:
    return sorted({str(value) for value in values or [] if str(value).strip()})


def _required_str(value: Any, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RollbackSimulationError(f"{field_name} must be a non-empty string")


def _is_string_list(value: Any) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _clamp(value: Any) -> float:
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        numeric = 0.0
    return round(max(0.0, min(1.0, numeric)), 3)


def _json_safe(value: Any) -> Any:
    if isinstance(value, RollbackSimulationPreview):
        return rollback_simulation_to_dict(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    return value


def _now() -> str:
    return datetime.now(UTC).isoformat()
