"""Safety gates for remediation commands."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

DESTRUCTIVE_DECISIONS = {"block", "drop", "kill", "kill_process", "terminate"}


def firewall_dry_run(settings: dict[str, Any] | None) -> bool:
    firewall = (settings or {}).get("firewall") or {}
    options = firewall.get("options") or {}
    if "dry_run" in firewall:
        return bool(firewall["dry_run"])
    if "dry_run" in options:
        return bool(options["dry_run"])
    return True


def safety_policy(settings: dict[str, Any] | None) -> dict[str, Any]:
    policy = (settings or {}).get("remediation_safety") or {}
    if not isinstance(policy, dict):
        policy = {}
    return {
        "active_enforcement_enabled": bool(policy.get("active_enforcement_enabled", False)),
        "require_confirmation": bool(policy.get("require_confirmation", True)),
        "confirmation_token": policy.get("confirmation_token"),
    }


def is_destructive_decision(decision: str | None) -> bool:
    return str(decision or "").lower() in DESTRUCTIVE_DECISIONS


def command_is_confirmed(command: dict[str, Any], settings: dict[str, Any] | None = None) -> bool:
    policy = safety_policy(settings)
    if not policy["require_confirmation"]:
        return True
    if not command.get("confirmed"):
        return False
    expected_token = policy.get("confirmation_token")
    if expected_token:
        return command.get("confirmation_token") == expected_token
    return True


def evaluate_remediation_command(command: dict[str, Any], settings: dict[str, Any] | None = None) -> tuple[bool, str]:
    """Return (dry_run, reason) for a remediation command."""

    if bool(command.get("dry_run", True)):
        return True, "command_dry_run"

    decision = str(command.get("decision") or "")
    if not is_destructive_decision(decision):
        return False, "non_destructive"

    policy = safety_policy(settings)
    if not policy["active_enforcement_enabled"]:
        return True, "active_enforcement_disabled"
    if not command_is_confirmed(command, settings):
        return True, "confirmation_required"
    if firewall_dry_run(settings):
        return True, "firewall_dry_run"
    return False, "confirmed_active"


def enforce_remediation_command_safety(command: dict[str, Any], settings: dict[str, Any] | None = None) -> dict[str, Any]:
    safe_command = deepcopy(command)
    effective_dry_run, safety_reason = evaluate_remediation_command(safe_command, settings)
    safe_command["dry_run"] = effective_dry_run
    metadata = safe_command.setdefault("metadata", {})
    if isinstance(metadata, dict):
        metadata["safety_reason"] = safety_reason
        metadata["enforcement"] = "dry_run" if effective_dry_run else "active"
    return safe_command


__all__ = [
    "DESTRUCTIVE_DECISIONS",
    "command_is_confirmed",
    "enforce_remediation_command_safety",
    "evaluate_remediation_command",
    "firewall_dry_run",
    "is_destructive_decision",
    "safety_policy",
]
