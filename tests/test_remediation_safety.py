from core_engine.remediation_safety import (
    command_is_confirmed,
    enforce_remediation_command_safety,
    evaluate_remediation_command,
    firewall_dry_run,
)


def test_firewall_dry_run_defaults_safe():
    assert firewall_dry_run({}) is True
    assert firewall_dry_run({"firewall": {"options": {"dry_run": False}}}) is False


def test_destructive_command_forced_to_dry_run_without_active_opt_in():
    command = {"type": "apply_remediation", "decision": "block", "dry_run": False}

    safe = enforce_remediation_command_safety(command, {})

    assert safe["dry_run"] is True
    assert safe["metadata"]["safety_reason"] == "active_enforcement_disabled"
    assert safe["metadata"]["enforcement"] == "dry_run"


def test_destructive_command_requires_confirmation_when_active_enabled():
    settings = {
        "firewall": {"options": {"dry_run": False}},
        "remediation_safety": {"active_enforcement_enabled": True},
    }
    command = {"type": "apply_remediation", "decision": "block", "dry_run": False}

    dry_run, reason = evaluate_remediation_command(command, settings)

    assert dry_run is True
    assert reason == "confirmation_required"


def test_confirmed_destructive_command_can_be_active_when_policy_allows():
    settings = {
        "firewall": {"options": {"dry_run": False}},
        "remediation_safety": {
            "active_enforcement_enabled": True,
            "confirmation_token": "confirm-123",
        },
    }
    command = {
        "type": "apply_remediation",
        "decision": "block",
        "dry_run": False,
        "confirmed": True,
        "confirmation_token": "confirm-123",
    }

    safe = enforce_remediation_command_safety(command, settings)

    assert command_is_confirmed(command, settings) is True
    assert safe["dry_run"] is False
    assert safe["metadata"]["safety_reason"] == "confirmed_active"
    assert safe["metadata"]["enforcement"] == "active"
