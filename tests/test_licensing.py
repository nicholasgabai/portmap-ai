from __future__ import annotations

import json
import socket
from copy import deepcopy

from core_engine.licensing import (
    deterministic_license_json,
    get_license_limit,
    is_feature_enabled,
    load_license,
    summarize_license,
    validate_license,
)


NOW = "2026-06-27T12:00:00+00:00"


def license_payload(**overrides):
    payload = {
        "license_id": "lic-professional-001",
        "edition": "professional",
        "issued_to": "local operator",
        "issued_at": "2026-01-01T00:00:00+00:00",
        "expires_at": "2026-12-31T00:00:00+00:00",
        "features": ["custom_reports"],
        "limits": {"nodes": 12, "exports_per_day": 75},
        "signature_status": "placeholder_valid",
        "grace_period": 14,
        "metadata": {"deployment": "local", "tier": "review"},
    }
    payload.update(overrides)
    return payload


def test_missing_license_file(tmp_path):
    loaded = load_license(tmp_path / "missing-license.json")
    summary = summarize_license(loaded, current_time=NOW)

    assert summary["status"] == "missing"
    assert summary["license_id"] == "license-missing"
    assert summary["validation_reason"] == "license file is missing"
    assert summary["network_called"] is False
    assert summary["runtime_state_mutated"] is False


def test_valid_license_file_load_and_validation(tmp_path):
    path = tmp_path / "license.json"
    path.write_text(json.dumps(license_payload()), encoding="utf-8")

    loaded = load_license(path)
    summary = summarize_license(loaded, current_time=NOW)

    assert summary["status"] == "valid"
    assert summary["edition"] == "professional"
    assert summary["signature_status"] == "placeholder_valid"
    assert "advanced_attribution" in summary["features"]
    assert "custom_reports" in summary["features"]
    assert summary["limits"]["nodes"] == 12
    assert summary["validation_reason"] == "license is valid for local entitlement checks"


def test_expired_license():
    summary = summarize_license(
        license_payload(expires_at="2026-01-31T00:00:00+00:00", grace_period=7),
        current_time=NOW,
    )

    assert summary["status"] == "expired"
    assert summary["validation_reason"] == "license is expired"
    assert is_feature_enabled(summary, "advanced_attribution") is False
    assert get_license_limit(summary, "nodes", default=0) == 0


def test_malformed_license_file(tmp_path):
    path = tmp_path / "license.json"
    path.write_text("{bad-json", encoding="utf-8")

    summary = summarize_license(load_license(path), current_time=NOW)

    assert summary["status"] == "invalid"
    assert summary["license_id"] == "license-invalid"
    assert summary["validation_reason"] == "license file is malformed"


def test_invalid_signature_placeholder():
    summary = summarize_license(
        license_payload(signature_status="invalid"),
        current_time=NOW,
    )

    assert summary["status"] == "invalid"
    assert summary["validation_reason"] == "license signature placeholder is not valid"
    assert is_feature_enabled(summary, "advanced_attribution") is False


def test_grace_period_behavior():
    summary = summarize_license(
        license_payload(expires_at="2026-06-20T12:00:00+00:00", grace_period=14),
        current_time=NOW,
    )

    assert summary["status"] == "grace_period"
    assert summary["grace_period"] == 14
    assert is_feature_enabled(summary, "advanced_attribution") is True
    assert get_license_limit(summary, "nodes") == 12


def test_feature_enabled_disabled_and_limit_lookup():
    license_data = license_payload(features={"custom_reports": True, "disabled_feature": False})

    assert is_feature_enabled(license_data, "custom_reports") is True
    assert is_feature_enabled(license_data, "disabled_feature") is False
    assert is_feature_enabled(license_data, "federated_intelligence") is False
    assert get_license_limit(license_data, "exports_per_day") == 75
    assert get_license_limit(license_data, "unknown_limit", default="n/a") == "n/a"


def test_edition_behavior_defaults():
    community = summarize_license(
        license_payload(edition="community", features=[], limits={}),
        current_time=NOW,
    )
    enterprise = summarize_license(
        license_payload(edition="enterprise", features=[], limits={}),
        current_time=NOW,
    )

    assert community["status"] == "valid"
    assert "basic_attribution" in community["features"]
    assert "federated_intelligence" not in community["features"]
    assert community["limits"]["nodes"] == 1
    assert "federated_intelligence" in enterprise["features"]
    assert enterprise["limits"]["nodes"] == 500


def test_deterministic_summary_output():
    payload = license_payload(
        features=["z_feature", "a_feature"],
        metadata={"z": "last", "a": "first"},
        limits={"workers": 4, "nodes": 2},
    )

    first = summarize_license(payload, current_time=NOW)
    second = summarize_license(payload, current_time=NOW)

    assert first == second
    assert first["features"] == sorted(first["features"])
    assert list(first["limits"].keys()) == sorted(first["limits"].keys())
    assert deterministic_license_json(payload) == deterministic_license_json(payload)


def test_no_network_calls(monkeypatch):
    calls: list[tuple[object, ...]] = []

    def fake_create_connection(*args, **kwargs):
        calls.append(args)
        raise AssertionError("license validation must remain local")

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    summary = summarize_license(license_payload(), current_time=NOW)

    assert calls == []
    assert summary["network_called"] is False
    assert summary["remote_license_server_contacted"] is False
    assert summary["billing_contacted"] is False
    assert summary["customer_provisioning_contacted"] is False


def test_validation_does_not_mutate_runtime_state_or_input():
    payload = license_payload(features={"custom_reports": True}, limits={"nodes": 7})
    before = deepcopy(payload)

    record = validate_license(payload, current_time=NOW)
    summary = record.to_dict()

    assert payload == before
    assert summary["runtime_state_mutated"] is False
    assert summary["enforcement_enabled"] is False
    assert summary["cloud_dependency"] is False
