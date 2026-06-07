import json

import pytest

from core_engine.policy import (
    PolicyError,
    build_policy_runtime_summary,
    create_runtime_policy,
    deterministic_policy_bundle_json,
    deterministic_policy_runtime_json,
    evaluate_policies,
    evaluate_policy,
    load_policy_bundle,
    policy_bundle_to_dict,
    policy_evaluation_to_dict,
    runtime_policy_to_dict,
)


NOW = "2026-06-06T12:00:00+00:00"


def _policy(**overrides):
    payload = {
        "policy_id": "policy-port-exposure",
        "policy_name": "Review Exposed Management Port",
        "policy_type": "port_exposure",
        "enabled": True,
        "severity": "high",
        "match_conditions": {
            "equals": {"port": 22, "source_mode": "live"},
            "minimums": {"confidence_score": 0.7},
        },
        "recommended_action": "operator_review",
        "approval_required": True,
        "enforcement_mode": "dry_run",
        "source_mode": "fixture",
        "advisory_notes": ["Review exposed management service metadata."],
    }
    payload.update(overrides)
    return payload


def test_policy_record_generation_and_export_safety():
    policy = create_runtime_policy(**_policy())
    exported = runtime_policy_to_dict(policy)

    assert exported["policy_id"] == "policy-port-exposure"
    assert exported["policy_type"] == "port_exposure"
    assert exported["destructive_action"] is False
    assert exported["preview_only"] is True
    assert exported["automatic_changes"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert json.loads(deterministic_policy_runtime_json(exported)) == exported


def test_policy_bundle_loading_from_dict_list_and_json():
    bundle = load_policy_bundle({"policies": [_policy()]}, now=NOW)
    direct = load_policy_bundle([_policy()], now=NOW)
    from_json = load_policy_bundle(json.dumps({"policies": [_policy()]}), now=NOW)

    assert len(bundle.policies) == 1
    assert len(direct.policies) == 1
    assert len(from_json.policies) == 1
    assert policy_bundle_to_dict(bundle)["policy_count"] == 1
    assert deterministic_policy_bundle_json(bundle) == deterministic_policy_bundle_json(policy_bundle_to_dict(bundle))


def test_malformed_policy_handling_produces_validation_records():
    bundle = load_policy_bundle({"policies": [{"policy_id": "missing-fields"}]}, now=NOW)

    exported = policy_bundle_to_dict(bundle)
    assert exported["policy_count"] == 0
    assert exported["invalid_policy_count"] == 1
    assert exported["validation_records"][0]["validation_state"] == "invalid"
    assert exported["destructive_action"] is False


def test_disabled_policy_normalizes_and_does_not_match():
    bundle = load_policy_bundle({"policies": [_policy(enabled=False)]}, now=NOW)
    evaluation = evaluate_policy(
        bundle.policies[0],
        {"context_type": "socket_observation", "port": 22, "source_mode": "live", "confidence_score": 0.9},
        now=NOW,
    )

    assert policy_bundle_to_dict(bundle)["disabled_policy_count"] == 1
    assert evaluation.evaluation_state == "not_matched"
    assert evaluation.match_reason == "policy_disabled"
    assert evaluation.matched is False


def test_policy_type_matching_across_telemetry_flow_drift_topology_contexts():
    policies = [
        create_runtime_policy(**_policy(policy_id="policy-port", policy_type="port_exposure", match_conditions={"equals": {"port": 22}})),
        create_runtime_policy(**_policy(policy_id="policy-flow", policy_type="flow_behavior", match_conditions={"equals": {"protocol": "tcp"}})),
        create_runtime_policy(**_policy(policy_id="policy-drift", policy_type="drift_behavior", match_conditions={"severity_at_least": "medium"})),
        create_runtime_policy(
            **_policy(
                policy_id="policy-topology",
                policy_type="topology_relationship",
                match_conditions={"contains": {"relationship_types": "management"}},
            )
        ),
    ]
    contexts = [
        {"context_type": "socket_observation", "port": 22},
        {"context_type": "flow_pair", "protocol": "tcp"},
        {"context_type": "behavior_drift", "severity": "high"},
        {"context_type": "topology_relationship", "relationship_types": ["management", "service"]},
    ]

    results = [evaluate_policy(policy, context, now=NOW) for policy, context in zip(policies, contexts)]

    assert [result.evaluation_state for result in results] == ["matched", "matched", "matched", "matched"]
    assert all(result.preview_only is True for result in results)
    assert all(result.destructive_action is False for result in results)


def test_telemetry_flow_drift_topology_evaluation_summary():
    policies = [
        create_runtime_policy(**_policy(policy_id="policy-match", match_conditions={"equals": {"port": 22}})),
        create_runtime_policy(**_policy(policy_id="policy-miss", match_conditions={"equals": {"port": 443}})),
    ]

    evaluations = evaluate_policies(policies, {"context_type": "socket_observation", "port": 22}, now=NOW)
    summary = build_policy_runtime_summary(evaluations)

    assert [row.evaluation_state for row in evaluations] == ["matched", "not_matched"]
    assert summary["evaluation_count"] == 2
    assert summary["matched_count"] == 1
    assert summary["by_state"] == {"matched": 1, "not_matched": 1}
    assert summary["preview_only"] is True
    assert summary["destructive_action"] is False


def test_confidence_score_bounds_and_context_confidence():
    policy = create_runtime_policy(**_policy(match_conditions={"equals": {"port": 22}}))
    matched = evaluate_policy(policy, {"context_type": "socket_observation", "port": 22, "confidence_score": 0.8}, now=NOW)
    missed = evaluate_policy(policy, {"context_type": "socket_observation", "port": 443, "confidence_score": 1.8}, now=NOW)

    assert 0.0 <= matched.confidence_score <= 1.0
    assert matched.confidence_score == 0.9
    assert 0.0 <= missed.confidence_score <= 1.0
    assert missed.confidence_score == 0.5


def test_unsafe_enforcement_and_destructive_actions_are_rejected():
    unsafe = load_policy_bundle(
        {
            "policies": [
                _policy(policy_id="policy-unsafe-mode", enforcement_mode="active"),
                _policy(policy_id="policy-unsafe-action", recommended_action="block_port"),
                _policy(policy_id="policy-destructive", destructive_action=True),
            ]
        },
        now=NOW,
    )

    exported = policy_bundle_to_dict(unsafe)
    assert exported["policy_count"] == 0
    assert exported["invalid_policy_count"] == 3
    assert all(record["destructive_action"] is False for record in exported["validation_records"])
    with pytest.raises(PolicyError):
        create_runtime_policy(**_policy(recommended_action="quarantine_service"))


def test_evaluation_serialization_is_export_safe():
    policy = create_runtime_policy(**_policy())
    evaluation = evaluate_policy(
        policy,
        {"context_type": "socket_observation", "port": 22, "source_mode": "live", "confidence_score": 0.9},
        now=NOW,
    )
    exported = policy_evaluation_to_dict(evaluation)
    serialized = json.dumps(exported, sort_keys=True)

    assert exported["preview_only"] is True
    assert exported["destructive_action"] is False
    assert exported["firewall_changes"] is False
    assert exported["service_changes"] is False
    assert "192.168." not in serialized
    assert "/" + "Users/" not in serialized


def test_cross_platform_policy_contexts_do_not_change_host_state():
    policy = create_runtime_policy(
        **_policy(
            policy_id="policy-runtime-health",
            policy_type="runtime_health",
            match_conditions={"equals": {"platform_family": "windows"}, "severity_at_least": "low"},
        )
    )
    evaluation = evaluate_policy(
        policy,
        {
            "context_type": "runtime_health",
            "platform_family": "windows",
            "severity": "medium",
            "source_mode": "fixture",
        },
        now=NOW,
    )

    exported = policy_evaluation_to_dict(evaluation)
    assert exported["matched"] is True
    assert exported["preview_only"] is True
    assert exported["automatic_changes"] is False
    assert exported["credentials_stored"] is False
