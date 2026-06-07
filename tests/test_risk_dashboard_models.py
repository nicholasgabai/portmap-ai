import json

import pytest

from core_engine.visualization import (
    RiskDashboardError,
    build_risk_dashboard_panel,
    deterministic_risk_dashboard_json,
    empty_risk_dashboard_panel,
    make_risk_card,
    risk_state_from_score,
    sort_risk_cards,
)


T1 = "2026-01-01T00:00:00+00:00"


def _asset(**overrides):
    base = {
        "asset_id": "asset-redacted-server",
        "asset_role": "server",
        "asset_state": "active",
        "confidence_score": 0.76,
        "observed_flow_count": 3,
        "related_flow_references": ["flow-redacted-web"],
        "source_modes": ["live"],
        "risk_summary": {
            "max_risk_score": 0.72,
            "recommended_review": True,
            "preview_only": True,
            "destructive_action": False,
        },
    }
    base.update(overrides)
    return base


def _flow(**overrides):
    base = {
        "flow_reference": "flow-redacted-web",
        "service_hint": "https",
        "risk_score": 0.66,
        "confidence_score": 0.81,
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def test_risk_card_generation_is_export_safe():
    card = make_risk_card(
        card_type="flow_risk",
        card_title="Flow risk",
        severity_level="high",
        confidence_score=0.8,
        risk_score=0.7,
        summary="Flow metadata requires review",
        explanation_points=["policy matched", "drift observed"],
        related_flow_references=["flow-redacted-web"],
        recommended_next_step="review_flow",
        source_modes=["live"],
    ).to_dict()

    assert card["record_type"] == "visual_risk_card"
    assert card["card_type"] == "flow_risk"
    assert card["severity_level"] == "high"
    assert card["source_modes"] == ["live"]
    assert card["preview_only"] is True
    assert card["destructive_action"] is False
    assert card["browser_ui_started"] is False
    assert card["enforcement_enabled"] is False
    assert card["raw_payload_stored"] is False
    assert 0.0 <= card["risk_score"] <= 1.0
    assert 0.0 <= card["confidence_score"] <= 1.0


def test_dashboard_generation_aggregates_counts_scores_and_recommendations():
    dashboard = build_risk_dashboard_panel(
        asset_inventory={"assets": [_asset()]},
        flow_summaries=[_flow()],
        policy_evaluations=[
            {
                "evaluation_id": "eval-redacted-001",
                "policy_id": "policy-redacted-001",
                "matched": True,
                "severity": "high",
                "confidence_score": 0.88,
                "recommended_action": "review",
                "source_mode": "live",
            }
        ],
        remediation_recommendations=[
            {
                "recommendation_id": "rec-redacted-001",
                "recommendation_type": "block_preview",
                "recommended_action": "block_preview",
                "risk_score": 0.83,
                "confidence_score": 0.74,
                "approval_required": True,
                "policy_references": ["policy-redacted-001"],
                "flow_references": ["flow-redacted-web"],
                "source_mode": "live",
            }
        ],
        incident_candidates=[
            {
                "candidate_id": "candidate-redacted-001",
                "candidate_type": "drift_review",
                "severity_level": "medium",
                "confidence_score": 0.6,
                "recommended_next_step": "review_candidate",
                "source_mode": "live",
            }
        ],
        guardrail_records=[
            {
                "guardrail_id": "guardrail-redacted-001",
                "guardrail_state": "blocked",
                "safety_blockers": ["approval required"],
                "source_mode": "live",
            }
        ],
        runtime_health_summaries=[
            {
                "runtime_id": "runtime-redacted-001",
                "health_state": "degraded",
                "confidence_score": 0.7,
                "source_mode": "live",
            }
        ],
        drift_records=[
            {
                "drift_id": "drift-redacted-001",
                "drift_score": 0.57,
                "drift_severity": "moderate_drift",
                "confidence_score": 0.66,
                "source_mode": "live",
            }
        ],
        attribution_records=[
            {
                "attribution_id": "attr-redacted-001",
                "attribution_state": "conflicting",
                "confidence_score": 0.42,
                "conflict_reason": "metadata conflict",
                "source_mode": "live",
            }
        ],
        generated_at=T1,
    ).to_dict()

    assert dashboard["record_type"] == "visual_risk_dashboard_panel"
    assert dashboard["risk_state"] in {"elevated", "high", "critical"}
    assert dashboard["overall_risk_score"] >= 0.7
    assert dashboard["highest_severity"] == "high"
    assert dashboard["card_count"] >= 8
    assert dashboard["severity_counts"]["high"] >= 1
    assert dashboard["category_counts"]["remediation_preview"] == 1
    assert dashboard["category_counts"]["guardrail_block"] == 1
    assert dashboard["recommendation_count"] >= 3
    assert dashboard["blocked_action_count"] >= 1
    assert dashboard["preview_only"] is True
    assert dashboard["destructive_action"] is False
    assert all(card["preview_only"] is True for card in dashboard["cards"])
    assert all(card["destructive_action"] is False for card in dashboard["cards"])


def test_dashboard_sorts_high_risk_first_bounds_and_deduplicates_cards():
    duplicate_flow = _flow(risk_score=0.92, flow_reference="flow-redacted-dup")
    dashboard = build_risk_dashboard_panel(
        flow_summaries=[
            duplicate_flow,
            duplicate_flow,
            _flow(flow_reference="flow-redacted-low", risk_score=0.2),
            _flow(flow_reference="flow-redacted-mid", risk_score=0.55),
        ],
        generated_at=T1,
        max_cards=2,
    ).to_dict()

    risks = [card["risk_score"] for card in dashboard["cards"]]

    assert dashboard["card_count"] == 2
    assert dashboard["bounded"] is True
    assert dashboard["max_cards"] == 2
    assert risks == sorted(risks, reverse=True)
    assert dashboard["cards"][0]["severity_level"] == "critical"


def test_empty_dashboard_and_malformed_inputs():
    empty = empty_risk_dashboard_panel(generated_at=T1).to_dict()

    assert empty["card_count"] == 0
    assert empty["cards"] == []
    assert empty["risk_state"] == "empty"
    assert empty["overall_risk_score"] == 0.0
    assert empty["export_safe"] is True

    with pytest.raises(RiskDashboardError):
        build_risk_dashboard_panel(flow_summaries=object(), generated_at=T1)
    with pytest.raises(RiskDashboardError):
        build_risk_dashboard_panel(policy_evaluations="not-a-list", generated_at=T1)

    dashboard = build_risk_dashboard_panel(flow_summaries=[object(), _flow()], generated_at=T1).to_dict()
    assert dashboard["card_count"] == 1


def test_source_mode_preservation_and_cross_platform_fixture_records():
    dashboard = build_risk_dashboard_panel(
        flow_summaries=[
            _flow(source_mode="fixture", service_hint="ssh", risk_score=0.51),
            _flow(flow_reference="flow-redacted-win", source_mode="simulated", service_hint="https", risk_score=0.62),
            _flow(flow_reference="flow-redacted-replay", source_mode="replay", service_hint="dns", risk_score=0.41),
        ],
        generated_at=T1,
    ).to_dict()

    modes = {tuple(card["source_modes"]) for card in dashboard["cards"]}

    assert ("fixture",) in modes
    assert ("simulated",) in modes
    assert ("replay",) in modes
    assert all("dummy_app" not in card["summary"] for card in dashboard["cards"])
    assert all("dummy_db" not in card["summary"] for card in dashboard["cards"])


def test_dashboard_serialization_redacts_private_identifier_like_references():
    sensitive_reference = "sensitive/ref/value"
    dashboard = build_risk_dashboard_panel(
        flow_summaries=[
            _flow(
                flow_reference=sensitive_reference,
                service_hint="https",
                risk_score=0.8,
                source_mode="live",
            )
        ],
        generated_at=T1,
    )
    payload = deterministic_risk_dashboard_json(dashboard)

    assert payload == json.dumps(dashboard.to_dict(), sort_keys=True, separators=(",", ":"), default=str)
    assert sensitive_reference not in payload
    assert "hostname" not in payload
    assert "payload_content" not in payload
    assert '"raw_payload_stored":false' in payload
    assert '"raw_dns_history_stored":false' in payload
    assert '"private_identifier_exported":false' in payload


def test_sort_helper_and_risk_state_helper_are_deterministic():
    low = make_risk_card(card_type="flow_risk", card_title="Low", severity_level="low", risk_score=0.2)
    high = make_risk_card(card_type="flow_risk", card_title="High", severity_level="high", risk_score=0.8)

    assert sort_risk_cards([low, high])[0].card_id == high.card_id
    assert risk_state_from_score(0.0, card_count=0) == "empty"
    assert risk_state_from_score(0.8, card_count=1) == "high"
