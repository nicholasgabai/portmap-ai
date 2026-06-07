from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Iterable

from core_engine.visualization.risk_cards import (
    RISK_DASHBOARD_SAFETY_FLAGS,
    RiskCard,
    RiskDashboardError,
    make_risk_card,
    risk_score_from_severity,
    severity_from_risk_score,
    severity_rank,
)
from core_engine.visualization.timeline_models import (
    normalize_severity,
    sanitize_reference,
    sanitize_references,
    sanitize_summary,
)
from core_engine.visualization.topology_models import clamp_score, normalize_source_mode, now_timestamp


RISK_DASHBOARD_RECORD_VERSION = 1
DEFAULT_MAX_RISK_CARDS = 128
RISK_STATES = {"empty", "nominal", "elevated", "high", "critical", "degraded", "unknown"}


@dataclass(frozen=True)
class RiskDashboardPanel:
    dashboard_id: str
    generated_at: str
    risk_state: str
    overall_risk_score: float
    highest_severity: str
    card_count: int
    severity_counts: dict[str, int]
    category_counts: dict[str, int]
    recommendation_count: int
    blocked_action_count: int
    cards: list[RiskCard] = field(default_factory=list)
    bounded: bool = True
    max_cards: int = DEFAULT_MAX_RISK_CARDS
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        card_rows = [card.to_dict() for card in self.cards]
        return {
            "record_type": "visual_risk_dashboard_panel",
            "record_version": RISK_DASHBOARD_RECORD_VERSION,
            "dashboard_id": sanitize_reference(self.dashboard_id),
            "generated_at": str(self.generated_at or ""),
            "risk_state": normalize_risk_state(self.risk_state),
            "overall_risk_score": clamp_score(self.overall_risk_score),
            "highest_severity": normalize_severity(self.highest_severity),
            "card_count": max(0, int(self.card_count or 0)),
            "severity_counts": dict(self.severity_counts),
            "category_counts": dict(self.category_counts),
            "recommendation_count": max(0, int(self.recommendation_count or 0)),
            "blocked_action_count": max(0, int(self.blocked_action_count or 0)),
            "cards": card_rows,
            "bounded": True,
            "max_cards": max(0, int(self.max_cards or 0)),
            "export_safe": True,
            "preview_only": True,
            "destructive_action": False,
            **RISK_DASHBOARD_SAFETY_FLAGS,
        }


def build_risk_dashboard_panel(
    *,
    asset_inventory: dict[str, Any] | None = None,
    topology_graphs: Iterable[dict[str, Any]] | None = None,
    flow_summaries: Iterable[dict[str, Any]] | None = None,
    policy_evaluations: Iterable[dict[str, Any]] | None = None,
    remediation_recommendations: Iterable[dict[str, Any]] | None = None,
    incident_candidates: Iterable[dict[str, Any]] | None = None,
    guardrail_records: Iterable[dict[str, Any]] | None = None,
    runtime_health_summaries: Iterable[dict[str, Any]] | None = None,
    drift_records: Iterable[dict[str, Any]] | None = None,
    attribution_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_cards: int = DEFAULT_MAX_RISK_CARDS,
) -> RiskDashboardPanel:
    _validate_iterable("topology_graphs", topology_graphs)
    _validate_iterable("flow_summaries", flow_summaries)
    _validate_iterable("policy_evaluations", policy_evaluations)
    _validate_iterable("remediation_recommendations", remediation_recommendations)
    _validate_iterable("incident_candidates", incident_candidates)
    _validate_iterable("guardrail_records", guardrail_records)
    _validate_iterable("runtime_health_summaries", runtime_health_summaries)
    _validate_iterable("drift_records", drift_records)
    _validate_iterable("attribution_records", attribution_records)
    timestamp = generated_at or now_timestamp()
    cards: list[RiskCard] = []
    cards.extend(_cards_from_asset_inventory(asset_inventory))
    cards.extend(_cards_from_topology_graphs(_dict_rows(topology_graphs)))
    cards.extend(_cards_from_flows(_dict_rows(flow_summaries)))
    cards.extend(_cards_from_policy_evaluations(_dict_rows(policy_evaluations)))
    cards.extend(_cards_from_remediation(_dict_rows(remediation_recommendations)))
    cards.extend(_cards_from_incidents(_dict_rows(incident_candidates)))
    cards.extend(_cards_from_guardrails(_dict_rows(guardrail_records)))
    cards.extend(_cards_from_runtime_health(_dict_rows(runtime_health_summaries)))
    cards.extend(_cards_from_drift(_dict_rows(drift_records)))
    cards.extend(_cards_from_attribution(_dict_rows(attribution_records)))
    return summarize_risk_dashboard(cards, generated_at=timestamp, max_cards=max_cards)


def summarize_risk_dashboard(
    cards: Iterable[RiskCard],
    *,
    generated_at: str | None = None,
    max_cards: int = DEFAULT_MAX_RISK_CARDS,
) -> RiskDashboardPanel:
    rows = sort_risk_cards(deduplicate_risk_cards(cards))[: max(0, int(max_cards))]
    severity_counts = Counter(card.severity_level for card in rows)
    category_counts = Counter(card.card_type for card in rows)
    blocked_count = sum(1 for card in rows if card.card_type == "guardrail_block" or "blocked" in _combined_text(card))
    recommendation_count = sum(1 for card in rows if card.card_type == "remediation_preview" or card.recommended_next_step not in {"monitor", "unknown", ""})
    highest = _highest_severity(rows)
    overall_score = _overall_risk_score(rows)
    timestamp = generated_at or now_timestamp()
    return RiskDashboardPanel(
        dashboard_id="risk-dashboard-" + _digest({"generated_at": timestamp, "cards": [card.card_id for card in rows], "max_cards": max_cards})[:16],
        generated_at=timestamp,
        risk_state=risk_state_from_score(overall_score, card_count=len(rows)),
        overall_risk_score=overall_score,
        highest_severity=highest,
        card_count=len(rows),
        severity_counts={key: int(severity_counts[key]) for key in sorted(severity_counts)},
        category_counts={key: int(category_counts[key]) for key in sorted(category_counts)},
        recommendation_count=recommendation_count,
        blocked_action_count=blocked_count,
        cards=rows,
        bounded=True,
        max_cards=max_cards,
        export_safe=True,
    )


def empty_risk_dashboard_panel(*, generated_at: str | None = None, max_cards: int = DEFAULT_MAX_RISK_CARDS) -> RiskDashboardPanel:
    return summarize_risk_dashboard([], generated_at=generated_at or now_timestamp(), max_cards=max_cards)


def deduplicate_risk_cards(cards: Iterable[RiskCard]) -> list[RiskCard]:
    grouped: dict[str, RiskCard] = {}
    for card in cards or []:
        if not isinstance(card, RiskCard):
            continue
        existing = grouped.get(card.card_id)
        if existing is None or _sort_key(card) < _sort_key(existing):
            grouped[card.card_id] = card
    return list(grouped.values())


def sort_risk_cards(cards: Iterable[RiskCard]) -> list[RiskCard]:
    return sorted([card for card in cards or [] if isinstance(card, RiskCard)], key=_sort_key)


def deterministic_risk_dashboard_json(record: RiskDashboardPanel | RiskCard | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, (RiskDashboardPanel, RiskCard)) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def risk_state_from_score(score: Any, *, card_count: int = 0) -> str:
    if card_count <= 0:
        return "empty"
    risk = clamp_score(score)
    if risk >= 0.9:
        return "critical"
    if risk >= 0.7:
        return "high"
    if risk >= 0.45:
        return "elevated"
    return "nominal"


def normalize_risk_state(value: Any) -> str:
    state = str(value or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    return state if state in RISK_STATES else "unknown"


def _cards_from_asset_inventory(inventory: dict[str, Any] | None) -> list[RiskCard]:
    if not isinstance(inventory, dict):
        return []
    assets = inventory.get("assets") or []
    if not isinstance(assets, list):
        return []
    cards = []
    for asset in assets:
        if not isinstance(asset, dict):
            continue
        risk_summary = asset.get("risk_summary") if isinstance(asset.get("risk_summary"), dict) else {}
        risk_score = _first_score(risk_summary.get("max_risk_score"), asset.get("risk_score"))
        if risk_score <= 0.0 and not risk_summary.get("recommended_review"):
            continue
        cards.append(
            make_risk_card(
                card_type="asset_risk",
                card_title=f"{asset.get('asset_role') or 'unknown'} asset risk",
                severity_level=severity_from_risk_score(risk_score),
                confidence_score=asset.get("confidence_score"),
                risk_score=risk_score,
                summary="Asset inventory risk summary",
                explanation_points=[
                    f"asset state: {asset.get('asset_state') or 'unknown'}",
                    f"observed flows: {asset.get('observed_flow_count') or 0}",
                ],
                related_asset_references=[asset.get("asset_id")],
                related_flow_references=asset.get("related_flow_references") or [],
                recommended_next_step="review_asset" if risk_summary.get("recommended_review") else "monitor",
                source_modes=asset.get("source_modes") or [],
            )
        )
    return cards


def _cards_from_topology_graphs(graphs: list[dict[str, Any]]) -> list[RiskCard]:
    cards = []
    for graph in graphs:
        edges = graph.get("edges") or []
        if not isinstance(edges, list):
            continue
        for edge in edges:
            if not isinstance(edge, dict):
                continue
            risk_score = _first_score(edge.get("risk_score"), edge.get("weight"))
            if risk_score < 0.45 and not edge.get("drift_detected"):
                continue
            cards.append(
                make_risk_card(
                    card_type="topology_risk",
                    card_title="Topology relationship risk",
                    severity_level=severity_from_risk_score(risk_score),
                    confidence_score=edge.get("confidence_score"),
                    risk_score=risk_score,
                    summary="Topology edge has elevated metadata risk",
                    explanation_points=[f"relationship: {edge.get('relationship_type') or 'unknown'}"],
                    related_flow_references=[edge.get("flow_reference")],
                    recommended_next_step="review_topology",
                    source_modes=[edge.get("source_mode") or edge.get("data_source")],
                )
            )
    return cards


def _cards_from_flows(flows: list[dict[str, Any]]) -> list[RiskCard]:
    cards = []
    for flow in flows:
        risk_score = _first_score(flow.get("risk_score"), flow.get("score"))
        if risk_score <= 0.0 and not flow.get("drift_detected"):
            continue
        cards.append(
            make_risk_card(
                card_type="flow_risk",
                card_title="Flow risk",
                severity_level=severity_from_risk_score(risk_score),
                confidence_score=flow.get("confidence_score"),
                risk_score=risk_score,
                summary="Flow metadata risk summary",
                explanation_points=[f"service: {flow.get('service_hint') or flow.get('service') or 'unknown'}"],
                related_flow_references=[flow.get("flow_reference") or flow.get("flow_id") or flow.get("session_id")],
                recommended_next_step="review_flow" if risk_score >= 0.45 else "monitor",
                source_modes=[flow.get("source_mode") or flow.get("data_source")],
            )
        )
    return cards


def _cards_from_policy_evaluations(rows: list[dict[str, Any]]) -> list[RiskCard]:
    cards = []
    for row in rows:
        matched = bool(row.get("matched")) or str(row.get("evaluation_state") or "").lower() == "matched"
        if not matched:
            continue
        severity = normalize_severity(row.get("severity") or row.get("severity_level") or "medium")
        cards.append(
            make_risk_card(
                card_type="policy_risk",
                card_title="Policy matched",
                severity_level=severity,
                confidence_score=row.get("confidence_score"),
                risk_score=_first_score(row.get("risk_score"), risk_score_from_severity(severity)),
                summary=row.get("match_reason") or "Policy evaluation matched metadata context",
                explanation_points=[row.get("policy_id") or "policy reference available"],
                related_policy_references=[row.get("policy_id"), row.get("evaluation_id")],
                related_flow_references=row.get("related_flow_references") or row.get("flow_references") or [],
                recommended_next_step=row.get("recommended_action") or "review_policy_match",
                source_modes=[row.get("source_mode") or row.get("data_source")],
            )
        )
    return cards


def _cards_from_remediation(rows: list[dict[str, Any]]) -> list[RiskCard]:
    return [
        make_risk_card(
            card_type="remediation_preview",
            card_title="Remediation preview",
            severity_level=severity_from_risk_score(_first_score(row.get("risk_score"), row.get("confidence_score"))),
            confidence_score=row.get("confidence_score"),
            risk_score=_first_score(row.get("risk_score"), row.get("confidence_score")),
            summary=row.get("recommended_action") or row.get("recommendation_type") or "Remediation preview",
            explanation_points=row.get("supporting_signals") or [],
            related_policy_references=row.get("policy_references") or [],
            related_flow_references=row.get("flow_references") or [],
            recommended_next_step="operator_review_required" if row.get("approval_required", True) else "monitor",
            source_modes=[row.get("source_mode") or row.get("data_source")],
        )
        for row in rows
        if row.get("recommendation_id") or row.get("recommended_action") or row.get("recommendation_type")
    ]


def _cards_from_incidents(rows: list[dict[str, Any]]) -> list[RiskCard]:
    return [
        make_risk_card(
            card_type="policy_risk" if "policy" in str(row.get("candidate_type") or "") else "topology_risk",
            card_title="Incident candidate",
            severity_level=row.get("severity_level") or severity_from_risk_score(row.get("confidence_score")),
            confidence_score=row.get("confidence_score"),
            risk_score=_first_score(row.get("risk_score"), risk_score_from_severity(row.get("severity_level"))),
            summary=row.get("operator_summary") or row.get("evidence_summary") or "Incident candidate summary",
            explanation_points=[row.get("candidate_type") or "candidate"],
            related_incident_references=[row.get("candidate_id")],
            related_flow_references=row.get("related_flow_references") or [],
            related_policy_references=row.get("related_policy_ids") or [],
            recommended_next_step=row.get("recommended_next_step") or "review_candidate",
            source_modes=[row.get("source_mode") or row.get("data_source")],
        )
        for row in rows
    ]


def _cards_from_guardrails(rows: list[dict[str, Any]]) -> list[RiskCard]:
    cards = []
    for row in rows:
        state = str(row.get("guardrail_state") or row.get("simulation_state") or "").lower()
        if "blocked" not in state and not row.get("safety_blockers"):
            continue
        cards.append(
            make_risk_card(
                card_type="guardrail_block",
                card_title="Guardrail blocked action",
                severity_level="high",
                confidence_score=row.get("confidence_score") or row.get("rollback_confidence") or 0.8,
                risk_score=0.82,
                summary=row.get("recommended_safe_mode") or "Safety guardrail requires operator review",
                explanation_points=row.get("safety_blockers") or row.get("failure_modes") or [],
                related_guardrail_references=[row.get("guardrail_id"), row.get("rollback_simulation_id")],
                recommended_next_step="resolve_safety_blocker",
                source_modes=[row.get("source_mode") or row.get("data_source")],
            )
        )
    return cards


def _cards_from_runtime_health(rows: list[dict[str, Any]]) -> list[RiskCard]:
    cards = []
    for row in rows:
        state = str(row.get("health_state") or row.get("runtime_state") or row.get("state") or "unknown").lower()
        if state in {"ok", "healthy", "ready", "nominal"}:
            continue
        risk_score = _first_score(row.get("risk_score"), 0.62 if state in {"degraded", "blocked", "unavailable"} else 0.3)
        cards.append(
            make_risk_card(
                card_type="runtime_health",
                card_title="Runtime health risk",
                severity_level=severity_from_risk_score(risk_score),
                confidence_score=row.get("confidence_score"),
                risk_score=risk_score,
                summary=f"Runtime health state: {state}",
                explanation_points=row.get("operator_actions") or row.get("advisory_notes") or [],
                recommended_next_step="review_runtime_health",
                source_modes=[row.get("source_mode") or row.get("data_source")],
            )
        )
    return cards


def _cards_from_drift(rows: list[dict[str, Any]]) -> list[RiskCard]:
    cards = []
    for row in rows:
        score = _first_score(row.get("drift_score"), row.get("risk_score"))
        severity = _drift_severity(row, score)
        if severity in {"info", "unknown"} and score <= 0.0:
            continue
        cards.append(
            make_risk_card(
                card_type="drift_risk",
                card_title="Behavioral drift",
                severity_level=severity,
                confidence_score=row.get("confidence_score"),
                risk_score=score or risk_score_from_severity(severity),
                summary=row.get("drift_class") or "Drift metadata summary",
                explanation_points=[row.get("recurrence_state") or "drift observation"],
                related_flow_references=[row.get("current_reference"), row.get("baseline_reference")],
                recommended_next_step="review_drift",
                source_modes=[row.get("source_mode") or row.get("data_source")],
            )
        )
    return cards


def _cards_from_attribution(rows: list[dict[str, Any]]) -> list[RiskCard]:
    cards = []
    for row in rows:
        state = str(row.get("attribution_state") or row.get("state") or "unknown").lower()
        if state in {"attributed", "probable"} and not row.get("conflict_reason"):
            continue
        risk_score = 0.58 if state in {"conflicting", "unattributed", "unknown"} or row.get("conflict_reason") else 0.25
        cards.append(
            make_risk_card(
                card_type="attribution_risk",
                card_title="Attribution review",
                severity_level=severity_from_risk_score(risk_score),
                confidence_score=row.get("attribution_confidence") or row.get("confidence_score"),
                risk_score=risk_score,
                summary=row.get("operator_summary") or "Application attribution requires review",
                explanation_points=[row.get("conflict_reason") or state],
                related_flow_references=[row.get("session_reference"), row.get("observed_entity_reference")],
                recommended_next_step="review_attribution",
                source_modes=[row.get("source_mode") or row.get("data_source")],
            )
        )
    return cards


def _highest_severity(cards: list[RiskCard]) -> str:
    if not cards:
        return "info"
    return max((card.severity_level for card in cards), key=severity_rank)


def _overall_risk_score(cards: list[RiskCard]) -> float:
    if not cards:
        return 0.0
    highest = max(card.risk_score for card in cards)
    average = sum(card.risk_score for card in cards) / len(cards)
    return clamp_score((highest * 0.7) + (average * 0.3))


def _sort_key(card: RiskCard) -> tuple[int, float, float, str]:
    return (-severity_rank(card.severity_level), -clamp_score(card.risk_score), -clamp_score(card.confidence_score), card.card_id)


def _combined_text(card: RiskCard) -> str:
    return " ".join([card.card_type, card.summary, card.recommended_next_step]).lower()


def _dict_rows(values: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [dict(row) for row in values or [] if isinstance(row, dict)]


def _validate_iterable(name: str, values: Any) -> None:
    if values is None:
        return
    try:
        iter(values)
    except TypeError as exc:
        raise RiskDashboardError(f"{name} must be iterable") from exc
    if isinstance(values, (str, bytes)):
        raise RiskDashboardError(f"{name} must be iterable")


def _first_score(*values: Any) -> float:
    for value in values:
        try:
            return clamp_score(float(value))
        except (TypeError, ValueError):
            continue
    return 0.0


def _drift_severity(row: dict[str, Any], score: float) -> str:
    text = str(row.get("drift_severity") or row.get("severity_level") or "").lower()
    if "major" in text:
        return "high"
    if "moderate" in text:
        return "medium"
    if "minor" in text:
        return "low"
    return severity_from_risk_score(score)


def _digest(value: Any) -> str:
    return sha256(str(value).encode("utf-8")).hexdigest()
