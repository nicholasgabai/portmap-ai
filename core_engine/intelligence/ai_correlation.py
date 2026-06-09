from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.intelligence.dns_analytics import DNSAnalyticsRecord
from core_engine.intelligence.domain_patterns import DomainPatternRecord
from core_engine.intelligence.evidence_chains import (
    EvidenceChainRecord,
    build_evidence_chain,
    chain_state_from_chains,
    highest_severity,
)
from core_engine.intelligence.ioc_inventory import IOCInventorySummary
from core_engine.intelligence.ioc_matching import IOCMatchRecord
from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_source_mode,
    now_timestamp,
    sanitize_metadata,
    sanitize_reference,
    sanitize_text,
)
from core_engine.intelligence.signature_matching import SignatureMatchRecord


AI_CORRELATION_STATES = {"correlated", "partially_correlated", "weak_signal", "empty", "degraded", "unknown"}


@dataclass(frozen=True)
class AICorrelationSummary:
    correlation_id: str
    generated_at: str
    correlation_state: str
    chain_count: int
    highest_severity: str
    confidence_score: float
    evidence_chain_summary: dict[str, Any]
    recommendation_summary: dict[str, Any]
    risk_summary: dict[str, Any]
    explanation_points: list[str] = field(default_factory=list)
    source_modes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)
    evidence_chains: list[EvidenceChainRecord] = field(default_factory=list, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "ai_correlation_summary",
            "record_version": IOC_RECORD_VERSION,
            "correlation_id": sanitize_reference(self.correlation_id),
            "generated_at": str(self.generated_at or ""),
            "correlation_state": normalize_ai_correlation_state(self.correlation_state),
            "chain_count": max(0, int(self.chain_count or 0)),
            "highest_severity": sanitize_reference(self.highest_severity) or "none",
            "confidence_score": clamp_score(self.confidence_score),
            "evidence_chain_summary": sanitize_metadata(self.evidence_chain_summary),
            "recommendation_summary": sanitize_metadata(self.recommendation_summary),
            "risk_summary": sanitize_metadata(self.risk_summary),
            "explanation_points": [sanitize_text(point) for point in self.explanation_points],
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def build_ai_correlation_summary(
    *,
    ioc_inventories: Iterable[IOCInventorySummary] | None = None,
    ioc_matches: Iterable[IOCMatchRecord] | None = None,
    dns_analytics: Iterable[DNSAnalyticsRecord] | DNSAnalyticsRecord | None = None,
    dns_patterns: Iterable[DomainPatternRecord] | None = None,
    signature_matches: Iterable[SignatureMatchRecord] | None = None,
    flow_summaries: Iterable[dict[str, Any]] | None = None,
    attribution_summaries: Iterable[dict[str, Any]] | None = None,
    topology_summaries: Iterable[dict[str, Any]] | None = None,
    drift_records: Iterable[dict[str, Any]] | None = None,
    policy_evaluations: Iterable[dict[str, Any]] | None = None,
    remediation_recommendations: Iterable[dict[str, Any]] | None = None,
    guardrail_records: Iterable[dict[str, Any]] | None = None,
    risk_dashboard_summaries: Iterable[dict[str, Any]] | None = None,
    evidence_chains: Iterable[EvidenceChainRecord] | None = None,
    generated_at: str | None = None,
) -> AICorrelationSummary:
    timestamp = generated_at or now_timestamp()
    chains = [chain for chain in evidence_chains or [] if isinstance(chain, EvidenceChainRecord)]
    malformed_count = 0
    if evidence_chains is None:
        chains, malformed_count = _build_default_chains(
            ioc_inventories=ioc_inventories,
            ioc_matches=ioc_matches,
            dns_analytics=dns_analytics,
            dns_patterns=dns_patterns,
            signature_matches=signature_matches,
            flow_summaries=flow_summaries,
            attribution_summaries=attribution_summaries,
            topology_summaries=topology_summaries,
            drift_records=drift_records,
            policy_evaluations=policy_evaluations,
            remediation_recommendations=remediation_recommendations,
            guardrail_records=guardrail_records,
            risk_dashboard_summaries=risk_dashboard_summaries,
        )
    if malformed_count and not chains:
        state = "degraded"
    else:
        state = normalize_ai_correlation_state(chain_state_from_chains(chains))
    confidence_values = [chain.confidence_score for chain in chains]
    confidence_score = clamp_score(sum(confidence_values) / len(confidence_values) if confidence_values else 0.0)
    severities = [chain.severity_level for chain in chains]
    source_modes = sorted({mode for chain in chains for mode in chain.source_modes}) or ["unknown"]
    evidence_summary = summarize_evidence_chains(chains)
    recommendation_summary = build_recommendation_summary(remediation_recommendations or [], guardrail_records or [], chains)
    risk_summary = build_risk_summary(risk_dashboard_summaries or [], chains)
    return AICorrelationSummary(
        correlation_id="ai-correlation-" + digest(
            {
                "generated_at": timestamp,
                "chains": [chain.chain_id for chain in chains],
                "state": state,
            }
        )[:16],
        generated_at=timestamp,
        correlation_state=state,
        chain_count=len(chains),
        highest_severity=highest_severity(severities),
        confidence_score=confidence_score,
        evidence_chain_summary=evidence_summary,
        recommendation_summary=recommendation_summary,
        risk_summary=risk_summary,
        explanation_points=_explanation_points(chains, state),
        source_modes=source_modes,
        preview_only=True,
        destructive_action=False,
        advisory_notes=[
            "deterministic local AI-correlation summary; no external model call, verdict, blocking, or enforcement",
        ],
        evidence_chains=chains,
    )


def empty_ai_correlation_summary(*, generated_at: str | None = None) -> AICorrelationSummary:
    return build_ai_correlation_summary(generated_at=generated_at)


def normalize_ai_correlation_state(value: Any) -> str:
    token = sanitize_reference(value).lower()
    return token if token in AI_CORRELATION_STATES else "unknown"


def summarize_evidence_chains(chains: Iterable[EvidenceChainRecord]) -> dict[str, Any]:
    rows = [chain for chain in chains or [] if isinstance(chain, EvidenceChainRecord)]
    type_counts = Counter(chain.chain_type for chain in rows)
    state_counts = Counter(chain.chain_state for chain in rows)
    return {
        "chain_count": len(rows),
        "chain_references": [sanitize_reference(chain.chain_id) for chain in rows[:32]],
        "type_counts": {key: int(type_counts[key]) for key in sorted(type_counts)},
        "state_counts": {key: int(state_counts[key]) for key in sorted(state_counts)},
        "preview_only": True,
        "destructive_action": False,
    }


def build_recommendation_summary(
    remediation_recommendations: Iterable[dict[str, Any]],
    guardrail_records: Iterable[dict[str, Any]],
    chains: Iterable[EvidenceChainRecord],
) -> dict[str, Any]:
    recommendations = [row for row in remediation_recommendations or [] if isinstance(row, dict)]
    guardrails = [row for row in guardrail_records or [] if isinstance(row, dict)]
    return {
        "recommendation_count": len(recommendations),
        "guardrail_count": len(guardrails),
        "blocked_count": sum(1 for row in guardrails if str(row.get("guardrail_state")) == "blocked"),
        "correlated_chain_count": sum(1 for chain in chains or [] if chain.chain_state == "correlated"),
        "recommended_next_step": "review_correlated_metadata" if recommendations or guardrails else "continue_monitoring",
        "preview_only": True,
        "destructive_action": False,
    }


def build_risk_summary(risk_dashboard_summaries: Iterable[dict[str, Any]], chains: Iterable[EvidenceChainRecord]) -> dict[str, Any]:
    dashboards = [row for row in risk_dashboard_summaries or [] if isinstance(row, dict)]
    risk_values = [float(row.get("overall_risk_score", 0.0)) for row in dashboards if _is_number(row.get("overall_risk_score"))]
    chain_severity = highest_severity(chain.severity_level for chain in chains or [])
    return {
        "risk_dashboard_count": len(dashboards),
        "average_risk_score": clamp_score(sum(risk_values) / len(risk_values) if risk_values else 0.0),
        "highest_chain_severity": chain_severity,
        "risk_state": "review" if chain_severity in {"high", "critical"} or any(value >= 0.7 for value in risk_values) else "monitor",
        "preview_only": True,
        "destructive_action": False,
    }


def _build_default_chains(**groups: Any) -> tuple[list[EvidenceChainRecord], int]:
    malformed_count = 0
    chains: list[EvidenceChainRecord] = []
    ioc_inventory_rows = _typed_list(groups.get("ioc_inventories"), IOCInventorySummary)
    ioc_match_rows = _typed_list(groups.get("ioc_matches"), IOCMatchRecord)
    dns_rows = _normalize_dns_analytics(groups.get("dns_analytics"))
    dns_pattern_rows = _typed_list(groups.get("dns_patterns"), DomainPatternRecord)
    signature_rows = _typed_list(groups.get("signature_matches"), SignatureMatchRecord)
    flow_rows, flow_malformed = _dict_list(groups.get("flow_summaries"))
    attribution_rows, attribution_malformed = _dict_list(groups.get("attribution_summaries"))
    topology_rows, topology_malformed = _dict_list(groups.get("topology_summaries"))
    drift_rows, drift_malformed = _dict_list(groups.get("drift_records"))
    policy_rows, policy_malformed = _dict_list(groups.get("policy_evaluations"))
    remediation_rows, remediation_malformed = _dict_list(groups.get("remediation_recommendations"))
    guardrail_rows, guardrail_malformed = _dict_list(groups.get("guardrail_records"))
    risk_rows, risk_malformed = _dict_list(groups.get("risk_dashboard_summaries"))
    malformed_count += sum(
        [
            flow_malformed,
            attribution_malformed,
            topology_malformed,
            drift_malformed,
            policy_malformed,
            remediation_malformed,
            guardrail_malformed,
            risk_malformed,
        ]
    )

    if ioc_inventory_rows or ioc_match_rows or dns_rows or dns_pattern_rows or signature_rows:
        chains.append(
            build_evidence_chain(
                chain_type="ioc_dns_signature",
                evidence_items=[*ioc_inventory_rows, *ioc_match_rows, *dns_rows, *dns_pattern_rows, *signature_rows],
                explanation_summary="IOC, DNS, and signature metadata were correlated locally",
            )
        )
    if flow_rows or attribution_rows or drift_rows:
        chains.append(
            build_evidence_chain(
                chain_type="flow_attribution_drift",
                evidence_items=[*flow_rows, *attribution_rows, *drift_rows],
                explanation_summary="Flow, attribution, and drift metadata were correlated locally",
            )
        )
    if topology_rows or policy_rows or risk_rows:
        chains.append(
            build_evidence_chain(
                chain_type="topology_policy_risk",
                evidence_items=[*topology_rows, *policy_rows, *risk_rows],
                explanation_summary="Topology, policy, and risk metadata were correlated locally",
            )
        )
    if remediation_rows or guardrail_rows:
        chains.append(
            build_evidence_chain(
                chain_type="remediation_guardrail",
                evidence_items=[*remediation_rows, *guardrail_rows],
                explanation_summary="Remediation preview and guardrail metadata were correlated locally",
            )
        )
    if len(chains) >= 2:
        chains.append(
            build_evidence_chain(
                chain_type="composite",
                evidence_items=[item for chain in chains for item in chain.evidence_items],
                explanation_summary="Multiple local metadata chain types were correlated into a composite summary",
            )
        )
    return chains, malformed_count


def _typed_list(value: Any, expected_type: type) -> list[Any]:
    if value is None:
        return []
    rows = value if isinstance(value, list) else [value]
    return [row for row in rows if isinstance(row, expected_type)]


def _dict_list(value: Any) -> tuple[list[dict[str, Any]], int]:
    if value is None:
        return [], 0
    rows = value if isinstance(value, list) else [value]
    valid = [row for row in rows if isinstance(row, dict)]
    return valid, len(rows) - len(valid)


def _normalize_dns_analytics(value: Any) -> list[DNSAnalyticsRecord]:
    if value is None:
        return []
    rows = value if isinstance(value, list) else [value]
    return [row for row in rows if isinstance(row, DNSAnalyticsRecord)]


def _explanation_points(chains: list[EvidenceChainRecord], state: str) -> list[str]:
    if not chains:
        return ["No local metadata evidence chains were available for correlation"]
    return [
        f"{chain.chain_type} returned {chain.chain_state} with {len(chain.evidence_items)} evidence items"
        for chain in chains[:8]
    ] + [f"Overall local correlation state is {state}"]


def _is_number(value: Any) -> bool:
    try:
        float(value)
        return True
    except Exception:
        return False
