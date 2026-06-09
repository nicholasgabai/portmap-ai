from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.intelligence.ai_correlation import AICorrelationSummary
from core_engine.intelligence.dns_analytics import DNSAnalyticsRecord
from core_engine.intelligence.domain_patterns import DomainPatternRecord
from core_engine.intelligence.evidence_chains import EvidenceChainRecord, highest_severity
from core_engine.intelligence.ioc_inventory import IOCInventorySummary
from core_engine.intelligence.ioc_matching import IOCMatchRecord
from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_source_mode,
    sanitize_metadata,
    sanitize_reference,
    sanitize_text,
)
from core_engine.intelligence.scoring_weights import (
    ScoringWeightProfile,
    apply_confidence_bounds,
    default_scoring_weight_profile,
    weight_for_category,
)
from core_engine.intelligence.signature_matching import SignatureMatchRecord


THREAT_SCORING_STATES = {"low", "moderate", "elevated", "high", "degraded", "empty", "unknown"}
SEVERITY_SCORE = {"none": 0.0, "low": 0.25, "medium": 0.5, "high": 0.78, "critical": 1.0, "unknown": 0.0}


@dataclass(frozen=True)
class AdvisoryThreatScoringRecord:
    scoring_id: str
    scoring_state: str
    advisory_score: float
    confidence_score: float
    severity_level: str
    score_breakdown: dict[str, Any]
    supporting_ioc_references: list[str] = field(default_factory=list)
    supporting_dns_references: list[str] = field(default_factory=list)
    supporting_signature_references: list[str] = field(default_factory=list)
    supporting_correlation_references: list[str] = field(default_factory=list)
    supporting_flow_references: list[str] = field(default_factory=list)
    supporting_attribution_references: list[str] = field(default_factory=list)
    supporting_drift_references: list[str] = field(default_factory=list)
    supporting_topology_references: list[str] = field(default_factory=list)
    supporting_runtime_references: list[str] = field(default_factory=list)
    supporting_remediation_references: list[str] = field(default_factory=list)
    supporting_guardrail_references: list[str] = field(default_factory=list)
    explanation_points: list[str] = field(default_factory=list)
    recommended_next_step: str = "continue_monitoring"
    source_modes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "advisory_threat_scoring_record",
            "record_version": IOC_RECORD_VERSION,
            "scoring_id": sanitize_reference(self.scoring_id),
            "scoring_state": normalize_scoring_state(self.scoring_state),
            "advisory_score": clamp_score(self.advisory_score),
            "confidence_score": clamp_score(self.confidence_score),
            "severity_level": sanitize_reference(self.severity_level) or "none",
            "score_breakdown": sanitize_metadata(self.score_breakdown),
            "supporting_ioc_references": _safe_refs(self.supporting_ioc_references),
            "supporting_dns_references": _safe_refs(self.supporting_dns_references),
            "supporting_signature_references": _safe_refs(self.supporting_signature_references),
            "supporting_correlation_references": _safe_refs(self.supporting_correlation_references),
            "supporting_flow_references": _safe_refs(self.supporting_flow_references),
            "supporting_attribution_references": _safe_refs(self.supporting_attribution_references),
            "supporting_drift_references": _safe_refs(self.supporting_drift_references),
            "supporting_topology_references": _safe_refs(self.supporting_topology_references),
            "supporting_runtime_references": _safe_refs(self.supporting_runtime_references),
            "supporting_remediation_references": _safe_refs(self.supporting_remediation_references),
            "supporting_guardrail_references": _safe_refs(self.supporting_guardrail_references),
            "explanation_points": [sanitize_text(point) for point in self.explanation_points],
            "recommended_next_step": sanitize_reference(self.recommended_next_step) or "continue_monitoring",
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def build_advisory_threat_score(
    *,
    weight_profile: ScoringWeightProfile | None = None,
    ioc_inventories: Iterable[IOCInventorySummary] | None = None,
    ioc_matches: Iterable[IOCMatchRecord] | None = None,
    dns_analytics: Iterable[DNSAnalyticsRecord] | DNSAnalyticsRecord | None = None,
    dns_patterns: Iterable[DomainPatternRecord] | None = None,
    signature_matches: Iterable[SignatureMatchRecord] | None = None,
    ai_correlations: Iterable[AICorrelationSummary] | AICorrelationSummary | None = None,
    evidence_chains: Iterable[EvidenceChainRecord] | None = None,
    flow_summaries: Iterable[dict[str, Any]] | None = None,
    attribution_summaries: Iterable[dict[str, Any]] | None = None,
    drift_records: Iterable[dict[str, Any]] | None = None,
    topology_summaries: Iterable[dict[str, Any]] | None = None,
    runtime_health_summaries: Iterable[dict[str, Any]] | None = None,
    remediation_recommendations: Iterable[dict[str, Any]] | None = None,
    guardrail_records: Iterable[dict[str, Any]] | None = None,
) -> AdvisoryThreatScoringRecord:
    profile = weight_profile if isinstance(weight_profile, ScoringWeightProfile) else default_scoring_weight_profile()
    signals: list[dict[str, Any]] = []
    malformed_count = 0
    signals.extend(_ioc_signals(ioc_inventories, ioc_matches))
    signals.extend(_dns_signals(dns_analytics, dns_patterns))
    signals.extend(_signature_signals(signature_matches))
    signals.extend(_correlation_signals(ai_correlations, evidence_chains))
    dict_groups = [
        ("flow", flow_summaries),
        ("attribution", attribution_summaries),
        ("drift", drift_records),
        ("topology", topology_summaries),
        ("runtime", runtime_health_summaries),
        ("remediation", remediation_recommendations),
        ("guardrail", guardrail_records),
    ]
    for category, rows in dict_groups:
        valid, malformed = _dict_signals(category, rows)
        signals.extend(valid)
        malformed_count += malformed
    if malformed_count and not signals:
        return _empty_or_degraded_record(state="degraded", profile=profile, malformed_count=malformed_count)
    if not signals:
        return _empty_or_degraded_record(state="empty", profile=profile, malformed_count=0)

    category_rows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for signal in signals:
        category_rows[signal["category"]].append(signal)
    breakdown = build_score_breakdown(category_rows, profile)
    advisory_score = clamp_score(sum(row["weighted_score"] for row in breakdown.values()) / max(sum(row["applied_weight"] for row in breakdown.values()), 1e-9))
    confidence_values = [signal["confidence_score"] for signal in signals]
    confidence_score = apply_confidence_bounds(sum(confidence_values) / len(confidence_values), profile)
    severity = severity_from_score(advisory_score)
    state = scoring_state_from_score(advisory_score)
    refs = _collect_supporting_refs(signals)
    source_modes = sorted({signal.get("source_mode", "unknown") for signal in signals}) or ["unknown"]
    explanation_points = _explanations(breakdown, state, advisory_score, confidence_score)
    return AdvisoryThreatScoringRecord(
        scoring_id="advisory-score-" + digest({"signals": [signal["reference"] for signal in signals], "score": advisory_score})[:16],
        scoring_state=state,
        advisory_score=advisory_score,
        confidence_score=confidence_score,
        severity_level=severity,
        score_breakdown=breakdown,
        supporting_ioc_references=refs["ioc"],
        supporting_dns_references=refs["dns"],
        supporting_signature_references=refs["signature"],
        supporting_correlation_references=refs["correlation"],
        supporting_flow_references=refs["flow"],
        supporting_attribution_references=refs["attribution"],
        supporting_drift_references=refs["drift"],
        supporting_topology_references=refs["topology"],
        supporting_runtime_references=refs["runtime"],
        supporting_remediation_references=refs["remediation"],
        supporting_guardrail_references=refs["guardrail"],
        explanation_points=explanation_points,
        recommended_next_step=recommended_next_step(state),
        source_modes=source_modes,
        preview_only=True,
        destructive_action=False,
        advisory_notes=[
            "advisory score only; no final verdict, bad-actor label, blocking, or enforcement",
        ],
    )


def build_score_breakdown(category_rows: dict[str, list[dict[str, Any]]], profile: ScoringWeightProfile) -> dict[str, Any]:
    breakdown: dict[str, Any] = {}
    for category in sorted(category_rows):
        rows = category_rows[category]
        category_score = clamp_score(sum(row["signal_score"] for row in rows) / len(rows))
        category_confidence = clamp_score(sum(row["confidence_score"] for row in rows) / len(rows))
        applied_weight = weight_for_category(profile, category) if profile.enabled else 0.0
        breakdown[category] = {
            "signal_count": len(rows),
            "category_score": category_score,
            "confidence_score": category_confidence,
            "applied_weight": applied_weight,
            "weighted_score": clamp_score(category_score * applied_weight),
            "preview_only": True,
            "destructive_action": False,
        }
    return breakdown


def normalize_scoring_state(value: Any) -> str:
    normalized_state = sanitize_reference(value).lower()
    return normalized_state if normalized_state in THREAT_SCORING_STATES else "unknown"


def scoring_state_from_score(score: float) -> str:
    value = clamp_score(score)
    if value >= 0.75:
        return "high"
    if value >= 0.5:
        return "elevated"
    if value >= 0.25:
        return "moderate"
    return "low"


def severity_from_score(score: float) -> str:
    value = clamp_score(score)
    if value >= 0.85:
        return "critical"
    if value >= 0.65:
        return "high"
    if value >= 0.35:
        return "medium"
    if value > 0.0:
        return "low"
    return "none"


def recommended_next_step(state: str) -> str:
    return {
        "high": "review_correlated_advisory_score",
        "elevated": "review_supporting_evidence",
        "moderate": "monitor_and_compare_baseline",
        "low": "continue_monitoring",
        "degraded": "collect_more_metadata",
        "empty": "continue_monitoring",
    }.get(state, "continue_monitoring")


def _ioc_signals(inventories: Iterable[IOCInventorySummary] | None, matches: Iterable[IOCMatchRecord] | None) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for inventory in inventories or []:
        if isinstance(inventory, IOCInventorySummary) and inventory.ioc_count:
            signals.append(_signal("ioc", inventory.inventory_id, clamp_score(inventory.confidence_summary.get("average", 0.4) * 0.55), inventory.confidence_summary.get("average", 0.4), "low", inventory.source_modes[0] if inventory.source_modes else "unknown"))
    for match in matches or []:
        if isinstance(match, IOCMatchRecord):
            score = 0.8 if match.match_state in {"matched", "partial_match", "pattern_match"} else 0.15
            signals.append(_signal("ioc", match.match_id, score, match.confidence_score, "medium", match.source_mode))
    return signals


def _dns_signals(analytics: Iterable[DNSAnalyticsRecord] | DNSAnalyticsRecord | None, patterns: Iterable[DomainPatternRecord] | None) -> list[dict[str, Any]]:
    rows = analytics if isinstance(analytics, list) else [analytics] if isinstance(analytics, DNSAnalyticsRecord) else []
    signals: list[dict[str, Any]] = []
    for dns in rows:
        score = SEVERITY_SCORE.get(dns.highest_severity, 0.0)
        if dns.analytics_state == "review_recommended":
            score = max(score, 0.75)
        elif dns.analytics_state == "noteworthy":
            score = max(score, 0.45)
        signals.append(_signal("dns", dns.dns_analytics_id, score, dns.confidence_score, dns.highest_severity, dns.source_modes[0] if dns.source_modes else "unknown"))
    for pattern in patterns or []:
        if isinstance(pattern, DomainPatternRecord):
            score = 0.75 if pattern.pattern_state == "review_recommended" else 0.45 if pattern.pattern_state == "noteworthy" else 0.2
            signals.append(_signal("dns", pattern.pattern_id, score, pattern.confidence_score, "high" if score >= 0.7 else "medium", pattern.source_mode))
    return signals


def _signature_signals(matches: Iterable[SignatureMatchRecord] | None) -> list[dict[str, Any]]:
    signals: list[dict[str, Any]] = []
    for match in matches or []:
        if isinstance(match, SignatureMatchRecord):
            base = SEVERITY_SCORE.get(match.severity_level, 0.0)
            state_boost = 1.0 if match.match_state == "matched" else 0.65 if match.match_state == "partial_match" else 0.2
            signals.append(_signal("signature", match.signature_match_id, base * state_boost, match.confidence_score, match.severity_level, match.source_mode))
    return signals


def _correlation_signals(correlations: Iterable[AICorrelationSummary] | AICorrelationSummary | None, chains: Iterable[EvidenceChainRecord] | None) -> list[dict[str, Any]]:
    rows = correlations if isinstance(correlations, list) else [correlations] if isinstance(correlations, AICorrelationSummary) else []
    signals: list[dict[str, Any]] = []
    for corr in rows:
        state_score = {"correlated": 0.8, "partially_correlated": 0.55, "weak_signal": 0.3, "degraded": 0.1, "empty": 0.0}.get(corr.correlation_state, 0.0)
        signals.append(_signal("correlation", corr.correlation_id, max(state_score, SEVERITY_SCORE.get(corr.highest_severity, 0.0)), corr.confidence_score, corr.highest_severity, corr.source_modes[0] if corr.source_modes else "unknown"))
    for chain in chains or []:
        if isinstance(chain, EvidenceChainRecord):
            state_score = {"correlated": 0.75, "partially_correlated": 0.5, "weakly_correlated": 0.25, "degraded": 0.1}.get(chain.chain_state, 0.0)
            signals.append(_signal("correlation", chain.chain_id, max(state_score, SEVERITY_SCORE.get(chain.severity_level, 0.0)), chain.confidence_score, chain.severity_level, chain.source_modes[0] if chain.source_modes else "unknown"))
    return signals


def _dict_signals(category: str, rows: Iterable[dict[str, Any]] | None) -> tuple[list[dict[str, Any]], int]:
    if rows is None:
        return [], 0
    items = rows if isinstance(rows, list) else [rows]
    valid: list[dict[str, Any]] = []
    malformed = 0
    for index, row in enumerate(items):
        if not isinstance(row, dict):
            malformed += 1
            continue
        reference = _reference_for_dict(row, category, index)
        confidence = _confidence_for_dict(row)
        score = _score_for_dict(row, category)
        severity = _severity_for_dict(row, score)
        source_mode = normalize_source_mode(row.get("source_mode") or _first(row.get("source_modes")) or "unknown")
        valid.append(_signal(category, reference, score, confidence, severity, source_mode))
    return valid, malformed


def _signal(category: str, reference: str, signal_score: Any, confidence: Any, severity: str, source_mode: str) -> dict[str, Any]:
    return {
        "category": category,
        "reference": sanitize_reference(reference),
        "signal_score": clamp_score(signal_score),
        "confidence_score": clamp_score(confidence),
        "severity_level": severity,
        "source_mode": normalize_source_mode(source_mode),
    }


def _empty_or_degraded_record(*, state: str, profile: ScoringWeightProfile, malformed_count: int) -> AdvisoryThreatScoringRecord:
    return AdvisoryThreatScoringRecord(
        scoring_id="advisory-score-" + digest({"state": state, "malformed": malformed_count})[:16],
        scoring_state=state,
        advisory_score=0.0,
        confidence_score=0.0,
        severity_level="unknown" if state == "degraded" else "none",
        score_breakdown={"malformed_count": malformed_count, "weight_profile_id": profile.weight_profile_id},
        explanation_points=[f"{state} advisory scoring input set"],
        recommended_next_step="collect_more_metadata" if state == "degraded" else "continue_monitoring",
        source_modes=["unknown"],
        preview_only=True,
        destructive_action=False,
        advisory_notes=["advisory score only; no final verdict, bad-actor label, blocking, or enforcement"],
    )


def _score_for_dict(row: dict[str, Any], category: str) -> float:
    explicit = row.get("risk_score") or row.get("overall_risk_score") or row.get("score") or row.get("drift_score")
    if explicit is not None:
        return clamp_score(explicit)
    severity = _severity_for_dict(row, 0.0)
    state = str(row.get("state") or row.get("guardrail_state") or row.get("runtime_state") or row.get("health_state") or "").lower()
    base = SEVERITY_SCORE.get(severity, 0.35)
    if "blocked" in state or "degraded" in state:
        base = max(base, 0.55 if category != "guardrail" else 0.75)
    return clamp_score(base)


def _severity_for_dict(row: dict[str, Any], score: float) -> str:
    severity = str(row.get("severity_level") or row.get("highest_severity") or "").lower()
    if severity in SEVERITY_SCORE:
        return severity
    return severity_from_score(score)


def _confidence_for_dict(row: dict[str, Any]) -> float:
    return clamp_score(row.get("confidence_score") or row.get("metadata_confidence") or 0.5)


def _reference_for_dict(row: dict[str, Any], category: str, index: int) -> str:
    for key in (
        "reference",
        "id",
        "flow_reference",
        "session_reference",
        "attribution_id",
        "drift_id",
        "relationship_reference",
        "runtime_id",
        "recommendation_id",
        "guardrail_id",
    ):
        if row.get(key):
            return str(row[key])
    return f"{category}-{index}"


def _collect_supporting_refs(signals: list[dict[str, Any]]) -> dict[str, list[str]]:
    refs = {key: [] for key in ("ioc", "dns", "signature", "correlation", "flow", "attribution", "drift", "topology", "runtime", "remediation", "guardrail")}
    for signal in signals:
        refs.setdefault(signal["category"], []).append(signal["reference"])
    return {key: sorted({ref for ref in values if ref})[:64] for key, values in refs.items()}


def _explanations(breakdown: dict[str, Any], state: str, advisory_score: float, confidence_score: float) -> list[str]:
    rows = [
        f"{category} contributed {payload['weighted_score']} weighted advisory score from {payload['signal_count']} signals"
        for category, payload in sorted(breakdown.items())
    ]
    rows.append(f"Advisory scoring state is {state} with score {advisory_score} and confidence {confidence_score}")
    return rows


def _first(value: Any) -> Any:
    if isinstance(value, list) and value:
        return value[0]
    return None


def _safe_refs(values: list[str]) -> list[str]:
    return [sanitize_reference(value) for value in values if sanitize_reference(value)][:64]
