from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.intelligence.dns_analytics import DNSAnalyticsRecord
from core_engine.intelligence.domain_patterns import DomainPatternRecord
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
from core_engine.intelligence.signature_matching import SignatureMatchRecord
from core_engine.intelligence.signature_records import normalize_severity


EVIDENCE_CHAIN_TYPES = {
    "ioc_dns_signature",
    "flow_attribution_drift",
    "topology_policy_risk",
    "remediation_guardrail",
    "composite",
    "unknown",
}
EVIDENCE_CHAIN_STATES = {
    "correlated",
    "partially_correlated",
    "weakly_correlated",
    "not_correlated",
    "degraded",
    "unknown",
}
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": -1}


@dataclass(frozen=True)
class EvidenceChainRecord:
    chain_id: str
    chain_type: str
    chain_state: str
    confidence_score: float
    severity_level: str
    evidence_items: list[dict[str, Any]] = field(default_factory=list)
    related_ioc_references: list[str] = field(default_factory=list)
    related_dns_references: list[str] = field(default_factory=list)
    related_signature_references: list[str] = field(default_factory=list)
    related_flow_references: list[str] = field(default_factory=list)
    related_attribution_references: list[str] = field(default_factory=list)
    related_topology_references: list[str] = field(default_factory=list)
    related_drift_references: list[str] = field(default_factory=list)
    related_policy_references: list[str] = field(default_factory=list)
    explanation_summary: str = ""
    source_modes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "evidence_chain_record",
            "record_version": IOC_RECORD_VERSION,
            "chain_id": sanitize_reference(self.chain_id),
            "chain_type": normalize_chain_type(self.chain_type),
            "chain_state": normalize_chain_state(self.chain_state),
            "confidence_score": clamp_score(self.confidence_score),
            "severity_level": normalize_severity(self.severity_level),
            "evidence_items": [sanitize_metadata(item) for item in self.evidence_items[:128]],
            "related_ioc_references": _safe_refs(self.related_ioc_references),
            "related_dns_references": _safe_refs(self.related_dns_references),
            "related_signature_references": _safe_refs(self.related_signature_references),
            "related_flow_references": _safe_refs(self.related_flow_references),
            "related_attribution_references": _safe_refs(self.related_attribution_references),
            "related_topology_references": _safe_refs(self.related_topology_references),
            "related_drift_references": _safe_refs(self.related_drift_references),
            "related_policy_references": _safe_refs(self.related_policy_references),
            "explanation_summary": sanitize_text(self.explanation_summary),
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def build_evidence_chain(
    *,
    chain_type: str = "unknown",
    evidence_items: Iterable[Any] | None = None,
    explanation_summary: str | None = None,
    source_modes: Iterable[str] | None = None,
    advisory_notes: list[str] | None = None,
) -> EvidenceChainRecord:
    items = [_normalize_evidence_item(item) for item in evidence_items or []]
    items = [item for item in items if item]
    refs = _collect_references(items)
    confidence_values = [float(item["confidence_score"]) for item in items if isinstance(item.get("confidence_score"), (int, float))]
    severity = highest_severity([str(item.get("severity_level") or "none") for item in items])
    confidence = clamp_score(sum(confidence_values) / len(confidence_values) if confidence_values else 0.0)
    state = _state_for_evidence_count(len(items), malformed_count=0)
    normalized_type = normalize_chain_type(chain_type)
    chain_id = "evidence-chain-" + digest(
        {
            "chain_type": normalized_type,
            "items": [item.get("reference") for item in items],
            "state": state,
        }
    )[:16]
    modes = set(source_modes or [])
    for item in items:
        modes.add(str(item.get("source_mode") or "unknown"))
    notes = list(advisory_notes or [])
    notes.append("deterministic local evidence chain; no external AI call, verdict, blocking, or enforcement")
    return EvidenceChainRecord(
        chain_id=chain_id,
        chain_type=normalized_type,
        chain_state=state,
        confidence_score=confidence,
        severity_level=severity,
        evidence_items=items,
        related_ioc_references=refs["ioc"],
        related_dns_references=refs["dns"],
        related_signature_references=refs["signature"],
        related_flow_references=refs["flow"],
        related_attribution_references=refs["attribution"],
        related_topology_references=refs["topology"],
        related_drift_references=refs["drift"],
        related_policy_references=refs["policy"],
        explanation_summary=explanation_summary or _default_explanation(normalized_type, len(items), state),
        source_modes=sorted(modes) or ["unknown"],
        preview_only=True,
        destructive_action=False,
        advisory_notes=notes,
    )


def degraded_evidence_chain(*, chain_type: str = "unknown", reason: str = "malformed correlation input") -> EvidenceChainRecord:
    normalized_type = normalize_chain_type(chain_type)
    return EvidenceChainRecord(
        chain_id="evidence-chain-degraded-" + digest({"chain_type": normalized_type, "reason": reason})[:16],
        chain_type=normalized_type,
        chain_state="degraded",
        confidence_score=0.0,
        severity_level="unknown",
        evidence_items=[],
        explanation_summary=reason,
        source_modes=["unknown"],
        preview_only=True,
        destructive_action=False,
        advisory_notes=["malformed input was isolated without external calls or enforcement"],
    )


def normalize_chain_type(value: Any) -> str:
    token = sanitize_reference(value).lower()
    return token if token in EVIDENCE_CHAIN_TYPES else "unknown"


def normalize_chain_state(value: Any) -> str:
    token = sanitize_reference(value).lower()
    return token if token in EVIDENCE_CHAIN_STATES else "unknown"


def highest_severity(values: Iterable[str]) -> str:
    rows = [normalize_severity(value) for value in values or []]
    if not rows:
        return "none"
    return max(rows, key=lambda value: SEVERITY_RANK.get(value, -1))


def chain_state_from_chains(chains: Iterable[EvidenceChainRecord]) -> str:
    rows = [chain for chain in chains or [] if isinstance(chain, EvidenceChainRecord)]
    if not rows:
        return "empty"
    states = {chain.chain_state for chain in rows}
    if "correlated" in states:
        return "correlated"
    if "partially_correlated" in states:
        return "partially_correlated"
    if "weakly_correlated" in states:
        return "weak_signal"
    if "degraded" in states:
        return "degraded"
    return "empty"


def _normalize_evidence_item(item: Any) -> dict[str, Any]:
    if isinstance(item, IOCMatchRecord):
        return {
            "evidence_type": "ioc_match",
            "reference": item.match_id,
            "related_reference": item.ioc_id,
            "category": "ioc",
            "confidence_score": clamp_score(item.confidence_score),
            "severity_level": "medium" if item.match_state in {"matched", "partial_match", "pattern_match"} else "low",
            "source_mode": item.source_mode,
            "summary": "IOC match metadata",
        }
    if isinstance(item, IOCInventorySummary):
        return {
            "evidence_type": "ioc_inventory",
            "reference": item.inventory_id,
            "category": "ioc",
            "confidence_score": clamp_score(item.confidence_summary.get("average", 0.0)),
            "severity_level": "low" if item.ioc_count else "none",
            "source_mode": (item.source_modes[0] if item.source_modes else "unknown"),
            "summary": "bounded IOC inventory metadata",
        }
    if isinstance(item, DNSAnalyticsRecord):
        return {
            "evidence_type": "dns_analytics",
            "reference": item.dns_analytics_id,
            "category": "dns",
            "confidence_score": clamp_score(item.confidence_score),
            "severity_level": item.highest_severity,
            "source_mode": (item.source_modes[0] if item.source_modes else "unknown"),
            "summary": "DNS analytics metadata",
        }
    if isinstance(item, DomainPatternRecord):
        return {
            "evidence_type": "domain_pattern",
            "reference": item.pattern_id,
            "category": "dns",
            "confidence_score": clamp_score(item.confidence_score),
            "severity_level": "high" if item.pattern_state == "review_recommended" else "medium",
            "source_mode": item.source_mode,
            "summary": "domain pattern metadata",
        }
    if isinstance(item, SignatureMatchRecord):
        return {
            "evidence_type": "signature_match",
            "reference": item.signature_match_id,
            "related_reference": item.signature_id,
            "category": "signature",
            "confidence_score": clamp_score(item.confidence_score),
            "severity_level": item.severity_level,
            "source_mode": item.source_mode,
            "summary": "signature match metadata",
        }
    if isinstance(item, dict):
        category = _category_for_dict(item)
        return {
            "evidence_type": sanitize_reference(item.get("record_type") or item.get("type") or category),
            "reference": _reference_for_dict(item, category),
            "category": category,
            "confidence_score": _confidence_for_dict(item),
            "severity_level": normalize_severity(item.get("severity_level") or item.get("highest_severity") or item.get("risk_state") or "low"),
            "source_mode": normalize_source_mode(item.get("source_mode") or _first_source_mode(item.get("source_modes"))),
            "summary": sanitize_text(item.get("summary") or item.get("operator_summary") or item.get("recommended_next_step") or "metadata signal"),
        }
    return {}


def _collect_references(items: list[dict[str, Any]]) -> dict[str, list[str]]:
    refs = {key: [] for key in ("ioc", "dns", "signature", "flow", "attribution", "topology", "drift", "policy")}
    for item in items:
        category = str(item.get("category") or "unknown")
        reference = str(item.get("reference") or "")
        related = str(item.get("related_reference") or "")
        if category in refs and reference:
            refs[category].append(reference)
        if category == "ioc" and related:
            refs["ioc"].append(related)
        if category == "signature" and related:
            refs["signature"].append(related)
    return {key: sorted({sanitize_reference(ref) for ref in values if sanitize_reference(ref)}) for key, values in refs.items()}


def _category_for_dict(item: dict[str, Any]) -> str:
    record_type = str(item.get("record_type") or item.get("category") or item.get("type") or "").lower()
    if "ioc" in record_type:
        return "ioc"
    if "dns" in record_type or "domain" in record_type:
        return "dns"
    if "signature" in record_type:
        return "signature"
    if "flow" in record_type:
        return "flow"
    if "attribution" in record_type:
        return "attribution"
    if "topology" in record_type or "relationship" in record_type:
        return "topology"
    if "drift" in record_type:
        return "drift"
    if "policy" in record_type:
        return "policy"
    if "remediation" in record_type or "guardrail" in record_type:
        return "policy"
    return "unknown"


def _reference_for_dict(item: dict[str, Any], category: str) -> str:
    for key in (
        "reference",
        "id",
        "match_id",
        "signature_match_id",
        "dns_analytics_id",
        "pattern_id",
        "flow_reference",
        "session_reference",
        "attribution_id",
        "relationship_reference",
        "drift_id",
        "policy_id",
        "evaluation_id",
        "recommendation_id",
        "guardrail_id",
        "card_id",
    ):
        if item.get(key):
            return str(item[key])
    return f"{category}-{digest(item)[:12]}"


def _confidence_for_dict(item: dict[str, Any]) -> float:
    return clamp_score(item.get("confidence_score") or item.get("risk_score") or item.get("overall_risk_score") or 0.5)


def _first_source_mode(value: Any) -> str:
    if isinstance(value, list) and value:
        return str(value[0])
    return "unknown"


def _state_for_evidence_count(count: int, malformed_count: int = 0) -> str:
    if malformed_count:
        return "degraded"
    if count >= 3:
        return "correlated"
    if count == 2:
        return "partially_correlated"
    if count == 1:
        return "weakly_correlated"
    return "not_correlated"


def _default_explanation(chain_type: str, count: int, state: str) -> str:
    return f"{chain_type} chain evaluated {count} local metadata signals and returned {state}"


def _safe_refs(values: list[str]) -> list[str]:
    return [sanitize_reference(value) for value in values if sanitize_reference(value)][:64]
