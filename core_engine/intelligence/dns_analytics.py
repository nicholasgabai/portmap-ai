from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.intelligence.domain_patterns import (
    DomainPatternRecord,
    analyze_domain_patterns,
    normalize_domain,
)
from core_engine.intelligence.ioc_inventory import IOCInventorySummary
from core_engine.intelligence.ioc_matching import IOCMatchRecord, match_iocs
from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_ioc_source_category,
    normalize_source_mode,
    now_timestamp,
    sanitize_metadata,
    sanitize_reference,
    sanitize_text,
)


DNS_ANALYTICS_STATES = {"normal", "noteworthy", "review_recommended", "degraded", "empty", "unknown"}
DNS_REVIEW_PATTERN_STATES = {"review_recommended", "degraded"}
DNS_MATCH_STATES = {"matched", "partial_match", "pattern_match"}


@dataclass(frozen=True)
class DNSAnalyticsRecord:
    dns_analytics_id: str
    analytics_state: str
    query_count: int
    unique_domain_count: int
    resolver_count: int
    pattern_count: int
    ioc_match_count: int
    highest_severity: str
    confidence_score: float
    resolver_behavior_summary: dict[str, Any]
    domain_pattern_summary: dict[str, Any]
    ioc_match_summary: dict[str, Any]
    recommended_next_step: str
    source_modes: list[str] = field(default_factory=list)
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "dns_analytics_record",
            "record_version": IOC_RECORD_VERSION,
            "dns_analytics_id": sanitize_reference(self.dns_analytics_id),
            "analytics_state": normalize_dns_analytics_state(self.analytics_state),
            "query_count": max(0, int(self.query_count or 0)),
            "unique_domain_count": max(0, int(self.unique_domain_count or 0)),
            "resolver_count": max(0, int(self.resolver_count or 0)),
            "pattern_count": max(0, int(self.pattern_count or 0)),
            "ioc_match_count": max(0, int(self.ioc_match_count or 0)),
            "highest_severity": sanitize_reference(self.highest_severity) or "none",
            "confidence_score": clamp_score(self.confidence_score),
            "resolver_behavior_summary": sanitize_metadata(self.resolver_behavior_summary),
            "domain_pattern_summary": sanitize_metadata(self.domain_pattern_summary),
            "ioc_match_summary": sanitize_metadata(self.ioc_match_summary),
            "recommended_next_step": sanitize_reference(self.recommended_next_step) or "continue_monitoring",
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def build_dns_analytics(
    dns_observations: Iterable[dict[str, Any]] | None = None,
    *,
    ioc_inventory: IOCInventorySummary | None = None,
    ioc_matches: Iterable[IOCMatchRecord] | None = None,
    domain_patterns: Iterable[DomainPatternRecord] | None = None,
    destination_summaries: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
) -> DNSAnalyticsRecord:
    timestamp = generated_at or now_timestamp()
    observations = [row for row in dns_observations or []]
    malformed_count = sum(1 for row in observations if not isinstance(row, dict))
    valid_observations = [row for row in observations if isinstance(row, dict)]
    patterns = [row for row in domain_patterns or [] if isinstance(row, DomainPatternRecord)]
    if domain_patterns is None and valid_observations:
        patterns = analyze_domain_patterns(valid_observations, generated_at=timestamp)

    matches = [row for row in ioc_matches or [] if isinstance(row, IOCMatchRecord)]
    if ioc_inventory is not None and not matches and valid_observations:
        matches = match_iocs(ioc_inventory.iocs, _dns_candidates(valid_observations))

    resolver_summary = build_resolver_behavior_summary(valid_observations, destination_summaries or [])
    domain_summary = summarize_domain_patterns(patterns)
    match_summary = summarize_ioc_matches(matches)
    query_count = len(valid_observations)
    unique_domains = {normalize_domain(_domain_from_observation(row)) for row in valid_observations}
    unique_domains = {domain for domain in unique_domains if domain}
    source_modes = sorted(
        {
            normalize_source_mode(row.get("source_mode"))
            for row in valid_observations
            if isinstance(row, dict)
        }
        | {pattern.source_mode for pattern in patterns}
        | {match.source_mode for match in matches}
    ) or ["unknown"]
    matched_count = int(match_summary["matched_count"])
    review_patterns = int(domain_summary["review_recommended_count"])
    noteworthy_patterns = int(domain_summary["noteworthy_count"])
    confidence_values = [pattern.confidence_score for pattern in patterns] + [
        match.confidence_score for match in matches if match.match_state in DNS_MATCH_STATES
    ]
    confidence_score = clamp_score(sum(confidence_values) / len(confidence_values) if confidence_values else (0.4 if query_count else 0.0))
    highest_severity = _highest_severity(
        matched_count=matched_count,
        review_patterns=review_patterns,
        noteworthy_patterns=noteworthy_patterns,
        malformed_count=malformed_count,
        resolver_change=bool(resolver_summary.get("resolver_change_detected")),
    )
    analytics_state = _analytics_state(
        query_count=query_count,
        malformed_count=malformed_count,
        matched_count=matched_count,
        review_patterns=review_patterns,
        noteworthy_patterns=noteworthy_patterns,
        resolver_change=bool(resolver_summary.get("resolver_change_detected")),
    )
    next_step = _recommended_next_step(analytics_state, matched_count=matched_count, review_patterns=review_patterns)
    return DNSAnalyticsRecord(
        dns_analytics_id="dns-analytics-" + digest(
            {
                "generated_at": timestamp,
                "query_count": query_count,
                "patterns": [pattern.pattern_id for pattern in patterns],
                "matches": [match.match_id for match in matches],
            }
        )[:16],
        analytics_state=analytics_state,
        query_count=query_count,
        unique_domain_count=len(unique_domains),
        resolver_count=int(resolver_summary["resolver_count"]),
        pattern_count=len(patterns),
        ioc_match_count=matched_count,
        highest_severity=highest_severity,
        confidence_score=confidence_score,
        resolver_behavior_summary=resolver_summary,
        domain_pattern_summary=domain_summary,
        ioc_match_summary=match_summary,
        recommended_next_step=next_step,
        source_modes=source_modes,
        preview_only=True,
        destructive_action=False,
        advisory_notes=[
            "DNS analytics are metadata-only and advisory",
            "No DNS lookups, external threat feeds, blocking, verdicts, or enforcement were performed",
        ],
    )


def empty_dns_analytics(*, generated_at: str | None = None) -> DNSAnalyticsRecord:
    return build_dns_analytics([], generated_at=generated_at)


def build_resolver_behavior_summary(
    dns_observations: Iterable[dict[str, Any]] | None = None,
    destination_summaries: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    resolver_refs: set[str] = set()
    for row in dns_observations or []:
        if not isinstance(row, dict):
            continue
        resolver_value = row.get("resolver_reference") or row.get("resolver") or row.get("resolver_id")
        resolver_ref = _resolver_reference(resolver_value)
        if resolver_ref:
            resolver_refs.add(resolver_ref)
    for row in destination_summaries or []:
        if not isinstance(row, dict):
            continue
        resolver_value = row.get("resolver_reference") or row.get("resolver_id")
        resolver_ref = _resolver_reference(resolver_value)
        if resolver_ref:
            resolver_refs.add(resolver_ref)
    resolver_count = len(resolver_refs)
    return {
        "resolver_count": resolver_count,
        "resolver_references": sorted(resolver_refs)[:16],
        "resolver_change_detected": resolver_count > 1,
        "behavior_state": "noteworthy" if resolver_count > 1 else ("observed" if resolver_count == 1 else "unknown"),
        "raw_resolvers_exported": False,
    }


def summarize_domain_patterns(patterns: Iterable[DomainPatternRecord] | None = None) -> dict[str, Any]:
    rows = [row for row in patterns or [] if isinstance(row, DomainPatternRecord)]
    type_counts = Counter(row.pattern_type for row in rows)
    state_counts = Counter(row.pattern_state for row in rows)
    return {
        "pattern_count": len(rows),
        "type_counts": {key: int(type_counts[key]) for key in sorted(type_counts)},
        "state_counts": {key: int(state_counts[key]) for key in sorted(state_counts)},
        "review_recommended_count": int(sum(state_counts.get(state, 0) for state in DNS_REVIEW_PATTERN_STATES)),
        "noteworthy_count": int(state_counts.get("noteworthy", 0)),
        "pattern_references": [sanitize_reference(row.pattern_id) for row in rows[:16]],
        "raw_domains_exported": False,
    }


def summarize_ioc_matches(matches: Iterable[IOCMatchRecord] | None = None) -> dict[str, Any]:
    rows = [row for row in matches or [] if isinstance(row, IOCMatchRecord)]
    state_counts = Counter(row.match_state for row in rows)
    source_counts = Counter(normalize_ioc_source_category(row.source_category) for row in rows)
    matched_count = int(sum(state_counts.get(state, 0) for state in DNS_MATCH_STATES))
    return {
        "match_count": len(rows),
        "matched_count": matched_count,
        "state_counts": {key: int(state_counts[key]) for key in sorted(state_counts)},
        "source_category_counts": {key: int(source_counts[key]) for key in sorted(source_counts)},
        "match_references": [sanitize_reference(row.match_id) for row in rows[:16]],
        "external_lookup_performed": False,
    }


def normalize_dns_analytics_state(value: Any) -> str:
    token = sanitize_reference(value).lower()
    return token if token in DNS_ANALYTICS_STATES else "unknown"


def _dns_candidates(observations: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for index, row in enumerate(observations or []):
        domain = normalize_domain(_domain_from_observation(row))
        if not domain:
            continue
        candidates.append(
            {
                "value": domain,
                "ioc_type": "domain",
                "candidate_reference": row.get("candidate_reference") or f"dns-candidate-{index}",
                "source_category": "dns",
                "source_mode": row.get("source_mode") or "unknown",
            }
        )
    return candidates


def _domain_from_observation(row: dict[str, Any]) -> Any:
    if not isinstance(row, dict):
        return None
    return row.get("domain") or row.get("query_name") or row.get("fqdn") or row.get("dns_name") or row.get("value")


def _resolver_reference(value: Any) -> str:
    token = sanitize_reference(value)
    return "resolver-" + digest(token)[:12] if token else ""


def _highest_severity(
    *,
    matched_count: int,
    review_patterns: int,
    noteworthy_patterns: int,
    malformed_count: int,
    resolver_change: bool,
) -> str:
    if matched_count or review_patterns:
        return "high"
    if noteworthy_patterns or resolver_change:
        return "medium"
    if malformed_count:
        return "low"
    return "none"


def _analytics_state(
    *,
    query_count: int,
    malformed_count: int,
    matched_count: int,
    review_patterns: int,
    noteworthy_patterns: int,
    resolver_change: bool,
) -> str:
    if query_count == 0 and malformed_count == 0 and matched_count == 0 and review_patterns == 0 and noteworthy_patterns == 0:
        return "empty"
    if malformed_count and query_count == 0:
        return "degraded"
    if matched_count or review_patterns:
        return "review_recommended"
    if noteworthy_patterns or resolver_change:
        return "noteworthy"
    if malformed_count:
        return "degraded"
    return "normal"


def _recommended_next_step(state: str, *, matched_count: int, review_patterns: int) -> str:
    if matched_count:
        return "review_dns_ioc_matches"
    if review_patterns:
        return "review_dns_patterns"
    if state == "degraded":
        return "collect_more_metadata"
    if state == "noteworthy":
        return "review_resolver_and_domain_patterns"
    return "continue_monitoring"
