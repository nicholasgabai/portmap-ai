from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.intelligence.ai_correlation import AICorrelationSummary
from core_engine.intelligence.dns_analytics import DNSAnalyticsRecord
from core_engine.intelligence.domain_patterns import DomainPatternRecord
from core_engine.intelligence.evidence_chains import EvidenceChainRecord
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
from core_engine.intelligence.query_language import (
    DEFAULT_HUNT_LIMIT,
    ThreatHuntQuery,
    build_hunt_query,
    max_results_from_filters,
    severity_meets_threshold,
    validate_query,
)
from core_engine.intelligence.signature_matching import SignatureMatchRecord
from core_engine.intelligence.threat_scoring import AdvisoryThreatScoringRecord


HUNT_STATES = {"results_found", "no_results", "degraded", "empty", "invalid", "unknown"}
SEVERITY_ORDER = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 0}


@dataclass(frozen=True)
class ThreatHuntResult:
    hunt_id: str
    query_id: str
    hunt_state: str
    result_count: int
    matched_records: list[dict[str, Any]] = field(default_factory=list)
    summary_points: list[str] = field(default_factory=list)
    confidence_summary: dict[str, Any] = field(default_factory=dict)
    severity_summary: dict[str, int] = field(default_factory=dict)
    source_modes: list[str] = field(default_factory=list)
    generated_at: str = ""
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "threat_hunt_result",
            "record_version": IOC_RECORD_VERSION,
            "hunt_id": sanitize_reference(self.hunt_id),
            "query_id": sanitize_reference(self.query_id),
            "hunt_state": normalize_hunt_state(self.hunt_state),
            "result_count": max(0, int(self.result_count or 0)),
            "matched_records": [sanitize_metadata(row) for row in self.matched_records][:DEFAULT_HUNT_LIMIT * 4],
            "summary_points": [sanitize_text(point) for point in self.summary_points],
            "confidence_summary": sanitize_metadata(self.confidence_summary),
            "severity_summary": {sanitize_reference(key): int(value) for key, value in self.severity_summary.items()},
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "generated_at": str(self.generated_at or ""),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def run_threat_hunt(
    query: ThreatHuntQuery | dict[str, Any] | None = None,
    *,
    query_name: str = "local_hunt",
    query_type: str = "composite_search",
    query_expression: str = "",
    filters: list[dict[str, Any]] | dict[str, Any] | None = None,
    source_scopes: list[str] | None = None,
    ioc_inventories: Iterable[IOCInventorySummary] | IOCInventorySummary | None = None,
    ioc_matches: Iterable[IOCMatchRecord] | IOCMatchRecord | None = None,
    dns_analytics: Iterable[DNSAnalyticsRecord] | DNSAnalyticsRecord | None = None,
    dns_patterns: Iterable[DomainPatternRecord] | DomainPatternRecord | None = None,
    signature_matches: Iterable[SignatureMatchRecord] | SignatureMatchRecord | None = None,
    ai_correlations: Iterable[AICorrelationSummary] | AICorrelationSummary | None = None,
    evidence_chains: Iterable[EvidenceChainRecord] | EvidenceChainRecord | None = None,
    threat_scores: Iterable[AdvisoryThreatScoringRecord] | AdvisoryThreatScoringRecord | None = None,
    timeline_summaries: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    topology_summaries: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    fleet_summaries: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    risk_dashboard_summaries: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    generated_at: str | None = None,
    max_results: int | None = None,
) -> ThreatHuntResult:
    try:
        hunt_query = normalize_hunt_query(
            query,
            query_name=query_name,
            query_type=query_type,
            query_expression=query_expression,
            filters=filters,
            source_scopes=source_scopes,
        )
    except Exception:
        return _empty_result("invalid", "hunt-query-invalid", generated_at=generated_at, points=["invalid query input"])
    issues = validate_query(hunt_query)
    if issues:
        return _empty_result("invalid", hunt_query.query_id, generated_at=generated_at, points=issues)
    if not hunt_query.enabled:
        return _empty_result("empty", hunt_query.query_id, generated_at=generated_at, points=["query is disabled"])

    records: list[dict[str, Any]] = []
    malformed_count = 0
    groups = [
        ("ioc", ioc_inventories),
        ("ioc", ioc_matches),
        ("dns", dns_analytics),
        ("dns", dns_patterns),
        ("signature", signature_matches),
        ("correlation", ai_correlations),
        ("correlation", evidence_chains),
        ("scoring", threat_scores),
        ("timeline", timeline_summaries),
        ("topology", topology_summaries),
        ("fleet", fleet_summaries),
        ("risk", risk_dashboard_summaries),
    ]
    for scope, values in groups:
        valid, malformed = _records_from_values(scope, values)
        records.extend(valid)
        malformed_count += malformed

    scopes = set(hunt_query.source_scopes)
    if "unknown" not in scopes:
        records = [row for row in records if row["source_scope"] in scopes or hunt_query.query_type == "composite_search"]
    if not records:
        state = "degraded" if malformed_count else "empty"
        point = "malformed input records were ignored" if malformed_count else "no local records supplied for hunt"
        return _empty_result(state, hunt_query.query_id, generated_at=generated_at, points=[point])

    limit = max_results if max_results is not None else hunt_query.result_limit
    matches = [row for row in records if _matches_query(row, hunt_query)]
    matches = sorted(matches, key=_sort_key)[: max(0, int(limit))]
    if not matches:
        state = "degraded" if malformed_count else "no_results"
    else:
        state = "degraded" if malformed_count else "results_found"
    timestamp = generated_at or now_timestamp()
    confidence_values = [row["confidence_score"] for row in matches]
    severity_counts = Counter(row["severity_level"] for row in matches)
    source_modes = sorted({row["source_mode"] for row in matches}) or ["unknown"]
    summary_points = _summary_points(hunt_query, matches, malformed_count, limit)
    return ThreatHuntResult(
        hunt_id="hunt-result-" + digest({"query": hunt_query.query_id, "matches": [row["record_reference"] for row in matches], "generated_at": timestamp})[:16],
        query_id=hunt_query.query_id,
        hunt_state=state,
        result_count=len(matches),
        matched_records=matches,
        summary_points=summary_points,
        confidence_summary=_confidence_summary(confidence_values),
        severity_summary={key: int(severity_counts[key]) for key in sorted(severity_counts)},
        source_modes=source_modes,
        generated_at=timestamp,
        preview_only=True,
        destructive_action=False,
        advisory_notes=["local metadata-only hunt result; no final verdict or enforcement"],
    )


def normalize_hunt_query(
    query: ThreatHuntQuery | dict[str, Any] | None,
    *,
    query_name: str,
    query_type: str,
    query_expression: str,
    filters: list[dict[str, Any]] | dict[str, Any] | None,
    source_scopes: list[str] | None,
) -> ThreatHuntQuery:
    if isinstance(query, ThreatHuntQuery):
        return query
    if isinstance(query, dict):
        return build_hunt_query(
            query_name=str(query["query_name"]) if "query_name" in query else query_name,
            query_type=str(query["query_type"]) if "query_type" in query else query_type,
            query_expression=str(query["query_expression"]) if "query_expression" in query else query_expression,
            filters=query.get("filters") or filters,
            source_scopes=query.get("source_scopes") or source_scopes,
            enabled=bool(query.get("enabled", True)),
        )
    return build_hunt_query(
        query_name=query_name,
        query_type=query_type,
        query_expression=query_expression,
        filters=filters,
        source_scopes=source_scopes,
    )


def normalize_hunt_state(value: Any) -> str:
    state = sanitize_reference(value).lower()
    return state if state in HUNT_STATES else "unknown"


def deterministic_hunt_json(record: ThreatHuntResult | ThreatHuntQuery | dict[str, Any]) -> str:
    payload = record.to_dict() if isinstance(record, (ThreatHuntResult, ThreatHuntQuery)) else record
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def _records_from_values(scope: str, values: Any) -> tuple[list[dict[str, Any]], int]:
    rows = _as_list(values)
    records: list[dict[str, Any]] = []
    malformed = 0
    for index, row in enumerate(rows):
        payload = _to_payload(row)
        if not isinstance(payload, dict):
            malformed += 1
            continue
        records.append(_summary_record(scope, payload, index))
        records.extend(_child_records(scope, payload))
    return records, malformed


def _to_payload(row: Any) -> dict[str, Any] | None:
    if hasattr(row, "to_dict"):
        payload = row.to_dict()
        return payload if isinstance(payload, dict) else None
    return row if isinstance(row, dict) else None


def _summary_record(scope: str, payload: dict[str, Any], index: int) -> dict[str, Any]:
    reference = _reference_for_payload(payload, scope, index)
    source_mode = normalize_source_mode(payload.get("source_mode") or _first(payload.get("source_modes")) or "unknown")
    severity = _severity_for_payload(payload)
    confidence = _confidence_for_payload(payload)
    summary = _summary_for_payload(payload, reference)
    return {
        "record_reference": sanitize_reference(reference),
        "record_type": sanitize_reference(payload.get("record_type") or scope),
        "source_scope": sanitize_reference(scope),
        "confidence_score": confidence,
        "severity_level": severity,
        "source_mode": source_mode,
        "summary": summary,
        "search_text": _search_text(payload, summary),
    }


def _child_records(scope: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    children: list[dict[str, Any]] = []
    if scope == "ioc" and isinstance(payload.get("iocs"), list):
        for index, row in enumerate(payload["iocs"]):
            if isinstance(row, dict):
                children.append(_summary_record(scope, row, index))
    if scope == "timeline" and isinstance(payload.get("events"), list):
        for index, row in enumerate(payload["events"]):
            if isinstance(row, dict):
                children.append(_summary_record(scope, row, index))
    if scope == "risk" and isinstance(payload.get("cards"), list):
        for index, row in enumerate(payload["cards"]):
            if isinstance(row, dict):
                children.append(_summary_record(scope, row, index))
    return children


def _matches_query(row: dict[str, Any], query: ThreatHuntQuery) -> bool:
    if query.query_expression and sanitize_text(query.query_expression).lower() not in row["search_text"].lower():
        return False
    for item in query.filters:
        operator = item.get("operator")
        field_name = item.get("field")
        value = item.get("value")
        if operator == "equals" and str(row.get(field_name, "")).lower() != str(value).lower():
            return False
        if operator == "contains" and str(value).lower() not in row["search_text"].lower() and str(value).lower() not in str(row.get(field_name, "")).lower():
            return False
        if operator == "min_confidence" and row["confidence_score"] < clamp_score(value):
            return False
        if operator == "min_severity" and not severity_meets_threshold(row["severity_level"], value):
            return False
        if operator == "source_mode" and row["source_mode"] != normalize_source_mode(value):
            return False
    return True


def _summary_points(query: ThreatHuntQuery, matches: list[dict[str, Any]], malformed_count: int, limit: int) -> list[str]:
    if not matches:
        points = [f"query {query.query_name} returned no local metadata matches"]
    else:
        scopes = Counter(row["source_scope"] for row in matches)
        points = [f"query {query.query_name} returned {len(matches)} bounded local metadata matches"]
        points.extend(f"{scope} scope matched {count} records" for scope, count in sorted(scopes.items()))
    if malformed_count:
        points.append(f"{malformed_count} malformed input records were ignored")
    points.append(f"result limit was {limit}")
    return points


def _confidence_summary(values: list[float]) -> dict[str, Any]:
    if not values:
        return {"minimum": 0.0, "maximum": 0.0, "average": 0.0, "count": 0}
    return {
        "minimum": min(values),
        "maximum": max(values),
        "average": round(sum(values) / len(values), 4),
        "count": len(values),
    }


def _empty_result(state: str, query_id: str, *, generated_at: str | None = None, points: list[str] | None = None) -> ThreatHuntResult:
    timestamp = generated_at or now_timestamp()
    return ThreatHuntResult(
        hunt_id="hunt-result-" + digest({"state": state, "query_id": query_id, "generated_at": timestamp})[:16],
        query_id=query_id,
        hunt_state=state,
        result_count=0,
        matched_records=[],
        summary_points=points or [state],
        confidence_summary={"minimum": 0.0, "maximum": 0.0, "average": 0.0, "count": 0},
        severity_summary={},
        source_modes=["unknown"],
        generated_at=timestamp,
        preview_only=True,
        destructive_action=False,
        advisory_notes=["local metadata-only hunt result; no final verdict or enforcement"],
    )


def _as_list(values: Any) -> list[Any]:
    if values is None:
        return []
    if isinstance(values, list):
        return values
    if isinstance(values, tuple):
        return list(values)
    return [values]


def _reference_for_payload(payload: dict[str, Any], scope: str, index: int) -> str:
    for key in (
        "ioc_id",
        "inventory_id",
        "match_id",
        "dns_analytics_id",
        "pattern_id",
        "signature_match_id",
        "correlation_id",
        "chain_id",
        "scoring_id",
        "timeline_window_id",
        "event_id",
        "graph_id",
        "topology_graph_id",
        "fleet_node_id",
        "summary_id",
        "dashboard_id",
        "card_id",
        "id",
        "reference",
    ):
        if payload.get(key):
            return str(payload[key])
    return f"{scope}-{index}"


def _severity_for_payload(payload: dict[str, Any]) -> str:
    for key in ("severity_level", "highest_severity", "risk_state", "scoring_state", "analytics_state", "match_state", "correlation_state"):
        value = payload.get(key)
        if value:
            text = str(value).lower()
            if text in SEVERITY_ORDER:
                return text
            if text in {"high", "critical", "elevated"}:
                return "high" if text == "elevated" else text
            if text in {"moderate", "review_recommended", "results_found", "matched", "correlated"}:
                return "medium"
            if text in {"noteworthy", "partial_match", "partially_correlated", "low"}:
                return "low"
    score = payload.get("advisory_score") or payload.get("risk_score") or payload.get("overall_risk_score") or 0.0
    try:
        value = float(score)
    except Exception:
        value = 0.0
    if value >= 0.85:
        return "critical"
    if value >= 0.65:
        return "high"
    if value >= 0.35:
        return "medium"
    if value > 0.0:
        return "low"
    return "unknown"


def _confidence_for_payload(payload: dict[str, Any]) -> float:
    return clamp_score(payload.get("confidence_score") or payload.get("metadata_confidence") or payload.get("advisory_score") or 0.5)


def _summary_for_payload(payload: dict[str, Any], reference: str) -> str:
    for key in ("summary", "operator_summary", "explanation_summary", "recommended_next_step", "match_reason", "pattern_state", "analytics_state", "scoring_state"):
        if payload.get(key):
            return sanitize_text(payload[key])
    return sanitize_text(f"{payload.get('record_type', 'metadata record')} {reference}")


def _search_text(payload: dict[str, Any], summary: str) -> str:
    safe = sanitize_metadata(payload)
    return json.dumps({"payload": safe, "summary": summary}, sort_keys=True, default=str).lower()


def _sort_key(row: dict[str, Any]) -> tuple[int, float, str]:
    return (-SEVERITY_ORDER.get(row["severity_level"], 0), -row["confidence_score"], row["record_reference"])


def _first(values: Any) -> Any:
    if isinstance(values, list) and values:
        return values[0]
    return None
