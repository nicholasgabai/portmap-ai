from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_source_mode,
    sanitize_metadata,
    sanitize_reference,
    sanitize_text,
    sanitize_token,
)


QUERY_TYPES = {
    "ioc_search",
    "dns_search",
    "signature_search",
    "correlation_search",
    "scoring_search",
    "timeline_search",
    "topology_search",
    "fleet_search",
    "composite_search",
    "unknown",
}
FILTER_OPERATORS = {"equals", "contains", "min_confidence", "min_severity", "source_mode"}
DEFAULT_HUNT_LIMIT = 128
MAX_HUNT_LIMIT = 512
SEVERITY_RANK = {"none": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "unknown": 0}


class QueryValidationError(ValueError):
    """Raised when a local hunting query cannot be evaluated safely."""


@dataclass(frozen=True)
class ThreatHuntQuery:
    query_id: str
    query_name: str
    query_type: str
    query_expression: str
    filters: list[dict[str, Any]] = field(default_factory=list)
    source_scopes: list[str] = field(default_factory=list)
    enabled: bool = True
    result_limit: int = DEFAULT_HUNT_LIMIT
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "threat_hunt_query",
            "record_version": IOC_RECORD_VERSION,
            "query_id": sanitize_reference(self.query_id),
            "query_name": sanitize_text(self.query_name),
            "query_type": normalize_query_type(self.query_type),
            "query_expression": sanitize_text(self.query_expression),
            "filters": [sanitize_filter(row) for row in self.filters],
            "source_scopes": normalize_source_scopes(self.source_scopes),
            "enabled": bool(self.enabled),
            "result_limit": max_results_from_filters({"limit": self.result_limit}),
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }


def build_hunt_query(
    *,
    query_name: str,
    query_type: str = "composite_search",
    query_expression: str = "",
    filters: list[dict[str, Any]] | dict[str, Any] | None = None,
    source_scopes: list[str] | None = None,
    enabled: bool = True,
    advisory_notes: list[str] | None = None,
) -> ThreatHuntQuery:
    normalized_type = normalize_query_type(query_type)
    normalized_filters = normalize_filters(filters)
    result_limit = max_results_from_filters(filters)
    scopes = normalize_source_scopes(source_scopes or scopes_for_query_type(normalized_type))
    if not sanitize_text(query_name):
        raise QueryValidationError("query_name is required")
    if not scopes:
        scopes = ["unknown"]
    notes = list(advisory_notes or [])
    notes.append("local metadata-only hunting query; no external search or enforcement")
    query_id = "hunt-query-" + digest(
        {
            "name": sanitize_text(query_name),
            "type": normalized_type,
            "expression": sanitize_text(query_expression),
            "filters": normalized_filters,
            "scopes": scopes,
        }
    )[:16]
    return ThreatHuntQuery(
        query_id=query_id,
        query_name=sanitize_text(query_name),
        query_type=normalized_type,
        query_expression=sanitize_text(query_expression),
        filters=normalized_filters,
        source_scopes=scopes,
        enabled=bool(enabled),
        result_limit=result_limit,
        preview_only=True,
        destructive_action=False,
        advisory_notes=notes,
    )


def validate_query(query: ThreatHuntQuery) -> list[str]:
    issues: list[str] = []
    if not isinstance(query, ThreatHuntQuery):
        return ["invalid query record"]
    if not sanitize_reference(query.query_id):
        issues.append("query_id is required")
    if not sanitize_text(query.query_name):
        issues.append("query_name is required")
    if normalize_query_type(query.query_type) == "unknown" and query.query_type != "unknown":
        issues.append("unsupported query_type")
    for row in query.filters:
        operator = sanitize_reference(row.get("operator"))
        if operator not in FILTER_OPERATORS:
            issues.append(f"unsupported filter operator {operator or 'unknown'}")
    return issues


def normalize_query_type(value: Any) -> str:
    query_type = sanitize_reference(value).lower()
    return query_type if query_type in QUERY_TYPES else "unknown"


def scopes_for_query_type(query_type: str) -> list[str]:
    mapping = {
        "ioc_search": ["ioc"],
        "dns_search": ["dns"],
        "signature_search": ["signature"],
        "correlation_search": ["correlation"],
        "scoring_search": ["scoring"],
        "timeline_search": ["timeline"],
        "topology_search": ["topology"],
        "fleet_search": ["fleet"],
        "composite_search": ["ioc", "dns", "signature", "correlation", "scoring", "timeline", "topology", "fleet", "risk"],
    }
    return mapping.get(normalize_query_type(query_type), ["unknown"])


def normalize_source_scopes(values: list[Any]) -> list[str]:
    scopes = [sanitize_reference(value).lower() for value in values or []]
    return sorted({scope for scope in scopes if scope})[:32]


def normalize_filters(filters: list[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if filters is None:
        return []
    rows = filters if isinstance(filters, list) else _filters_from_mapping(filters) if isinstance(filters, dict) else []
    normalized: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        item = sanitize_filter(row)
        if item["operator"] in FILTER_OPERATORS:
            normalized.append(item)
    return normalized[:32]


def sanitize_filter(row: dict[str, Any]) -> dict[str, Any]:
    operator = sanitize_reference(row.get("operator") or row.get("op") or _operator_from_row(row)).lower()
    field_name = sanitize_reference(row.get("field") or row.get("name") or "")
    value = row.get("value", row.get("equals", row.get("contains")))
    if operator == "min_confidence":
        value = clamp_score(row.get("value", row.get("min_confidence", row.get("confidence_score", 0.0))))
        field_name = field_name or "confidence_score"
    elif operator == "min_severity":
        value = normalize_severity(row.get("value", row.get("min_severity", row.get("severity_level", "unknown"))))
        field_name = field_name or "severity_level"
    elif operator == "source_mode":
        value = normalize_source_mode(row.get("value", row.get("source_mode", "unknown")))
        field_name = field_name or "source_mode"
    elif isinstance(value, dict):
        value = sanitize_metadata(value)
    elif isinstance(value, (int, float, bool)) or value is None:
        value = value
    else:
        value = sanitize_text(value)
    return {
        "operator": operator if operator in FILTER_OPERATORS else "unknown",
        "field": field_name,
        "value": value,
    }


def max_results_from_filters(filters: list[dict[str, Any]] | dict[str, Any] | None, default: int = DEFAULT_HUNT_LIMIT) -> int:
    if isinstance(filters, dict):
        raw = filters.get("max_results") or filters.get("limit") or default
    else:
        raw = default
        for row in filters or []:
            if isinstance(row, dict) and (row.get("max_results") or row.get("limit")):
                raw = row.get("max_results") or row.get("limit")
                break
    try:
        limit = int(raw)
    except Exception:
        limit = default
    return max(0, min(limit, MAX_HUNT_LIMIT))


def normalize_severity(value: Any) -> str:
    severity = sanitize_reference(value).lower()
    return severity if severity in SEVERITY_RANK else "unknown"


def severity_meets_threshold(value: Any, threshold: Any) -> bool:
    return SEVERITY_RANK.get(normalize_severity(value), 0) >= SEVERITY_RANK.get(normalize_severity(threshold), 0)


def _filters_from_mapping(values: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for key, value in values.items():
        if key in {"limit", "max_results"}:
            continue
        if key in {"confidence_min", "min_confidence"}:
            rows.append({"operator": "min_confidence", "value": value})
        elif key in {"severity_min", "min_severity"}:
            rows.append({"operator": "min_severity", "value": value})
        elif key in {"source_mode", "source_modes"}:
            if isinstance(value, list):
                rows.extend({"operator": "source_mode", "value": item} for item in value)
            else:
                rows.append({"operator": "source_mode", "value": value})
        elif isinstance(value, dict):
            operator = value.get("operator") or value.get("op") or "equals"
            rows.append({"operator": operator, "field": key, "value": value.get("value")})
        else:
            rows.append({"operator": "equals", "field": key, "value": value})
    return rows


def _operator_from_row(row: dict[str, Any]) -> str:
    if "contains" in row:
        return "contains"
    if "equals" in row:
        return "equals"
    if "min_confidence" in row:
        return "min_confidence"
    if "min_severity" in row:
        return "min_severity"
    if "source_mode" in row:
        return "source_mode"
    return "equals"
