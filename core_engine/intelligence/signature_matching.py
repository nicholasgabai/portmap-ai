from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.intelligence.domain_patterns import DomainPatternRecord
from core_engine.intelligence.ioc_matching import IOCMatchRecord
from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_source_mode,
    sanitize_reference,
    sanitize_text,
)
from core_engine.intelligence.signature_records import (
    SEVERITY_LEVELS,
    SIGNATURE_TYPES,
    SignatureRecord,
    normalize_severity,
    normalize_signature_type,
)


SIGNATURE_MATCH_STATES = {"matched", "partial_match", "not_matched", "invalid", "degraded", "unknown"}


@dataclass(frozen=True)
class SignatureMatchRecord:
    signature_match_id: str
    signature_id: str
    signature_type: str
    match_state: str
    match_reason: str
    matched_references: list[str] = field(default_factory=list)
    supporting_iocs: list[str] = field(default_factory=list)
    supporting_dns_patterns: list[str] = field(default_factory=list)
    supporting_flows: list[str] = field(default_factory=list)
    supporting_protocols: list[str] = field(default_factory=list)
    supporting_attribution: list[str] = field(default_factory=list)
    supporting_topology: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    severity_level: str = "unknown"
    source_mode: str = "unknown"
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "signature_match_record",
            "record_version": IOC_RECORD_VERSION,
            "signature_match_id": sanitize_reference(self.signature_match_id),
            "signature_id": sanitize_reference(self.signature_id),
            "signature_type": normalize_signature_type(self.signature_type),
            "match_state": normalize_signature_match_state(self.match_state),
            "match_reason": sanitize_text(self.match_reason),
            "matched_references": _safe_refs(self.matched_references),
            "supporting_iocs": _safe_refs(self.supporting_iocs),
            "supporting_dns_patterns": _safe_refs(self.supporting_dns_patterns),
            "supporting_flows": _safe_refs(self.supporting_flows),
            "supporting_protocols": _safe_refs(self.supporting_protocols),
            "supporting_attribution": _safe_refs(self.supporting_attribution),
            "supporting_topology": _safe_refs(self.supporting_topology),
            "confidence_score": clamp_score(self.confidence_score),
            "severity_level": normalize_severity(self.severity_level),
            "source_mode": normalize_source_mode(self.source_mode),
            **IOC_SAFETY_FLAGS,
        }


def match_signature(signature: SignatureRecord, context: dict[str, Any] | None = None) -> SignatureMatchRecord:
    if not isinstance(signature, SignatureRecord):
        return _build_match(
            signature_id="signature-invalid",
            signature_type="unknown",
            state="invalid",
            reason="invalid signature input",
            confidence=0.0,
            severity="unknown",
            source_mode="unknown",
        )
    if not signature.enabled:
        return _build_match(
            signature_id=signature.signature_id,
            signature_type=signature.signature_type,
            state="not_matched",
            reason="signature is disabled",
            confidence=0.0,
            severity=signature.severity_level,
            source_mode=signature.source_mode,
        )
    if not isinstance(context, dict):
        return _build_match(
            signature_id=signature.signature_id,
            signature_type=signature.signature_type,
            state="invalid",
            reason="invalid match context",
            confidence=0.0,
            severity=signature.severity_level,
            source_mode=signature.source_mode,
        )

    signature_type = normalize_signature_type(signature.signature_type)
    if signature_type == "ioc_match":
        result = _match_ioc_signature(signature, context)
    elif signature_type == "dns_pattern":
        result = _match_dns_signature(signature, context)
    elif signature_type == "flow_behavior":
        result = _match_dict_collection_signature(signature, context, "flows", "supporting_flows")
    elif signature_type == "protocol_behavior":
        result = _match_dict_collection_signature(signature, context, "protocols", "supporting_protocols")
    elif signature_type == "application_attribution":
        result = _match_dict_collection_signature(signature, context, "attribution", "supporting_attribution")
    elif signature_type == "topology_relationship":
        result = _match_dict_collection_signature(signature, context, "topology", "supporting_topology")
    elif signature_type == "runtime_health":
        result = _match_runtime_signature(signature, context)
    elif signature_type == "composite":
        result = _match_composite_signature(signature, context)
    else:
        result = _build_match(
            signature_id=signature.signature_id,
            signature_type=signature.signature_type,
            state="unknown",
            reason="signature type is unknown",
            confidence=0.0,
            severity=signature.severity_level,
            source_mode=signature.source_mode,
        )
    return result


def match_signatures(signatures: Iterable[SignatureRecord], context: dict[str, Any] | None = None) -> list[SignatureMatchRecord]:
    return [match_signature(signature, context) for signature in signatures or []]


def normalize_signature_match_state(value: Any) -> str:
    token = sanitize_reference(value).lower()
    return token if token in SIGNATURE_MATCH_STATES else "unknown"


def _match_ioc_signature(signature: SignatureRecord, context: dict[str, Any]) -> SignatureMatchRecord:
    rows = [row for row in context.get("ioc_matches", []) if isinstance(row, IOCMatchRecord)]
    required_state = str(signature.match_conditions.get("match_state") or signature.match_conditions.get("ioc_match_state") or "matched")
    min_count = _safe_int(signature.match_conditions.get("min_ioc_matches"), default=1)
    matched = [row for row in rows if row.match_state == required_state or row.match_state in {"matched", "partial_match", "pattern_match"} and required_state == "matched"]
    return _collection_result(
        signature,
        matched_count=len(matched),
        min_count=min_count,
        reason="IOC match condition evaluated locally",
        refs=[row.match_id for row in matched],
        supporting_iocs=[row.ioc_id for row in matched],
        confidence_values=[row.confidence_score for row in matched],
    )


def _match_dns_signature(signature: SignatureRecord, context: dict[str, Any]) -> SignatureMatchRecord:
    rows = [row for row in context.get("domain_patterns", []) if isinstance(row, DomainPatternRecord)]
    pattern_type = signature.match_conditions.get("pattern_type")
    pattern_state = signature.match_conditions.get("pattern_state")
    min_count = _safe_int(signature.match_conditions.get("min_dns_patterns"), default=1)
    matched = [
        row
        for row in rows
        if (not pattern_type or row.pattern_type == pattern_type) and (not pattern_state or row.pattern_state == pattern_state)
    ]
    return _collection_result(
        signature,
        matched_count=len(matched),
        min_count=min_count,
        reason="DNS pattern condition evaluated locally",
        refs=[row.pattern_id for row in matched],
        supporting_dns_patterns=[row.pattern_id for row in matched],
        confidence_values=[row.confidence_score for row in matched],
    )


def _match_dict_collection_signature(
    signature: SignatureRecord,
    context: dict[str, Any],
    key: str,
    support_field: str,
) -> SignatureMatchRecord:
    rows = [row for row in context.get(key, []) if isinstance(row, dict)]
    min_count = _safe_int(signature.match_conditions.get("min_count"), default=1)
    conditions = {
        item_key: item_value
        for item_key, item_value in signature.match_conditions.items()
        if item_key not in {"min_count", "min_signal_matches"}
    }
    matched = [row for row in rows if _row_matches_conditions(row, conditions)]
    refs = [_reference_for_row(row, key, index) for index, row in enumerate(matched)]
    kwargs = {support_field: refs}
    return _collection_result(
        signature,
        matched_count=len(matched),
        min_count=min_count,
        reason=f"{key} metadata condition evaluated locally",
        refs=refs,
        confidence_values=[_confidence_for_row(row) for row in matched],
        **kwargs,
    )


def _match_runtime_signature(signature: SignatureRecord, context: dict[str, Any]) -> SignatureMatchRecord:
    runtime = context.get("runtime_health")
    rows = runtime if isinstance(runtime, list) else [runtime] if isinstance(runtime, dict) else []
    min_count = _safe_int(signature.match_conditions.get("min_count"), default=1)
    conditions = {key: value for key, value in signature.match_conditions.items() if key != "min_count"}
    matched = [row for row in rows if isinstance(row, dict) and _row_matches_conditions(row, conditions)]
    refs = [_reference_for_row(row, "runtime", index) for index, row in enumerate(matched)]
    return _collection_result(
        signature,
        matched_count=len(matched),
        min_count=min_count,
        reason="runtime health condition evaluated locally",
        refs=refs,
        confidence_values=[_confidence_for_row(row) for row in matched],
    )


def _match_composite_signature(signature: SignatureRecord, context: dict[str, Any]) -> SignatureMatchRecord:
    signal_results = [
        _match_ioc_signature(signature, context) if any(row in signature.match_conditions for row in ("match_state", "ioc_match_state", "min_ioc_matches")) else None,
        _match_dns_signature(signature, context) if any(row in signature.match_conditions for row in ("pattern_type", "pattern_state", "min_dns_patterns")) else None,
        _match_dict_collection_signature(signature, context, "flows", "supporting_flows")
        if any(row in signature.match_conditions for row in ("protocol", "flow_state", "session_classification"))
        else None,
        _match_dict_collection_signature(signature, context, "protocols", "supporting_protocols")
        if any(row in signature.match_conditions for row in ("protocol_hint", "protocol_state"))
        else None,
        _match_dict_collection_signature(signature, context, "attribution", "supporting_attribution")
        if any(row in signature.match_conditions for row in ("attribution_state", "candidate_app_class", "candidate_service_class"))
        else None,
        _match_dict_collection_signature(signature, context, "topology", "supporting_topology")
        if any(row in signature.match_conditions for row in ("relationship_state", "relationship_type", "topology_risk"))
        else None,
    ]
    matches = [row for row in signal_results if isinstance(row, SignatureMatchRecord) and row.match_state in {"matched", "partial_match"}]
    required = _safe_int(signature.match_conditions.get("min_signal_matches"), default=2)
    refs = [ref for row in matches for ref in row.matched_references]
    supporting_iocs = [ref for row in matches for ref in row.supporting_iocs]
    supporting_dns = [ref for row in matches for ref in row.supporting_dns_patterns]
    supporting_flows = [ref for row in matches for ref in row.supporting_flows]
    supporting_protocols = [ref for row in matches for ref in row.supporting_protocols]
    supporting_attribution = [ref for row in matches for ref in row.supporting_attribution]
    supporting_topology = [ref for row in matches for ref in row.supporting_topology]
    confidence_values = [row.confidence_score for row in matches]
    return _collection_result(
        signature,
        matched_count=len(matches),
        min_count=required,
        reason="composite signature evaluated across local metadata signals",
        refs=refs,
        supporting_iocs=supporting_iocs,
        supporting_dns_patterns=supporting_dns,
        supporting_flows=supporting_flows,
        supporting_protocols=supporting_protocols,
        supporting_attribution=supporting_attribution,
        supporting_topology=supporting_topology,
        confidence_values=confidence_values,
    )


def _collection_result(
    signature: SignatureRecord,
    *,
    matched_count: int,
    min_count: int,
    reason: str,
    refs: list[str],
    confidence_values: list[float],
    supporting_iocs: list[str] | None = None,
    supporting_dns_patterns: list[str] | None = None,
    supporting_flows: list[str] | None = None,
    supporting_protocols: list[str] | None = None,
    supporting_attribution: list[str] | None = None,
    supporting_topology: list[str] | None = None,
) -> SignatureMatchRecord:
    if matched_count >= min_count:
        state = "matched"
    elif matched_count > 0:
        state = "partial_match"
    else:
        state = "not_matched"
    confidence = clamp_score(
        (sum(confidence_values) / len(confidence_values) if confidence_values else 0.0) * signature.confidence_score
    )
    return _build_match(
        signature_id=signature.signature_id,
        signature_type=signature.signature_type,
        state=state,
        reason=reason,
        confidence=confidence,
        severity=signature.severity_level,
        source_mode=signature.source_mode,
        refs=refs,
        supporting_iocs=supporting_iocs or [],
        supporting_dns_patterns=supporting_dns_patterns or [],
        supporting_flows=supporting_flows or [],
        supporting_protocols=supporting_protocols or [],
        supporting_attribution=supporting_attribution or [],
        supporting_topology=supporting_topology or [],
    )


def _build_match(
    *,
    signature_id: str,
    signature_type: str,
    state: str,
    reason: str,
    confidence: float,
    severity: str,
    source_mode: str,
    refs: list[str] | None = None,
    supporting_iocs: list[str] | None = None,
    supporting_dns_patterns: list[str] | None = None,
    supporting_flows: list[str] | None = None,
    supporting_protocols: list[str] | None = None,
    supporting_attribution: list[str] | None = None,
    supporting_topology: list[str] | None = None,
) -> SignatureMatchRecord:
    match_id = "signature-match-" + digest(
        {
            "signature_id": signature_id,
            "signature_type": signature_type,
            "state": state,
            "refs": refs or [],
        }
    )[:16]
    return SignatureMatchRecord(
        signature_match_id=match_id,
        signature_id=signature_id,
        signature_type=signature_type if signature_type in SIGNATURE_TYPES else "unknown",
        match_state=state,
        match_reason=reason,
        matched_references=refs or [],
        supporting_iocs=supporting_iocs or [],
        supporting_dns_patterns=supporting_dns_patterns or [],
        supporting_flows=supporting_flows or [],
        supporting_protocols=supporting_protocols or [],
        supporting_attribution=supporting_attribution or [],
        supporting_topology=supporting_topology or [],
        confidence_score=confidence,
        severity_level=severity if severity in SEVERITY_LEVELS else "unknown",
        source_mode=source_mode,
        preview_only=True,
        destructive_action=False,
    )


def _row_matches_conditions(row: dict[str, Any], conditions: dict[str, Any]) -> bool:
    if not conditions:
        return False
    for key, expected in conditions.items():
        actual = row.get(key)
        if actual != expected:
            return False
    return True


def _reference_for_row(row: dict[str, Any], prefix: str, index: int) -> str:
    return str(
        row.get("reference")
        or row.get("id")
        or row.get("flow_reference")
        or row.get("session_reference")
        or row.get("relationship_reference")
        or row.get("attribution_id")
        or row.get("protocol_reference")
        or f"{prefix}-{index}"
    )


def _confidence_for_row(row: dict[str, Any]) -> float:
    return clamp_score(row.get("confidence_score") or row.get("metadata_confidence") or row.get("risk_score") or 0.5)


def _safe_int(value: Any, *, default: int) -> int:
    try:
        return max(0, int(value))
    except Exception:
        return default


def _safe_refs(values: list[str]) -> list[str]:
    return [sanitize_reference(value) for value in values if sanitize_reference(value)][:64]
