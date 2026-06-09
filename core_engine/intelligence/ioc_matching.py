from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Iterable

from core_engine.intelligence.ioc_records import (
    IOCRecord,
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_ioc_source_category,
    normalize_ioc_type,
    normalize_ioc_value,
    normalize_source_mode,
    sanitize_reference,
    sanitize_text,
)


MATCH_STATES = {"matched", "partial_match", "pattern_match", "not_matched", "invalid", "unknown"}


@dataclass(frozen=True)
class IOCMatchRecord:
    match_id: str
    ioc_id: str
    candidate_reference: str
    match_state: str
    match_type: str
    confidence_score: float
    match_reason: str
    source_category: str
    source_mode: str
    preview_only: bool = True
    destructive_action: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "ioc_match_record",
            "record_version": IOC_RECORD_VERSION,
            "match_id": sanitize_reference(self.match_id),
            "ioc_id": sanitize_reference(self.ioc_id),
            "candidate_reference": sanitize_reference(self.candidate_reference),
            "match_state": normalize_match_state(self.match_state),
            "match_type": sanitize_reference(self.match_type) or "unknown",
            "confidence_score": clamp_score(self.confidence_score),
            "match_reason": sanitize_text(self.match_reason),
            "source_category": normalize_ioc_source_category(self.source_category),
            "source_mode": normalize_source_mode(self.source_mode),
            **IOC_SAFETY_FLAGS,
        }


def match_ioc(
    ioc: IOCRecord,
    candidate: dict[str, Any],
    *,
    candidate_reference: str | None = None,
) -> IOCMatchRecord:
    if not isinstance(ioc, IOCRecord) or not isinstance(candidate, dict):
        return _match_record(
            ioc_id=getattr(ioc, "ioc_id", "ioc-unknown"),
            candidate_reference=candidate_reference or "candidate-unknown",
            state="invalid",
            match_type="invalid",
            confidence=0.0,
            reason="invalid IOC or candidate input",
            source_category="unknown",
            source_mode="unknown",
        )
    reference = candidate_reference or candidate.get("candidate_reference") or candidate.get("id") or candidate.get("flow_reference") or candidate.get("session_reference") or "candidate-unknown"
    source_category = normalize_ioc_source_category(candidate.get("source_category") or ioc.source_category)
    source_mode = normalize_source_mode(candidate.get("source_mode") or ioc.source_mode)
    candidate_value = candidate.get("value")
    candidate_type = normalize_ioc_type(candidate.get("ioc_type") or ioc.ioc_type)
    try:
        normalized_candidate = normalize_ioc_value(candidate_value, candidate_type)
    except Exception:
        return _match_record(
            ioc_id=ioc.ioc_id,
            candidate_reference=str(reference),
            state="invalid",
            match_type="invalid",
            confidence=0.0,
            reason="candidate could not be normalized",
            source_category=source_category,
            source_mode=source_mode,
        )
    if not normalized_candidate:
        return _match_record(
            ioc_id=ioc.ioc_id,
            candidate_reference=str(reference),
            state="invalid",
            match_type="invalid",
            confidence=0.0,
            reason="candidate value is empty",
            source_category=source_category,
            source_mode=source_mode,
        )
    pattern = ioc.normalized_value
    if pattern == normalized_candidate:
        return _match_record(ioc.ioc_id, str(reference), "matched", "exact", ioc.confidence_score, "normalized values match exactly", source_category, source_mode)
    if "*" in pattern or "?" in pattern:
        if fnmatch.fnmatch(normalized_candidate, pattern):
            return _match_record(ioc.ioc_id, str(reference), "pattern_match", "pattern", clamp_score(ioc.confidence_score * 0.9), "candidate matched IOC wildcard pattern", source_category, source_mode)
    if pattern and (pattern in normalized_candidate or normalized_candidate in pattern):
        return _match_record(ioc.ioc_id, str(reference), "partial_match", "normalized", clamp_score(ioc.confidence_score * 0.7), "candidate partially matched normalized IOC value", source_category, source_mode)
    return _match_record(ioc.ioc_id, str(reference), "not_matched", "normalized", 0.0, "candidate did not match IOC", source_category, source_mode)


def match_iocs(iocs: Iterable[IOCRecord], candidates: Iterable[dict[str, Any]]) -> list[IOCMatchRecord]:
    rows: list[IOCMatchRecord] = []
    for ioc in iocs or []:
        if not isinstance(ioc, IOCRecord):
            continue
        for candidate in candidates or []:
            if not isinstance(candidate, dict):
                rows.append(match_ioc(ioc, {}, candidate_reference="candidate-invalid"))
                continue
            rows.append(match_ioc(ioc, candidate))
    return rows


def normalize_match_state(value: Any) -> str:
    token = sanitize_reference(value).lower()
    return token if token in MATCH_STATES else "unknown"


def _match_record(
    ioc_id: str,
    candidate_reference: str,
    state: str,
    match_type: str,
    confidence: float,
    reason: str,
    source_category: str,
    source_mode: str,
) -> IOCMatchRecord:
    match_id = "ioc-match-" + digest(
        {
            "ioc_id": ioc_id,
            "candidate_reference": candidate_reference,
            "state": state,
            "match_type": match_type,
        }
    )[:16]
    return IOCMatchRecord(
        match_id=match_id,
        ioc_id=ioc_id,
        candidate_reference=candidate_reference,
        match_state=state,
        match_type=match_type,
        confidence_score=confidence,
        match_reason=reason,
        source_category=source_category,
        source_mode=source_mode,
        preview_only=True,
        destructive_action=False,
    )
