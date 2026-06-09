from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field, replace
from typing import Any, Iterable

from core_engine.intelligence.ioc_records import (
    IOCRecord,
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_ioc_source_category,
    normalize_ioc_type,
    normalize_source_mode,
    now_timestamp,
    sanitize_reference,
)


DEFAULT_MAX_IOCS = 256


@dataclass(frozen=True)
class IOCInventorySummary:
    inventory_id: str
    ioc_count: int
    type_counts: dict[str, int]
    source_category_counts: dict[str, int]
    source_modes: list[str]
    confidence_summary: dict[str, float]
    first_seen: str
    last_seen: str
    iocs: list[IOCRecord] = field(default_factory=list)
    bounded: bool = True
    max_iocs: int = DEFAULT_MAX_IOCS
    export_safe: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "ioc_inventory_summary",
            "record_version": IOC_RECORD_VERSION,
            "inventory_id": sanitize_reference(self.inventory_id),
            "ioc_count": max(0, int(self.ioc_count or 0)),
            "type_counts": dict(self.type_counts),
            "source_category_counts": dict(self.source_category_counts),
            "source_modes": sorted({normalize_source_mode(mode) for mode in self.source_modes}) or ["unknown"],
            "confidence_summary": dict(self.confidence_summary),
            "first_seen": str(self.first_seen or ""),
            "last_seen": str(self.last_seen or ""),
            "iocs": [ioc.to_dict() for ioc in self.iocs],
            "bounded": True,
            "max_iocs": max(0, int(self.max_iocs or 0)),
            "export_safe": True,
            **IOC_SAFETY_FLAGS,
        }


def build_ioc_inventory(
    iocs: Iterable[IOCRecord | dict[str, Any]] | None,
    *,
    generated_at: str | None = None,
    max_iocs: int = DEFAULT_MAX_IOCS,
) -> IOCInventorySummary:
    rows = [row for row in iocs or [] if isinstance(row, IOCRecord)]
    merged = deduplicate_iocs(rows)
    bounded = merged[: max(0, int(max_iocs or 0))]
    return summarize_ioc_inventory(bounded, generated_at=generated_at, max_iocs=max_iocs)


def deduplicate_iocs(iocs: Iterable[IOCRecord]) -> list[IOCRecord]:
    grouped: dict[tuple[str, str], IOCRecord] = {}
    for ioc in iocs or []:
        if not isinstance(ioc, IOCRecord):
            continue
        key = (normalize_ioc_type(ioc.ioc_type), ioc.value_hash)
        existing = grouped.get(key)
        grouped[key] = ioc if existing is None else merge_iocs(existing, ioc)
    return sorted(grouped.values(), key=lambda item: (item.ioc_type, item.value_hash))


def merge_iocs(left: IOCRecord, right: IOCRecord) -> IOCRecord:
    first_seen = min(filter(None, [left.first_seen, right.first_seen]), default=left.first_seen or right.first_seen)
    last_seen = max(filter(None, [left.last_seen, right.last_seen]), default=left.last_seen or right.last_seen)
    tags = sorted({*left.tags, *right.tags})
    source_modes = sorted({normalize_source_mode(left.source_mode), normalize_source_mode(right.source_mode)})
    source_categories = sorted(
        {normalize_ioc_source_category(left.source_category), normalize_ioc_source_category(right.source_category)}
    )
    metadata = {
        **left.metadata,
        **right.metadata,
        "merged_source_modes": source_modes,
        "merged_source_categories": source_categories,
    }
    notes = sorted({*left.advisory_notes, *right.advisory_notes, "deduplicated IOC inventory record"})
    return replace(
        left,
        confidence_score=clamp_score(max(left.confidence_score, right.confidence_score)),
        first_seen=first_seen,
        last_seen=last_seen,
        tags=tags,
        metadata=metadata,
        advisory_notes=notes,
    )


def summarize_ioc_inventory(
    iocs: Iterable[IOCRecord],
    *,
    generated_at: str | None = None,
    max_iocs: int = DEFAULT_MAX_IOCS,
) -> IOCInventorySummary:
    rows = [ioc for ioc in iocs or [] if isinstance(ioc, IOCRecord)]
    type_counts = Counter(normalize_ioc_type(ioc.ioc_type) for ioc in rows)
    source_counts = Counter(normalize_ioc_source_category(ioc.source_category) for ioc in rows)
    modes = sorted({mode for ioc in rows for mode in _source_modes_for_ioc(ioc)}) or ["unknown"]
    confidence_values = [ioc.confidence_score for ioc in rows]
    confidence_summary = {
        "min": clamp_score(min(confidence_values) if confidence_values else 0.0),
        "max": clamp_score(max(confidence_values) if confidence_values else 0.0),
        "average": clamp_score(sum(confidence_values) / len(confidence_values) if confidence_values else 0.0),
    }
    timestamp = generated_at or now_timestamp()
    first_seen = min((ioc.first_seen for ioc in rows if ioc.first_seen), default=timestamp)
    last_seen = max((ioc.last_seen for ioc in rows if ioc.last_seen), default=timestamp)
    return IOCInventorySummary(
        inventory_id="ioc-inventory-" + digest({"generated_at": timestamp, "iocs": [ioc.ioc_id for ioc in rows], "max_iocs": max_iocs})[:16],
        ioc_count=len(rows),
        type_counts={key: int(type_counts[key]) for key in sorted(type_counts)},
        source_category_counts={key: int(source_counts[key]) for key in sorted(source_counts)},
        source_modes=modes,
        confidence_summary=confidence_summary,
        first_seen=first_seen,
        last_seen=last_seen,
        iocs=rows,
        bounded=True,
        max_iocs=max_iocs,
        export_safe=True,
    )


def empty_ioc_inventory(*, generated_at: str | None = None, max_iocs: int = DEFAULT_MAX_IOCS) -> IOCInventorySummary:
    return summarize_ioc_inventory([], generated_at=generated_at, max_iocs=max_iocs)


def _source_modes_for_ioc(ioc: IOCRecord) -> set[str]:
    modes = {normalize_source_mode(ioc.source_mode)}
    merged = ioc.metadata.get("merged_source_modes") if isinstance(ioc.metadata, dict) else None
    if isinstance(merged, list):
        modes.update(normalize_source_mode(mode) for mode in merged)
    return {mode for mode in modes if mode}
