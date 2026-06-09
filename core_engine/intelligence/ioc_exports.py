from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.intelligence.ioc_inventory import IOCInventorySummary, empty_ioc_inventory
from core_engine.intelligence.ioc_matching import IOCMatchRecord
from core_engine.intelligence.ioc_records import (
    IOC_RECORD_VERSION,
    IOC_SAFETY_FLAGS,
    clamp_score,
    digest,
    normalize_ioc_source_category,
    normalize_ioc_type,
    now_timestamp,
    sanitize_reference,
    sanitize_text,
)


@dataclass(frozen=True)
class IOCExportSummary:
    summary_id: str
    generated_at: str
    inventory_summary: IOCInventorySummary
    match_summary: dict[str, Any]
    type_counts: dict[str, int]
    source_category_counts: dict[str, int]
    confidence_summary: dict[str, float]
    export_formats: list[str] = field(default_factory=lambda: ["json", "csv_rows"])
    preview_only: bool = True
    destructive_action: bool = False
    advisory_notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "record_type": "ioc_export_summary",
            "record_version": IOC_RECORD_VERSION,
            "summary_id": sanitize_reference(self.summary_id),
            "generated_at": str(self.generated_at or ""),
            "inventory_summary": self.inventory_summary.to_dict(),
            "match_summary": dict(self.match_summary),
            "type_counts": dict(self.type_counts),
            "source_category_counts": dict(self.source_category_counts),
            "confidence_summary": dict(self.confidence_summary),
            "export_formats": [sanitize_reference(item) for item in self.export_formats],
            "advisory_notes": [sanitize_text(note) for note in self.advisory_notes],
            **IOC_SAFETY_FLAGS,
        }

    def to_csv_rows(self) -> list[dict[str, Any]]:
        return ioc_summary_to_csv_rows(self)


def build_ioc_export_summary(
    inventory: IOCInventorySummary | None = None,
    matches: Iterable[IOCMatchRecord] | None = None,
    *,
    generated_at: str | None = None,
) -> IOCExportSummary:
    timestamp = generated_at or now_timestamp()
    inventory_summary = inventory if isinstance(inventory, IOCInventorySummary) else empty_ioc_inventory(generated_at=timestamp)
    match_rows = [match for match in matches or [] if isinstance(match, IOCMatchRecord)]
    match_counts = Counter(match.match_state for match in match_rows)
    match_confidences = [match.confidence_score for match in match_rows]
    match_summary = {
        "match_count": len(match_rows),
        "state_counts": {key: int(match_counts[key]) for key in sorted(match_counts)},
        "matched_count": int(match_counts.get("matched", 0) + match_counts.get("pattern_match", 0) + match_counts.get("partial_match", 0)),
        "preview_only": True,
        "destructive_action": False,
    }
    confidence_values = [ioc.confidence_score for ioc in inventory_summary.iocs] + match_confidences
    confidence_summary = {
        "min": clamp_score(min(confidence_values) if confidence_values else 0.0),
        "max": clamp_score(max(confidence_values) if confidence_values else 0.0),
        "average": clamp_score(sum(confidence_values) / len(confidence_values) if confidence_values else 0.0),
    }
    return IOCExportSummary(
        summary_id="ioc-export-" + digest(
            {
                "generated_at": timestamp,
                "inventory_id": inventory_summary.inventory_id,
                "matches": [match.match_id for match in match_rows],
            }
        )[:16],
        generated_at=timestamp,
        inventory_summary=inventory_summary,
        match_summary=match_summary,
        type_counts={normalize_ioc_type(key): int(value) for key, value in inventory_summary.type_counts.items()},
        source_category_counts={
            normalize_ioc_source_category(key): int(value) for key, value in inventory_summary.source_category_counts.items()
        },
        confidence_summary=confidence_summary,
        advisory_notes=[
            "IOC export summary is metadata-only",
            "No external lookups, verdicts, or enforcement actions were performed",
        ],
    )


def ioc_summary_to_csv_rows(summary: IOCExportSummary) -> list[dict[str, Any]]:
    if not isinstance(summary, IOCExportSummary):
        return []
    rows: list[dict[str, Any]] = []
    for ioc in summary.inventory_summary.iocs:
        payload = ioc.to_dict()
        rows.append(
            {
                "row_type": "ioc",
                "ioc_id": payload["ioc_id"],
                "ioc_type": payload["ioc_type"],
                "value_hash": payload["value_hash"],
                "value_preview": payload["value_preview"],
                "source_category": payload["source_category"],
                "source_mode": payload["source_mode"],
                "confidence_score": payload["confidence_score"],
                "first_seen": payload["first_seen"],
                "last_seen": payload["last_seen"],
                "preview_only": True,
                "destructive_action": False,
            }
        )
    return rows
