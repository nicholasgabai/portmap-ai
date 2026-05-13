"""Local behavior correlation and baseline delta helpers."""

from core_engine.correlation.baseline import (
    build_baseline_from_aggregated_reports,
    build_baseline_from_events,
    build_baseline_from_snapshots,
    build_baseline_from_visibility_reports,
)
from core_engine.correlation.delta import (
    compare_asset_sets,
    compare_baselines,
    compare_finding_sets,
    compare_service_sets,
    compare_topology_sets,
)
from core_engine.correlation.scoring import (
    assign_advisory_severity,
    score_delta_finding,
    summarize_delta_scores,
)

__all__ = [
    "assign_advisory_severity",
    "build_baseline_from_aggregated_reports",
    "build_baseline_from_events",
    "build_baseline_from_snapshots",
    "build_baseline_from_visibility_reports",
    "compare_asset_sets",
    "compare_baselines",
    "compare_finding_sets",
    "compare_service_sets",
    "compare_topology_sets",
    "score_delta_finding",
    "summarize_delta_scores",
]
