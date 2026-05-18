from __future__ import annotations

from typing import Any, Iterable

from core_engine.policy.models import Policy
from core_engine.runtime.pipeline import run_runtime_pipeline, summarize_runtime_pipeline
from core_engine.storage.repositories import LocalStorageRepository


def run_visibility_runtime_workflow(
    *,
    assets: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    flows: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    findings: Iterable[dict[str, Any]] | None = None,
    baseline_snapshot: dict[str, Any] | None = None,
    current_snapshot: dict[str, Any] | None = None,
    policies: Iterable[Policy] | None = None,
    repository: LocalStorageRepository | None = None,
    dry_run: bool = True,
    write_local: bool = False,
    generated_at: str | None = None,
    label: str = "visibility-runtime-workflow",
) -> dict[str, Any]:
    """Run the Phase 61 local visibility workflow.

    This is a convenience wrapper around the reusable runtime pipeline. It
    consumes already-collected records and never performs active collection.
    """
    return run_runtime_pipeline(
        assets=assets,
        services=services,
        flows=flows,
        findings=findings,
        baseline_snapshot=baseline_snapshot,
        current_snapshot=current_snapshot,
        policies=policies,
        repository=repository,
        dry_run=dry_run,
        write_local=write_local,
        generated_at=generated_at,
        label=label,
    )


__all__ = ["run_runtime_pipeline", "run_visibility_runtime_workflow", "summarize_runtime_pipeline"]
