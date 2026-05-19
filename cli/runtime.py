from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from rich.console import Console
from rich.table import Table

from core_engine.export import (
    build_operational_export_bundle,
    export_operational_bundle_json,
    write_operational_export_archive,
    write_operational_export_bundle,
)
from core_engine.policy.models import ReviewRecord
from core_engine.policy.review_queue import ReviewQueue
from core_engine.runtime import (
    RuntimeSessionManager,
    build_runtime_recovery_summary,
    load_runtime_profile,
    summarize_runtime_profile,
)
from core_engine.runtime.pipeline import run_runtime_pipeline
from core_engine.storage.repositories import LocalStorageRepository
from core_engine.storage.sqlite_store import SQLiteStore


console = Console()


SAFETY_FLAGS = {
    "local_only": True,
    "raw_payload_stored": False,
    "automatic_changes": False,
    "administrator_controlled": True,
}


def add_runtime_subparser(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> argparse.ArgumentParser:
    runtime = subparsers.add_parser("runtime", help="Unified local runtime operations")
    runtime_subparsers = runtime.add_subparsers(dest="runtime_command", required=True)

    status = runtime_subparsers.add_parser("status", help="Summarize a local runtime profile and session")
    _add_profile_args(status)
    status.add_argument("--session-id", default="runtime-session-cli", help="Session identifier for the status summary")
    status.add_argument("--output", choices=["table", "json"], default="table")
    status.set_defaults(func=cmd_runtime)

    run = runtime_subparsers.add_parser("run", help="Run the explicit local runtime pipeline over provided records")
    _add_profile_args(run)
    run.add_argument("--assets-json", help="Asset row/list, visibility report, or JSON file path")
    run.add_argument("--services-json", help="Service row/list, service report, or JSON file path")
    run.add_argument("--findings-json", help="Finding row/list or JSON file path")
    run.add_argument("--baseline-json", help="Baseline topology snapshot JSON object or file path")
    run.add_argument("--current-json", help="Current topology snapshot JSON object or file path")
    run.add_argument("--label", default="runtime-cli", help="Runtime workflow label")
    run.add_argument("--session-id", default="runtime-session-cli", help="Session identifier for the run summary")
    run.add_argument("--write-local", action="store_true", help="Explicitly allow local storage writes")
    run.add_argument("--db-path", help="SQLite database path required with --write-local")
    run.add_argument("--output", choices=["table", "json"], default="json")
    run.set_defaults(func=cmd_runtime)

    recover = runtime_subparsers.add_parser("recover", help="Summarize local runtime checkpoints and recovery recommendations")
    recover.add_argument("--checkpoint-json", action="append", help="Runtime checkpoint JSON object or file path; repeat to include multiple")
    recover.add_argument("--pipeline-json", action="append", help="Runtime pipeline result JSON object or file path; repeat to include multiple")
    recover.add_argument("--output", choices=["table", "json"], default="json")
    recover.set_defaults(func=cmd_runtime)

    reviews = runtime_subparsers.add_parser("reviews", help="Summarize local operator review records")
    reviews.add_argument("--reviews-json", help="Review record/list or review export JSON file path")
    reviews.add_argument("--status", help="Filter review summary source records by status")
    reviews.add_argument("--severity", help="Filter review summary source records by severity")
    reviews.add_argument("--category", help="Filter review summary source records by category")
    reviews.add_argument("--output", choices=["table", "json"], default="json")
    reviews.set_defaults(func=cmd_runtime)

    export = runtime_subparsers.add_parser("export", help="Build an operator-controlled local operational export bundle")
    export.add_argument("--snapshots-json", help="Snapshot row/list or JSON file path")
    export.add_argument("--findings-json", help="Finding row/list or JSON file path")
    export.add_argument("--reviews-json", help="Review row/list or JSON file path")
    export.add_argument("--runtime-summary-json", help="Runtime summary JSON object or file path")
    export.add_argument("--label", default="runtime-cli-export", help="Export bundle label")
    export.add_argument("--output-path", help="Optional operator-selected output path")
    export.add_argument("--archive", action="store_true", help="Write a zip archive when --output-path is provided")
    export.add_argument("--output", choices=["table", "json"], default="json")
    export.set_defaults(func=cmd_runtime)
    return runtime


def cmd_runtime(args: argparse.Namespace) -> int:
    try:
        if args.runtime_command == "status":
            payload = runtime_status(args)
        elif args.runtime_command == "run":
            payload = runtime_run(args)
        elif args.runtime_command == "recover":
            payload = runtime_recover(args)
        elif args.runtime_command == "reviews":
            payload = runtime_reviews(args)
        elif args.runtime_command == "export":
            payload = runtime_export(args)
        else:
            raise ValueError(f"unsupported runtime command: {args.runtime_command}")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        error_payload = {
            "status": "error",
            "error": str(exc),
            "runtime_command": getattr(args, "runtime_command", ""),
            **SAFETY_FLAGS,
        }
        if getattr(args, "output", "json") == "json":
            _print_json(error_payload)
        else:
            print(f"Runtime error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        _print_json(payload)
    else:
        _render_runtime_table(payload, args.runtime_command)
    return 0


def runtime_status(args: argparse.Namespace) -> dict[str, Any]:
    profile = _load_profile(args)
    manager = RuntimeSessionManager()
    session = manager.start_session(
        session_id=args.session_id,
        mode=profile.runtime_mode,
        enabled_components=profile.components,
        metadata={"profile_id": profile.profile_id, "source": "runtime-cli"},
    )
    return {
        "status": "ok",
        "runtime_command": "status",
        "profile_summary": summarize_runtime_profile(profile),
        "session_summary": session.to_dict(),
        **SAFETY_FLAGS,
    }


def runtime_run(args: argparse.Namespace) -> dict[str, Any]:
    profile = _load_profile(args)
    repository = None
    if args.write_local:
        if not args.db_path:
            raise ValueError("--db-path is required with --write-local")
        repository = LocalStorageRepository(SQLiteStore(Path(args.db_path)))
    assets = _json_rows_arg(args.assets_json, list_keys=("assets", "records"))
    services = _json_rows_arg(args.services_json, list_keys=("services", "results"))
    findings = _json_rows_arg(args.findings_json, list_keys=("findings", "records"))
    baseline = _json_object_arg(args.baseline_json, label="--baseline-json")
    current = _json_object_arg(args.current_json, label="--current-json")
    result = run_runtime_pipeline(
        assets=assets,
        services=services,
        findings=findings,
        baseline_snapshot=baseline,
        current_snapshot=current,
        repository=repository,
        dry_run=not args.write_local,
        write_local=args.write_local,
        label=args.label,
    )
    manager = RuntimeSessionManager()
    session = manager.start_session(
        session_id=args.session_id,
        mode="local-write" if args.write_local else "dry-run",
        enabled_components=profile.components,
        metadata={"profile_id": profile.profile_id, "source": "runtime-cli"},
    )
    session_summary = manager.attach_pipeline_result(session.session_id, result)
    if result.get("summary"):
        manager.attach_event_summary(session.session_id, {"event_count": result["summary"].get("event_count", 0)})
        manager.attach_storage_summary(session.session_id, {"storage_write_count": result["summary"].get("storage_write_count", 0)})
    return {
        "status": result["status"],
        "runtime_command": "run",
        "dry_run": not args.write_local,
        "write_local": bool(args.write_local),
        "profile_summary": summarize_runtime_profile(profile),
        "session_summary": session_summary,
        "pipeline_result": result,
        **SAFETY_FLAGS,
    }


def runtime_recover(args: argparse.Namespace) -> dict[str, Any]:
    checkpoints = [_json_object(value, label="--checkpoint-json", allow_file=True) for value in args.checkpoint_json or []]
    pipeline_results = [_json_object(value, label="--pipeline-json", allow_file=True) for value in args.pipeline_json or []]
    summary = build_runtime_recovery_summary(
        checkpoints=checkpoints,
        pipeline_results=pipeline_results,
    )
    return {
        "runtime_command": "recover",
        **summary,
    }


def runtime_reviews(args: argparse.Namespace) -> dict[str, Any]:
    rows = _json_rows_arg(args.reviews_json, list_keys=("reviews", "items", "records"))
    reviews = [_review_from_row(row) for row in rows]
    queue = ReviewQueue(reviews)
    filtered = queue.list_reviews(status=args.status, severity=args.severity, category=args.category)
    filtered_queue = ReviewQueue(filtered)
    return {
        "status": "ok",
        "runtime_command": "reviews",
        "summary": filtered_queue.summarize_reviews(),
        "items": [review.to_dict() for review in filtered],
        **SAFETY_FLAGS,
    }


def runtime_export(args: argparse.Namespace) -> dict[str, Any]:
    snapshots = _json_rows_arg(args.snapshots_json, list_keys=("snapshots", "records"))
    findings = _json_rows_arg(args.findings_json, list_keys=("findings", "records"))
    reviews = _json_rows_arg(args.reviews_json, list_keys=("reviews", "items", "records"))
    runtime_summary = _json_object_arg(args.runtime_summary_json, label="--runtime-summary-json")
    bundle = build_operational_export_bundle(
        snapshots=snapshots,
        findings=findings,
        reviews=reviews,
        runtime_summary=runtime_summary,
        label=args.label,
    )
    write_result = None
    if args.output_path:
        if args.archive:
            write_result = write_operational_export_archive(args.output_path, bundle)
        else:
            write_result = write_operational_export_bundle(args.output_path, bundle)
    return {
        "status": "ok",
        "runtime_command": "export",
        "bundle": bundle,
        "write_result": write_result,
        **SAFETY_FLAGS,
    }


def _add_profile_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", default="default", choices=["default", "edge-device", "raspberry-pi"], help="Built-in runtime profile")
    parser.add_argument("--profile-json", help="Operator runtime profile JSON object or file path")


def _load_profile(args: argparse.Namespace):
    operator_profile = _json_object_arg(getattr(args, "profile_json", None), label="--profile-json")
    return load_runtime_profile(builtin=args.profile, operator_profile=operator_profile)


def _review_from_row(row: dict[str, Any]) -> ReviewRecord:
    return ReviewRecord(
        review_id=str(row.get("review_id") or row.get("finding_id") or ""),
        policy_id=str(row.get("policy_id") or "policy-runtime-cli"),
        source_ref=str(row.get("source_ref") or row.get("source") or "runtime:cli"),
        category=str(row.get("category") or "operator_review"),
        severity=str(row.get("severity") or "info"),
        title=str(row.get("title") or "Runtime Review"),
        summary=str(row.get("summary") or "Runtime review record."),
        evidence_refs=[str(item) for item in row.get("evidence_refs") or []],
        recommended_action=str(row.get("recommended_action") or "operator_review"),
        status=str(row.get("status") or "open"),
        approval_required=bool(row.get("approval_required", True)),
        created_at=str(row.get("created_at") or "2026-01-01T00:00:00+00:00"),
        updated_at=str(row.get("updated_at") or row.get("created_at") or "2026-01-01T00:00:00+00:00"),
        reviewed_by=row.get("reviewed_by"),
        review_note=row.get("review_note"),
    )


def _json_rows_arg(value: str | None, *, list_keys: tuple[str, ...]) -> list[dict[str, Any]]:
    if not value:
        return []
    return _extract_json_rows(value, list_keys=list_keys, allow_file=True)


def _json_object_arg(value: str | None, *, label: str) -> dict[str, Any] | None:
    if not value:
        return None
    return _json_object(value, label=label, allow_file=True)


def _load_json_arg(value: str) -> Any:
    stripped = value.strip()
    if stripped.startswith(("{", "[")):
        return json.loads(value)
    candidate = Path(value)
    if candidate.exists() and candidate.is_file():
        with open(candidate, "r", encoding="utf-8") as handle:
            return json.load(handle)
    return json.loads(value)


def _extract_json_rows(value: str, *, list_keys: tuple[str, ...], allow_file: bool = False) -> list[dict[str, Any]]:
    payload = _load_json_arg(value) if allow_file else json.loads(value)
    if isinstance(payload, dict):
        for key in list_keys:
            if isinstance(payload.get(key), list):
                return [row for row in payload[key] if isinstance(row, dict)]
        return [payload]
    if isinstance(payload, list):
        return [row for row in payload if isinstance(row, dict)]
    raise ValueError("JSON input must decode to an object, list, or supported report object")


def _json_object(value: str, *, label: str, allow_file: bool = False) -> dict[str, Any]:
    payload = _load_json_arg(value) if allow_file else json.loads(value)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must decode to an object")
    return payload


def _print_json(payload: Any) -> None:
    print(json.dumps(payload, indent=2, sort_keys=True))


def _render_runtime_table(payload: dict[str, Any], command: str) -> None:
    table = Table(title=f"PortMap-AI Runtime {command.title()}")
    table.add_column("Field")
    table.add_column("Value")
    table.add_row("status", str(payload.get("status") or "-"))
    if command == "status":
        profile = payload.get("profile_summary") or {}
        session = payload.get("session_summary") or {}
        table.add_row("profile", str(profile.get("profile_id") or "-"))
        table.add_row("mode", str(session.get("mode") or profile.get("runtime_mode") or "-"))
        table.add_row("components", str(profile.get("component_count") or session.get("component_count") or 0))
    elif command == "run":
        summary = ((payload.get("pipeline_result") or {}).get("summary") or {})
        table.add_row("dry_run", str(payload.get("dry_run")))
        table.add_row("events", str(summary.get("event_count", 0)))
        table.add_row("findings", str(summary.get("finding_count", 0)))
        table.add_row("storage_writes", str(summary.get("storage_write_count", 0)))
    elif command == "recover":
        table.add_row("recommendations", str(payload.get("recommendation_count", 0)))
        table.add_row("incomplete", str(len(payload.get("incomplete_workflows") or [])))
        table.add_row("failed_steps", str(len(payload.get("failed_steps") or [])))
    elif command == "reviews":
        summary = payload.get("summary") or {}
        table.add_row("reviews", str(summary.get("review_count", 0)))
        table.add_row("approval_required", str(summary.get("approval_required_count", 0)))
    elif command == "export":
        manifest = ((payload.get("bundle") or {}).get("manifest") or {})
        table.add_row("digest", str(manifest.get("digest") or "-"))
        table.add_row("write_result", str((payload.get("write_result") or {}).get("status") or "not_written"))
    console.print(table)
