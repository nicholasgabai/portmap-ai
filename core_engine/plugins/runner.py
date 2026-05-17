from __future__ import annotations

import os
import subprocess
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.plugins.manifest import SAFETY_FLAGS, normalize_plugin_manifest


EXECUTION_STATUS_SEVERITY = {
    "dry_run": "info",
    "completed": "info",
    "failed": "medium",
    "timed_out": "high",
    "unsupported": "high",
}


def run_plugin(
    plugin: dict[str, Any],
    *,
    args: Iterable[str] | None = None,
    env: dict[str, str] | None = None,
    env_allowlist: Iterable[str] | None = None,
    timeout_seconds: float = 5.0,
    stdout_limit: int = 4096,
    stderr_limit: int = 4096,
    dry_run: bool = True,
    cwd: str | None = None,
) -> dict[str, Any]:
    manifest = _manifest_from_plugin(plugin)
    command = list(manifest.get("command") or [])
    extra_args = [str(item) for item in args or []]
    if not command:
        return _execution_result(
            manifest,
            "unsupported",
            errors=["plugin command is empty"],
            command=command,
            args=extra_args,
            dry_run=dry_run,
        )
    if dry_run:
        return _execution_result(
            manifest,
            "dry_run",
            command=command,
            args=extra_args,
            dry_run=True,
        )
    if "execute_local" not in set(manifest.get("permissions") or []):
        return _execution_result(
            manifest,
            "unsupported",
            errors=["plugin manifest does not declare execute_local permission"],
            command=command,
            args=extra_args,
            dry_run=False,
        )

    safe_env = _safe_env(env or {}, env_allowlist or [])
    try:
        completed = subprocess.run(
            [*command, *extra_args],
            capture_output=True,
            check=False,
            cwd=cwd,
            env=safe_env,
            text=True,
            timeout=max(float(timeout_seconds), 0.001),
        )
    except subprocess.TimeoutExpired as exc:
        return _execution_result(
            manifest,
            "timed_out",
            command=command,
            args=extra_args,
            stdout=_coerce_text(exc.stdout),
            stderr=_coerce_text(exc.stderr),
            errors=["plugin execution exceeded timeout"],
            dry_run=False,
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )
    except OSError as exc:
        return _execution_result(
            manifest,
            "unsupported",
            command=command,
            args=extra_args,
            errors=[f"plugin execution failed to start: {type(exc).__name__}"],
            dry_run=False,
            timeout_seconds=timeout_seconds,
            stdout_limit=stdout_limit,
            stderr_limit=stderr_limit,
        )

    status = "completed" if completed.returncode == 0 else "failed"
    return _execution_result(
        manifest,
        status,
        command=command,
        args=extra_args,
        return_code=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        dry_run=False,
        timeout_seconds=timeout_seconds,
        stdout_limit=stdout_limit,
        stderr_limit=stderr_limit,
    )


def summarize_execution_result(result: dict[str, Any]) -> dict[str, Any]:
    status = str(result.get("status") or "unsupported")
    return {
        "plugin_id": str(result.get("plugin_id") or ""),
        "status": status,
        "severity": EXECUTION_STATUS_SEVERITY.get(status, "medium"),
        "return_code": result.get("return_code"),
        "stdout_length": int(result.get("stdout_length") or 0),
        "stderr_length": int(result.get("stderr_length") or 0),
        "stdout_truncated": bool(result.get("stdout_truncated", False)),
        "stderr_truncated": bool(result.get("stderr_truncated", False)),
        "error_count": len(result.get("errors") or []),
        "recommended_review": status not in {"completed", "dry_run"},
        **SAFETY_FLAGS,
    }


def build_execution_event(
    result: dict[str, Any],
    *,
    source: str = "plugins.runner",
    timestamp: str | None = None,
) -> dict[str, Any]:
    summary = summarize_execution_result(result)
    severity = summary["severity"]
    event_type = "system_notice" if severity in {"info", "low"} else "policy_review_required"
    message = _operator_summary(summary)
    return {
        "event_id": _stable_id("evt", result.get("execution_id"), event_type, message),
        "event_type": event_type,
        "severity": severity,
        "source": source,
        "timestamp": timestamp or _now(),
        "message": message,
        "asset_ref": None,
        "service_ref": None,
        "flow_ref": None,
        "snapshot_ref": None,
        "finding_ref": _stable_id("finding", result.get("execution_id"), summary["status"]),
        "metadata": {
            "diagnostic_type": "plugin_execution",
            "plugin_id": summary["plugin_id"],
            "status": summary["status"],
            "summary": summary,
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_execution_finding(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    summary = summarize_execution_result(result)
    return {
        "finding_id": _stable_id("finding", result.get("execution_id"), summary["status"], summary["plugin_id"]),
        "finding_type": "plugin_execution_result",
        "category": "plugin_execution",
        "severity": summary["severity"],
        "title": "Plugin Execution Result",
        "summary": _operator_summary(summary),
        "evidence_refs": [f"plugin:{summary['plugin_id']}", f"status:{summary['status']}"],
        "recommended_review": summary["recommended_review"],
        "source_refs": [source_ref or f"plugin:{summary['plugin_id']}"],
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
        "local_only": True,
    }


def build_execution_storage_record(result: dict[str, Any], *, record_type: str = "plugin_execution") -> dict[str, Any]:
    summary = summarize_execution_result(result)
    return {
        "record_id": _stable_id("storage", result.get("execution_id"), record_type, summary),
        "record_type": record_type,
        "summary": summary,
        "payload": {
            "status": result.get("status"),
            "plugin_id": result.get("plugin_id"),
            "return_code": result.get("return_code"),
            "stdout_summary": result.get("stdout_summary"),
            "stderr_summary": result.get("stderr_summary"),
            "stdout_truncated": result.get("stdout_truncated"),
            "stderr_truncated": result.get("stderr_truncated"),
            "errors": list(result.get("errors") or []),
        },
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
        "local_only": True,
    }


def build_execution_timeline_entry(
    result: dict[str, Any],
    *,
    timestamp: str | None = None,
    source_ref: str | None = None,
) -> dict[str, Any]:
    summary = summarize_execution_result(result)
    text = _operator_summary(summary)
    return {
        "timeline_id": _stable_id("timeline", result.get("execution_id"), text),
        "timestamp": timestamp or _now(),
        "category": "plugin_execution",
        "severity": summary["severity"],
        "title": "Plugin Execution",
        "summary": text,
        "asset_ref": None,
        "service_ref": None,
        "snapshot_ref": None,
        "source_refs": [source_ref or f"plugin:{summary['plugin_id']}"],
        "recommended_review": summary["recommended_review"],
        "raw_payload_stored": False,
        "automatic_changes": False,
        "administrator_controlled": True,
    }


def build_execution_correlation_record(result: dict[str, Any], *, source_ref: str | None = None) -> dict[str, Any]:
    finding = build_execution_finding(result, source_ref=source_ref)
    status = str(result.get("status") or "unsupported")
    score = {"dry_run": 0.0, "completed": 0.0, "failed": 0.35, "timed_out": 0.65, "unsupported": 0.6}.get(status, 0.4)
    return {
        **finding,
        "correlation_key": f"plugin_execution:{finding['category']}:{finding['severity']}",
        "score": score,
        "confidence": 0.9 if status in {"completed", "dry_run"} else 0.75,
    }


def _manifest_from_plugin(plugin: dict[str, Any]) -> dict[str, Any]:
    if "manifest" in plugin and isinstance(plugin["manifest"], dict):
        manifest = plugin["manifest"]
    else:
        manifest = plugin
    if "manifest_id" in manifest and "record_version" in manifest:
        return manifest
    return normalize_plugin_manifest(manifest)


def _execution_result(
    manifest: dict[str, Any],
    status: str,
    *,
    command: list[str],
    args: list[str],
    return_code: int | None = None,
    stdout: str | bytes | None = None,
    stderr: str | bytes | None = None,
    errors: list[str] | None = None,
    dry_run: bool,
    timeout_seconds: float | None = None,
    stdout_limit: int = 4096,
    stderr_limit: int = 4096,
) -> dict[str, Any]:
    stdout_text = _coerce_text(stdout)
    stderr_text = _coerce_text(stderr)
    stdout_summary, stdout_truncated = _bounded_text(stdout_text, stdout_limit)
    stderr_summary, stderr_truncated = _bounded_text(stderr_text, stderr_limit)
    payload = {
        "ok": status in {"completed", "dry_run"},
        "status": status,
        "classification": status,
        "record_version": 1,
        "diagnostic_type": "plugin_execution",
        "plugin_id": manifest.get("plugin_id"),
        "manifest_id": manifest.get("manifest_id"),
        "execution_id": _stable_id("plugin-run", manifest.get("plugin_id"), status, _now(), return_code),
        "command_summary": _command_summary(command, args),
        "dry_run": dry_run,
        "return_code": return_code,
        "timeout_seconds": timeout_seconds,
        "stdout_summary": stdout_summary,
        "stderr_summary": stderr_summary,
        "stdout_length": len(stdout_text),
        "stderr_length": len(stderr_text),
        "stdout_truncated": stdout_truncated,
        "stderr_truncated": stderr_truncated,
        "errors": list(errors or []),
        **SAFETY_FLAGS,
    }
    payload["summary"] = summarize_execution_result(payload)
    payload["integration_hooks"] = _integration_hooks(payload)
    return payload


def _safe_env(env: dict[str, str], env_allowlist: Iterable[str]) -> dict[str, str]:
    allowed = {str(name) for name in env_allowlist}
    result = {key: os.environ[key] for key in allowed if key in os.environ}
    for key, value in env.items():
        if key in allowed:
            result[str(key)] = str(value)
    return result


def _bounded_text(value: str, limit: int) -> tuple[str, bool]:
    if limit < 0:
        limit = 0
    if len(value) <= limit:
        return value, False
    return value[:limit], True


def _coerce_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _command_summary(command: list[str], args: list[str]) -> dict[str, Any]:
    return {
        "executable": os.path.basename(command[0]) if command else "",
        "argument_count": max(len(command) - 1, 0) + len(args),
        "command_stored": False,
    }


def _integration_hooks(result: dict[str, Any]) -> dict[str, bool]:
    return {
        "event_pipeline_ready": True,
        "storage_ready": True,
        "scheduler_ready": True,
        "dashboard_ready": True,
        "policy_review_ready": result.get("status") not in {"completed", "dry_run"},
        "timeline_ready": True,
        "correlation_ready": True,
    }


def _operator_summary(summary: dict[str, Any]) -> str:
    plugin_id = str(summary.get("plugin_id") or "unknown-plugin")
    status = str(summary.get("status") or "unknown")
    if status == "dry_run":
        return f"Plugin {plugin_id} dry-run preview generated for operator review."
    if status == "completed":
        return f"Plugin {plugin_id} completed local controlled execution."
    return f"Plugin {plugin_id} produced {status} execution status for operator review."


def _stable_id(prefix: str, *parts: Any) -> str:
    material = "|".join(str(part) for part in parts)
    return f"{prefix}-" + sha256(material.encode("utf-8")).hexdigest()[:16]


def _now() -> str:
    return datetime.now(UTC).isoformat()
