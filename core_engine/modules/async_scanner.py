from __future__ import annotations

import asyncio
import errno
import json
import logging
import socket
import time
from typing import Any, Awaitable, Callable, Iterable

from core_engine.modules.ip_utils import TargetAddress, format_host_port
from core_engine.modules.scan_scheduler import ScanPlan, adaptive_rate_delay, build_scan_plan
from core_engine.risky_ports import service_name_for_port


AsyncProbe = Callable[[TargetAddress, int, float], Awaitable[dict[str, Any]]]


def _family_for_target(target: TargetAddress) -> socket.AddressFamily:
    return socket.AF_INET6 if target.version == 6 else socket.AF_INET


def _state_from_exception(exc: BaseException) -> tuple[str, str]:
    if isinstance(exc, ConnectionRefusedError):
        return "closed", "connection_refused"
    if isinstance(exc, TimeoutError) or isinstance(exc, asyncio.TimeoutError):
        return "filtered", "timeout"
    if isinstance(exc, OSError):
        code = int(exc.errno or 0)
        if code in {errno.ECONNREFUSED, errno.ECONNRESET}:
            return "closed", "connection_refused"
        if code in {errno.ETIMEDOUT, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN}:
            return "filtered", errno.errorcode.get(code, str(code)).lower()
        if code in {errno.EACCES, errno.EPERM}:
            return "unknown", "permission_denied"
        return "unknown", errno.errorcode.get(code, type(exc).__name__.lower())
    return "unknown", type(exc).__name__


def _result(target: TargetAddress, port: int, state: str, reason: str, duration_ms: float) -> dict[str, Any]:
    return {
        "program": "-",
        "pid": 0,
        "port": int(port),
        "service_name": service_name_for_port(port) or "",
        "payload": "",
        "flags": "",
        "protocol": "TCP",
        "status": state.upper(),
        "tcp_state": state,
        "direction": "outgoing",
        "local": "-",
        "remote": format_host_port(target.host, int(port)),
        "target": target.host,
        "ip_version": target.version,
        "target_source": target.source,
        "reason": reason,
        "duration_ms": round(duration_ms, 3),
        "scanner": "async_connect",
    }


async def probe_tcp_connect(target: TargetAddress, port: int, timeout: float) -> dict[str, Any]:
    """Probe one TCP port with asyncio.open_connection."""
    started = time.perf_counter()
    writer: asyncio.StreamWriter | None = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(target.host, int(port), family=_family_for_target(target)),
            timeout=timeout,
        )
        duration_ms = (time.perf_counter() - started) * 1000
        return _result(target, int(port), "open", "connect_success", duration_ms)
    except BaseException as exc:
        duration_ms = (time.perf_counter() - started) * 1000
        state, reason = _state_from_exception(exc)
        return _result(target, int(port), state, reason, duration_ms)
    finally:
        if writer:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


async def scan_with_plan(
    plan: ScanPlan,
    *,
    probe: AsyncProbe = probe_tcp_connect,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    semaphore = asyncio.Semaphore(plan.concurrency)
    results: list[dict[str, Any]] = []
    timeout_count = 0
    error_count = 0
    completed = 0

    async def run_probe(target: TargetAddress, port: int) -> dict[str, Any]:
        nonlocal completed, timeout_count, error_count
        async with semaphore:
            row = await probe(target, port, plan.timeout)
            completed += 1
            reason = str(row.get("reason") or "")
            state = str(row.get("tcp_state") or "")
            if reason == "timeout":
                timeout_count += 1
            if state == "unknown":
                error_count += 1
            if logger:
                logger.info("async_scan_result %s", json.dumps(row, sort_keys=True))
            delay = adaptive_rate_delay(
                base_delay=plan.rate_delay,
                timeout_ratio=timeout_count / max(completed, 1),
                error_ratio=error_count / max(completed, 1),
            )
            if delay:
                await asyncio.sleep(delay)
            return row

    tasks = [asyncio.create_task(run_probe(target, port)) for target in plan.targets for port in plan.ports]
    for task in asyncio.as_completed(tasks):
        results.append(await task)
    results.sort(key=lambda row: (str(row.get("target", "")), int(row.get("port", 0))))
    return results


async def async_scan_targets(
    targets: str | Iterable[str],
    ports: Iterable[int],
    *,
    ip_version: str | int | None = "auto",
    timeout: float = 1.0,
    concurrency: int = 64,
    rate_per_second: float = 128.0,
    max_targets: int = 256,
    max_ports: int = 1024,
    aggressive: bool = False,
    probe: AsyncProbe = probe_tcp_connect,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    plan = build_scan_plan(
        targets,
        ports,
        ip_version=ip_version,
        timeout=timeout,
        concurrency=concurrency,
        rate_per_second=rate_per_second,
        max_targets=max_targets,
        max_ports=max_ports,
        aggressive=aggressive,
    )
    rows = await scan_with_plan(plan, probe=probe, logger=logger)
    if plan.warnings:
        for row in rows:
            row.setdefault("warnings", list(plan.warnings))
    return rows


def scan_targets(
    targets: str | Iterable[str],
    ports: Iterable[int],
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Synchronous wrapper for CLI and service integrations."""
    return asyncio.run(async_scan_targets(targets, ports, **kwargs))


__all__ = [
    "AsyncProbe",
    "async_scan_targets",
    "probe_tcp_connect",
    "scan_targets",
    "scan_with_plan",
]
