from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Iterable

from core_engine.modules.ip_utils import TargetAddress, expand_targets
from core_engine.modules.ipv6_scanner import normalize_tcp_ports


DEFAULT_CONCURRENCY = 64
DEFAULT_RATE_PER_SECOND = 128.0
DEFAULT_MAX_TARGETS = 256
DEFAULT_MAX_PORTS = 1024
AGGRESSIVE_MAX_TARGETS = 8192
AGGRESSIVE_MAX_PORTS = 65535
AGGRESSIVE_MAX_CONCURRENCY = 1024
AGGRESSIVE_MAX_RATE_PER_SECOND = 5000.0


@dataclass(frozen=True)
class ScanPlan:
    targets: list[TargetAddress]
    ports: list[int]
    concurrency: int
    timeout: float
    rate_per_second: float
    aggressive: bool = False
    warnings: list[str] = field(default_factory=list)

    @property
    def total_probes(self) -> int:
        return len(self.targets) * len(self.ports)

    @property
    def batches(self) -> int:
        if self.total_probes == 0:
            return 0
        return math.ceil(self.total_probes / self.concurrency)

    @property
    def rate_delay(self) -> float:
        return 0.0 if self.rate_per_second <= 0 else 1.0 / self.rate_per_second

    def to_dict(self) -> dict[str, Any]:
        return {
            "targets": [target.to_dict() for target in self.targets],
            "ports": list(self.ports),
            "concurrency": self.concurrency,
            "timeout": self.timeout,
            "rate_per_second": self.rate_per_second,
            "rate_delay": self.rate_delay,
            "aggressive": self.aggressive,
            "total_probes": self.total_probes,
            "batches": self.batches,
            "warnings": list(self.warnings),
        }


def normalize_concurrency(value: int, *, aggressive: bool = False) -> int:
    concurrency = int(value)
    if concurrency <= 0:
        raise ValueError("scan concurrency must be greater than 0")
    max_concurrency = AGGRESSIVE_MAX_CONCURRENCY if aggressive else DEFAULT_CONCURRENCY
    if concurrency > max_concurrency:
        mode = "aggressive" if aggressive else "default"
        raise ValueError(f"scan concurrency exceeds {mode} limit of {max_concurrency}")
    return concurrency


def normalize_rate_per_second(value: float, *, aggressive: bool = False) -> float:
    rate = float(value)
    if rate <= 0:
        raise ValueError("scan rate_per_second must be greater than 0")
    max_rate = AGGRESSIVE_MAX_RATE_PER_SECOND if aggressive else DEFAULT_RATE_PER_SECOND
    if rate > max_rate:
        mode = "aggressive" if aggressive else "default"
        raise ValueError(f"scan rate_per_second exceeds {mode} limit of {max_rate:g}")
    return rate


def adaptive_rate_delay(*, base_delay: float, timeout_ratio: float, error_ratio: float = 0.0) -> float:
    """Increase inter-probe delay under elevated timeout/error rates."""
    if base_delay < 0:
        raise ValueError("base_delay must be 0 or greater")
    pressure = max(float(timeout_ratio), float(error_ratio), 0.0)
    if pressure >= 0.75:
        return base_delay * 4
    if pressure >= 0.5:
        return base_delay * 2
    if pressure >= 0.25:
        return base_delay * 1.5
    return base_delay


def build_scan_plan(
    targets: str | Iterable[str],
    ports: Iterable[int],
    *,
    ip_version: str | int | None = "auto",
    timeout: float = 1.0,
    concurrency: int = DEFAULT_CONCURRENCY,
    rate_per_second: float = DEFAULT_RATE_PER_SECOND,
    max_targets: int = DEFAULT_MAX_TARGETS,
    max_ports: int = DEFAULT_MAX_PORTS,
    aggressive: bool = False,
) -> ScanPlan:
    if timeout <= 0:
        raise ValueError("scan timeout must be greater than 0")
    target_limit = max(max_targets, AGGRESSIVE_MAX_TARGETS) if aggressive else max_targets
    port_limit = max(max_ports, AGGRESSIVE_MAX_PORTS) if aggressive else max_ports
    selected_targets = expand_targets(targets, ip_version=ip_version, max_targets=target_limit)
    selected_ports = normalize_tcp_ports(ports)

    if not aggressive and len(selected_targets) > max_targets:
        raise ValueError(f"scheduled scan limited to {max_targets} targets by default; enable aggressive mode to override")
    if not aggressive and len(selected_ports) > max_ports:
        raise ValueError(f"scheduled scan limited to {max_ports} ports by default; enable aggressive mode to override")
    if aggressive and len(selected_targets) > target_limit:
        raise ValueError(f"scheduled scan exceeds aggressive target limit of {target_limit}")
    if aggressive and len(selected_ports) > port_limit:
        raise ValueError(f"scheduled scan exceeds aggressive port limit of {port_limit}")

    warnings: list[str] = []
    if aggressive:
        warnings.append("aggressive mode increases scan volume and should only be used on authorized networks")

    normalized_concurrency = normalize_concurrency(concurrency, aggressive=aggressive)
    normalized_rate = normalize_rate_per_second(rate_per_second, aggressive=aggressive)
    return ScanPlan(
        targets=selected_targets,
        ports=selected_ports,
        concurrency=normalized_concurrency,
        timeout=float(timeout),
        rate_per_second=normalized_rate,
        aggressive=aggressive,
        warnings=warnings,
    )


__all__ = [
    "AGGRESSIVE_MAX_CONCURRENCY",
    "AGGRESSIVE_MAX_PORTS",
    "AGGRESSIVE_MAX_RATE_PER_SECOND",
    "AGGRESSIVE_MAX_TARGETS",
    "DEFAULT_CONCURRENCY",
    "DEFAULT_MAX_PORTS",
    "DEFAULT_MAX_TARGETS",
    "DEFAULT_RATE_PER_SECOND",
    "ScanPlan",
    "adaptive_rate_delay",
    "build_scan_plan",
    "normalize_concurrency",
    "normalize_rate_per_second",
]
