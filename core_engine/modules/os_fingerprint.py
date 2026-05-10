from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from core_engine.modules.service_detection import enumerate_services


PACKAGE_FINGERPRINTS = Path(__file__).resolve().parents[1] / "os_fingerprints.json"
REPO_FINGERPRINTS = Path(__file__).resolve().parents[2] / "data" / "os_fingerprints.json"
UNKNOWN_THRESHOLD = 0.4


@dataclass(frozen=True)
class OSFingerprint:
    name: str
    ttl_initial: tuple[int, ...] = ()
    ttl_observed_min: int = 0
    ttl_observed_max: int = 0
    tcp_window_sizes: tuple[int, ...] = ()
    tcp_option_markers: tuple[str, ...] = ()
    service_markers: tuple[str, ...] = ()
    banner_patterns: tuple[str, ...] = ()


@dataclass(frozen=True)
class OSCandidate:
    os_family: str
    confidence: float
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "os_family": self.os_family,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
        }


def load_os_fingerprints(path: str | Path | None = None) -> list[OSFingerprint]:
    selected_path = Path(path) if path else REPO_FINGERPRINTS if REPO_FINGERPRINTS.exists() else PACKAGE_FINGERPRINTS
    with open(selected_path, "r", encoding="utf-8") as handle:
        payload = json.load(handle)
    fingerprints: list[OSFingerprint] = []
    for raw in payload.get("families", []):
        fingerprints.append(
            OSFingerprint(
                name=str(raw.get("name") or "unknown"),
                ttl_initial=tuple(int(value) for value in raw.get("ttl_initial", [])),
                ttl_observed_min=int(raw.get("ttl_observed_min", 0) or 0),
                ttl_observed_max=int(raw.get("ttl_observed_max", 0) or 0),
                tcp_window_sizes=tuple(int(value) for value in raw.get("tcp_window_sizes", [])),
                tcp_option_markers=tuple(str(value).lower() for value in raw.get("tcp_option_markers", [])),
                service_markers=tuple(str(value).upper() for value in raw.get("service_markers", [])),
                banner_patterns=tuple(str(value) for value in raw.get("banner_patterns", [])),
            )
        )
    return fingerprints


def _normalize_options(options: Any) -> set[str]:
    if options is None:
        return set()
    if isinstance(options, str):
        raw_items = re.split(r"[\s,]+", options)
    else:
        raw_items = [str(item) for item in options]
    normalized: set[str] = set()
    aliases = {"ws": "wscale", "window_scale": "wscale", "sackok": "sack"}
    for raw in raw_items:
        value = raw.strip().lower()
        if not value:
            continue
        normalized.add(aliases.get(value, value))
    return normalized


def _service_names(observation: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for item in observation.get("services") or []:
        if isinstance(item, str):
            names.add(item.upper())
        elif isinstance(item, dict):
            service = item.get("service") or item.get("name")
            if service:
                names.add(str(service).upper())
    for item in observation.get("service_results") or []:
        service = item.get("service") if isinstance(item, dict) else None
        if service:
            names.add(str(service).upper())
    return names


def _banners(observation: dict[str, Any]) -> list[str]:
    banners = [str(item) for item in observation.get("banners") or [] if str(item)]
    for item in observation.get("service_results") or []:
        if isinstance(item, dict) and item.get("banner"):
            banners.append(str(item["banner"]))
        if isinstance(item, dict) and item.get("version"):
            banners.append(str(item["version"]))
    return banners


def _score_fingerprint(observation: dict[str, Any], fingerprint: OSFingerprint) -> OSCandidate:
    score = 0.0
    evidence: list[str] = []
    ttl = observation.get("ttl")
    if ttl is not None:
        ttl_int = int(ttl)
        if fingerprint.ttl_observed_min <= ttl_int <= fingerprint.ttl_observed_max:
            score += 0.35
            evidence.append(f"ttl:{ttl_int} in {fingerprint.ttl_observed_min}-{fingerprint.ttl_observed_max}")
        elif any(abs(ttl_int - initial) <= 8 for initial in fingerprint.ttl_initial):
            score += 0.25
            evidence.append(f"ttl:{ttl_int} near initial {list(fingerprint.ttl_initial)}")

    tcp_window = observation.get("tcp_window") or observation.get("window_size")
    if tcp_window is not None:
        window_int = int(tcp_window)
        if window_int in fingerprint.tcp_window_sizes:
            score += 0.2
            evidence.append(f"tcp_window:{window_int}")

    options = _normalize_options(observation.get("tcp_options"))
    if options and fingerprint.tcp_option_markers:
        overlap = options.intersection(fingerprint.tcp_option_markers)
        if overlap:
            ratio = len(overlap) / max(len(fingerprint.tcp_option_markers), 1)
            score += min(0.2, 0.05 + ratio * 0.15)
            evidence.append(f"tcp_options:{','.join(sorted(overlap))}")

    services = _service_names(observation)
    if services and fingerprint.service_markers:
        overlap = services.intersection(fingerprint.service_markers)
        if overlap:
            score += min(0.18, 0.06 * len(overlap))
            evidence.append(f"services:{','.join(sorted(overlap))}")

    banners = _banners(observation)
    for pattern in fingerprint.banner_patterns:
        if any(re.search(pattern, banner, flags=re.IGNORECASE) for banner in banners):
            score += 0.25
            evidence.append(f"banner:{pattern}")
            break

    return OSCandidate(fingerprint.name, min(score, 0.99), tuple(evidence))


def fingerprint_observation(
    observation: dict[str, Any],
    *,
    fingerprints: Iterable[OSFingerprint] | None = None,
) -> dict[str, Any]:
    """Infer a probable OS family from passive observations and service evidence."""
    loaded = list(fingerprints or load_os_fingerprints())
    candidates = sorted(
        (_score_fingerprint(observation, fingerprint) for fingerprint in loaded),
        key=lambda item: item.confidence,
        reverse=True,
    )
    best = candidates[0] if candidates else OSCandidate("unknown", 0.0, ())
    probable = best.os_family if best.confidence >= UNKNOWN_THRESHOLD else "unknown"
    confidence = best.confidence if probable != "unknown" else 0.0
    return {
        "target": observation.get("target", ""),
        "probable_os": probable,
        "confidence": round(confidence, 3),
        "certainty": "low" if confidence < 0.6 else "medium" if confidence < 0.8 else "high",
        "evidence": list(best.evidence) if probable != "unknown" else [],
        "candidates": [candidate.to_dict() for candidate in candidates if candidate.confidence > 0],
        "notes": [
            "OS fingerprinting is probabilistic.",
            "Low-confidence results are reported as unknown.",
            "No exploit or credential behavior is performed.",
        ],
    }


def fingerprint_from_service_results(
    target: str,
    service_results: Iterable[dict[str, Any]],
    *,
    ttl: int | None = None,
    tcp_window: int | None = None,
    tcp_options: Iterable[str] | str | None = None,
) -> dict[str, Any]:
    observation: dict[str, Any] = {
        "target": target,
        "service_results": list(service_results),
    }
    if ttl is not None:
        observation["ttl"] = ttl
    if tcp_window is not None:
        observation["tcp_window"] = tcp_window
    if tcp_options is not None:
        observation["tcp_options"] = tcp_options
    return fingerprint_observation(observation)


def fingerprint_targets(
    targets: str | Iterable[str],
    ports: Iterable[int] | None = None,
    *,
    ip_version: str | int | None = "auto",
    timeout: float = 2.0,
    max_targets: int = 64,
    max_ports: int = 128,
    aggressive: bool = False,
    ttl: int | None = None,
    tcp_window: int | None = None,
    tcp_options: Iterable[str] | str | None = None,
    logger: logging.Logger | None = None,
) -> list[dict[str, Any]]:
    """Run safe service enumeration and infer OS families from the resulting evidence."""
    services = enumerate_services(
        targets,
        ports=ports,
        ip_version=ip_version,
        timeout=timeout,
        max_targets=max_targets,
        max_ports=max_ports,
        aggressive=aggressive,
    )
    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in services:
        grouped.setdefault(str(row.get("target", "")), []).append(row)

    results: list[dict[str, Any]] = []
    for target, rows in grouped.items():
        result = fingerprint_from_service_results(
            target,
            rows,
            ttl=ttl,
            tcp_window=tcp_window,
            tcp_options=tcp_options,
        )
        result["service_results"] = rows
        results.append(result)
        if logger:
            logger.info("os_fingerprint_result %s", json.dumps(result, sort_keys=True))
    return results


__all__ = [
    "OSCandidate",
    "OSFingerprint",
    "fingerprint_from_service_results",
    "fingerprint_observation",
    "fingerprint_targets",
    "load_os_fingerprints",
]
