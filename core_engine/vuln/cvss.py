from __future__ import annotations

from typing import Any


SEVERITY_BY_SCORE = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (0.1, "low"),
    (0.0, "none"),
)
SEVERITY_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_from_score(score: float | int | None) -> str:
    try:
        value = float(score or 0)
    except (TypeError, ValueError):
        value = 0.0
    for floor, severity in SEVERITY_BY_SCORE:
        if value >= floor:
            return severity
    return "none"


def normalize_severity(value: Any, *, score: float | int | None = None) -> str:
    text = str(value or "").strip().lower()
    if text in SEVERITY_RANK:
        return text
    return severity_from_score(score)


def severity_rank(severity: str | None) -> int:
    return SEVERITY_RANK.get(str(severity or "").lower(), 0)


def extract_cvss(cve: dict[str, Any]) -> dict[str, Any]:
    metrics = cve.get("metrics") if isinstance(cve, dict) else {}
    if not isinstance(metrics, dict):
        metrics = {}
    metric_keys = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2")
    for key in metric_keys:
        entries = metrics.get(key)
        if not isinstance(entries, list):
            continue
        selected = _select_metric(entries)
        if not selected:
            continue
        data = selected.get("cvssData") if isinstance(selected.get("cvssData"), dict) else {}
        score = _float(data.get("baseScore") or selected.get("baseScore"))
        severity = normalize_severity(selected.get("baseSeverity") or data.get("baseSeverity"), score=score)
        return {
            "version": data.get("version") or key.removeprefix("cvssMetric"),
            "score": score,
            "severity": severity,
            "vector": data.get("vectorString") or "",
            "source": selected.get("source") or "",
            "type": selected.get("type") or "",
        }
    return {"version": "", "score": 0.0, "severity": "none", "vector": "", "source": "", "type": ""}


def advisory_risk_score(
    cvss_score: float | int | None,
    *,
    exposed: bool = False,
    known_exploited: bool = False,
    version_match: bool = False,
) -> float:
    base = min(max(_float(cvss_score) / 10.0, 0.0), 1.0)
    if exposed:
        base += 0.08
    if known_exploited:
        base += 0.15
    if version_match:
        base += 0.05
    return round(min(base, 1.0), 2)


def _select_metric(entries: list[Any]) -> dict[str, Any] | None:
    candidates = [entry for entry in entries if isinstance(entry, dict)]
    if not candidates:
        return None
    primary = [entry for entry in candidates if str(entry.get("type") or "").lower() == "primary"]
    return max(primary or candidates, key=lambda item: _float((item.get("cvssData") or {}).get("baseScore") or item.get("baseScore")))


def _float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
