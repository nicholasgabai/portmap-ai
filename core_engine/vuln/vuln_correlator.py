from __future__ import annotations

from hashlib import sha256
import re
from typing import Any, Iterable

from core_engine.vuln.cve_client import analyze_service_cves
from core_engine.vuln.cvss import severity_rank


EXPLOITABILITY_PATTERNS = (
    ("remote_code_execution", re.compile(r"\b(remote code execution|rce|execute arbitrary code|command execution)\b", re.I)),
    ("authentication_bypass", re.compile(r"\b(authentication bypass|auth bypass|without authentication|unauthenticated)\b", re.I)),
    ("privilege_escalation", re.compile(r"\b(privilege escalation|gain privileges|elevat(?:e|ion) privileges)\b", re.I)),
    ("path_traversal", re.compile(r"\b(path traversal|directory traversal|\.\./)\b", re.I)),
    ("sql_injection", re.compile(r"\b(sql injection|sqli)\b", re.I)),
    ("credential_exposure", re.compile(r"\b(credential|password|secret|token disclosure|information disclosure)\b", re.I)),
    ("denial_of_service", re.compile(r"\b(denial of service|dos|crash)\b", re.I)),
)
RANSOMWARE_MARKERS = ("ransomware", "ransom", "kev-ransomware", "known ransomware")


def correlate_vulnerabilities(
    *,
    services: Iterable[dict[str, Any]] | None = None,
    cve_matches: Iterable[dict[str, Any]] | None = None,
    cves: Iterable[dict[str, Any]] | None = None,
    min_confidence: float = 0.25,
) -> dict[str, Any]:
    service_rows = [row for row in services or [] if isinstance(row, dict)]
    if cve_matches is None:
        if cves is None:
            match_rows: list[dict[str, Any]] = []
        else:
            match_rows = analyze_service_cves(service_rows, cves, min_confidence=min_confidence)["matches"]
    else:
        match_rows = [row for row in cve_matches if isinstance(row, dict)]

    service_index = {_service_key(row): row for row in service_rows}
    vulnerabilities = [
        correlate_vulnerability(match, service_index.get(_service_key(match), {}))
        for match in match_rows
    ]
    vulnerabilities = _dedupe(vulnerabilities)
    vulnerabilities.sort(key=lambda item: (-item["priority_score"], -severity_rank(item["severity"]), item["cve_id"]))
    return {
        "ok": True,
        "service_count": len(service_rows),
        "cve_match_count": len(match_rows),
        "vulnerability_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "model": "local_vulnerability_correlator",
    }


def correlate_vulnerability(match: dict[str, Any], service: dict[str, Any] | None = None) -> dict[str, Any]:
    service = service or {}
    target = str(match.get("target") or service.get("target") or service.get("host") or service.get("remote") or "-")
    port = match.get("port", service.get("port"))
    service_name = str(match.get("service") or service.get("service") or service.get("service_name") or "unknown")
    version = str(match.get("version") or service.get("version") or "")
    exposure = classify_exposure({**service, **match})
    indicators = exploitability_indicators(match, service)
    known_exploited = bool(match.get("known_exploited") or service.get("known_exploited"))
    ransomware = ransomware_association(match, service)
    priority_score = _priority_score(match, exposure, indicators, known_exploited, ransomware)
    priority = _priority_label(priority_score)
    cve_id = str(match.get("cve_id") or match.get("id") or "unknown").upper()
    finding = {
        "vulnerability_id": _vulnerability_id(target, port, service_name, cve_id),
        "target": target,
        "port": port,
        "service": service_name,
        "version": version,
        "cve_id": cve_id,
        "severity": str(match.get("severity") or "none").lower(),
        "cvss_score": _float(match.get("cvss_score")),
        "confidence": round(_float(match.get("confidence")), 2),
        "match_reasons": list(match.get("match_reasons") or []),
        "exposure": exposure,
        "known_exploited": known_exploited,
        "ransomware_association": ransomware["associated"],
        "ransomware_families": ransomware["families"],
        "exploitability_indicators": indicators,
        "priority": priority,
        "priority_score": priority_score,
        "explanation": _explanation(cve_id, service_name, version, exposure, indicators, known_exploited, ransomware, priority),
        "recommended_actions": _recommended_actions(exposure, known_exploited, ransomware, indicators),
        "evidence": _evidence(match, service),
        "automatic_changes": False,
    }
    return finding


def classify_exposure(row: dict[str, Any]) -> dict[str, Any]:
    state = str(row.get("state") or row.get("status") or row.get("tcp_state") or "").lower()
    host = str(
        row.get("bind_address")
        or row.get("local_address")
        or row.get("local_ip")
        or row.get("target")
        or ""
    ).strip("[]")
    classification = str(row.get("classification") or row.get("exposure") or row.get("interface_scope") or "").lower()
    is_open = state in {"open", "listening", "established"}
    all_interfaces = host in {"0.0.0.0", "::", "*"} or classification == "all_interfaces"
    public = classification in {"public", "public_interface", "internet_exposed"} or bool(row.get("public_exposed"))
    lan = classification in {"lan", "lan_interface"} or bool(row.get("lan_exposed"))
    if public:
        scope = "public"
    elif all_interfaces:
        scope = "all_interfaces"
    elif lan:
        scope = "lan"
    elif is_open:
        scope = "open"
    else:
        scope = "unknown"
    return {
        "state": state or "unknown",
        "scope": scope,
        "is_open": is_open,
        "all_interfaces": all_interfaces,
        "public": public,
        "lan": lan,
    }


def exploitability_indicators(match: dict[str, Any], service: dict[str, Any] | None = None) -> list[str]:
    service = service or {}
    text = " ".join(
        str(value)
        for value in [
            match.get("summary"),
            match.get("advisory"),
            " ".join(match.get("references") or []),
            " ".join(match.get("match_reasons") or []),
            service.get("banner"),
            service.get("evidence"),
        ]
        if value
    )
    indicators = [name for name, pattern in EXPLOITABILITY_PATTERNS if pattern.search(text)]
    if match.get("known_exploited") or service.get("known_exploited"):
        indicators.append("known_exploited")
    return sorted(set(indicators))


def ransomware_association(match: dict[str, Any], service: dict[str, Any] | None = None) -> dict[str, Any]:
    service = service or {}
    families = _string_list(match.get("ransomware_families") or service.get("ransomware_families"))
    tags = _string_list(match.get("tags") or service.get("tags"))
    text = " ".join(
        str(value)
        for value in [
            match.get("summary"),
            match.get("advisory"),
            " ".join(tags),
            " ".join(families),
        ]
        if value
    ).lower()
    associated = bool(match.get("ransomware_association") or service.get("ransomware_association") or families)
    if not associated:
        associated = any(marker in text for marker in RANSOMWARE_MARKERS)
    return {"associated": associated, "families": sorted(set(families))}


def _priority_score(
    match: dict[str, Any],
    exposure: dict[str, Any],
    indicators: list[str],
    known_exploited: bool,
    ransomware: dict[str, Any],
) -> float:
    base = max(_float(match.get("risk_score")), min(_float(match.get("cvss_score")) / 10.0, 1.0))
    if exposure["is_open"]:
        base += 0.05
    if exposure["all_interfaces"]:
        base += 0.08
    if exposure["public"]:
        base += 0.12
    if known_exploited:
        base += 0.16
    if ransomware["associated"]:
        base += 0.10
    high_impact = {"remote_code_execution", "authentication_bypass", "privilege_escalation"}
    if high_impact & set(indicators):
        base += 0.08
    elif indicators:
        base += 0.04
    if _float(match.get("confidence")) >= 0.85:
        base += 0.03
    return round(min(base, 1.0), 2)


def _priority_label(score: float) -> str:
    if score >= 0.9:
        return "critical"
    if score >= 0.7:
        return "high"
    if score >= 0.4:
        return "medium"
    return "low"


def _recommended_actions(
    exposure: dict[str, Any],
    known_exploited: bool,
    ransomware: dict[str, Any],
    indicators: list[str],
) -> list[str]:
    actions = ["validate_service_version", "review_vendor_patch_or_mitigation"]
    if exposure["public"] or exposure["all_interfaces"]:
        actions.append("review_exposure_and_access_controls")
    if known_exploited:
        actions.append("prioritize_known_exploited_vulnerability_review")
    if ransomware["associated"]:
        actions.append("check_ransomware_advisories_and_backup_posture")
    if "remote_code_execution" in indicators or "authentication_bypass" in indicators:
        actions.append("consider_temporary_compensating_controls_after_approval")
    return actions


def _explanation(
    cve_id: str,
    service_name: str,
    version: str,
    exposure: dict[str, Any],
    indicators: list[str],
    known_exploited: bool,
    ransomware: dict[str, Any],
    priority: str,
) -> str:
    parts = [f"{cve_id} matched {service_name}{(' ' + version) if version else ''}"]
    parts.append(f"exposure scope is {exposure['scope']}")
    if indicators:
        parts.append(f"indicators: {', '.join(indicators)}")
    if known_exploited:
        parts.append("known exploited evidence is present")
    if ransomware["associated"]:
        parts.append("ransomware association evidence is present")
    parts.append(f"priority is {priority}")
    return "; ".join(parts)


def _evidence(match: dict[str, Any], service: dict[str, Any]) -> dict[str, Any]:
    return {
        "match_reasons": list(match.get("match_reasons") or []),
        "summary": match.get("summary") or "",
        "service_state": service.get("state") or service.get("status") or match.get("state"),
        "service_confidence": service.get("confidence"),
        "cve_confidence": match.get("confidence"),
        "references": list(match.get("references") or [])[:10],
    }


def _service_key(row: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(row.get("target") or row.get("host") or row.get("remote") or "-"),
        str(row.get("port") or ""),
        str(row.get("service") or row.get("service_name") or "").lower(),
    )


def _dedupe(vulnerabilities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for item in vulnerabilities:
        key = item["vulnerability_id"]
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def _vulnerability_id(target: str, port: Any, service: str, cve_id: str) -> str:
    seed = f"{target}:{port}:{service}:{cve_id}"
    return sha256(seed.encode("utf-8")).hexdigest()[:16]


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(item) for item in value if item not in {None, ""}]
    return [str(value)]


def _float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
