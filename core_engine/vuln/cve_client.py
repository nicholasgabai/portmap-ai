from __future__ import annotations

from datetime import UTC, datetime
import json
import re
from typing import Any, Callable, Iterable
from urllib import parse, request

from core_engine.vuln.cvss import advisory_risk_score, extract_cvss, normalize_severity, severity_rank


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_FETCH_LIMIT = 50
MAX_FETCH_LIMIT = 2000

UrlOpen = Callable[..., Any]


def fetch_nvd_cves(
    *,
    keyword: str | None = None,
    cve_id: str | None = None,
    api_key: str | None = None,
    limit: int = DEFAULT_FETCH_LIMIT,
    start_index: int = 0,
    opener: UrlOpen = request.urlopen,
    timeout: float = 10.0,
) -> dict[str, Any]:
    if not keyword and not cve_id:
        raise ValueError("keyword or cve_id is required for NVD fetch")
    if limit < 1 or limit > MAX_FETCH_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_FETCH_LIMIT}")
    params: dict[str, Any] = {"resultsPerPage": int(limit), "startIndex": int(start_index)}
    if keyword:
        params["keywordSearch"] = keyword
    if cve_id:
        params["cveId"] = cve_id.upper()
    headers = {"User-Agent": "PortMap-AI/0.1 advisory-cve-client"}
    if api_key:
        headers["apiKey"] = api_key
    url = f"{NVD_API_URL}?{parse.urlencode(params)}"
    req = request.Request(url, headers=headers, method="GET")
    with opener(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    payload = json.loads(body) if body else {}
    records = [
        normalize_cve_record(item)
        for item in payload.get("vulnerabilities", [])
        if isinstance(item, dict)
    ]
    return {
        "ok": True,
        "source": "nvd",
        "query": {"keyword": keyword, "cve_id": cve_id, "limit": limit, "start_index": start_index},
        "fetched_at": datetime.now(UTC).isoformat(),
        "total_results": int(payload.get("totalResults") or len(records)),
        "record_count": len(records),
        "records": records,
    }


def load_cves_from_json(value: str) -> list[dict[str, Any]]:
    payload = json.loads(value)
    if isinstance(payload, dict):
        if isinstance(payload.get("records"), list):
            candidates = payload["records"]
        elif isinstance(payload.get("cves"), list):
            candidates = payload["cves"]
        elif isinstance(payload.get("vulnerabilities"), list):
            candidates = payload["vulnerabilities"]
        else:
            candidates = [payload]
    elif isinstance(payload, list):
        candidates = payload
    else:
        raise ValueError("CVE JSON must decode to an object, list, or NVD response")
    return [normalize_cve_record(item) for item in candidates if isinstance(item, dict)]


def normalize_cve_record(raw: dict[str, Any]) -> dict[str, Any]:
    cve = raw.get("cve") if isinstance(raw.get("cve"), dict) else raw
    cve_id = str(cve.get("id") or cve.get("cve_id") or raw.get("id") or raw.get("cve_id") or "").upper()
    descriptions = _descriptions(cve)
    cvss = extract_cvss(cve)
    if cvss["score"] == 0.0 and cve.get("cvss_score") is not None:
        try:
            cvss["score"] = float(cve.get("cvss_score") or 0)
        except (TypeError, ValueError):
            cvss["score"] = 0.0
        cvss["severity"] = normalize_severity(cve.get("severity") or cvss.get("severity"), score=cvss["score"])
    cpes = _extract_cpes(cve)
    cwes = _extract_cwes(cve)
    references = _extract_references(cve)
    known_exploited = bool(cve.get("known_exploited") or cve.get("cisa_known_exploited") or cve.get("kev"))
    ransomware_families = _string_list(cve.get("ransomware_families"))
    tags = _string_list(cve.get("tags"))
    ransomware_association = bool(cve.get("ransomware_association") or ransomware_families or any("ransom" in tag.lower() for tag in tags))
    severity = normalize_severity(cve.get("severity") or cvss.get("severity"), score=cvss.get("score"))
    return {
        "id": cve_id,
        "source": raw.get("sourceIdentifier") or cve.get("sourceIdentifier") or cve.get("source") or "",
        "published": raw.get("published") or cve.get("published") or "",
        "last_modified": raw.get("lastModified") or cve.get("lastModified") or cve.get("last_modified") or "",
        "descriptions": descriptions,
        "summary": descriptions[0] if descriptions else str(cve.get("summary") or ""),
        "cvss": cvss,
        "cvss_score": cvss["score"],
        "severity": severity,
        "cwes": cwes,
        "cpes": cpes,
        "references": references,
        "known_exploited": known_exploited,
        "ransomware_association": ransomware_association,
        "ransomware_families": ransomware_families,
        "tags": tags,
        "raw_payload_stored": False,
    }


def analyze_service_cves(
    services: Iterable[dict[str, Any]],
    cves: Iterable[dict[str, Any]],
    *,
    min_confidence: float = 0.25,
) -> dict[str, Any]:
    service_rows = [service for service in services if isinstance(service, dict)]
    cve_rows = [normalize_cve_record(cve) for cve in cves if isinstance(cve, dict)]
    matches: list[dict[str, Any]] = []
    for service in service_rows:
        matches.extend(match_service_to_cves(service, cve_rows, min_confidence=min_confidence))
    matches.sort(key=lambda item: (-item["risk_score"], -severity_rank(item["severity"]), item["cve_id"]))
    return {
        "ok": True,
        "service_count": len(service_rows),
        "cve_count": len(cve_rows),
        "match_count": len(matches),
        "matches": matches,
        "raw_payload_stored": False,
        "automatic_changes": False,
        "model": "local_cve_intelligence",
    }


def match_service_to_cves(
    service: dict[str, Any],
    cves: Iterable[dict[str, Any]],
    *,
    min_confidence: float = 0.25,
) -> list[dict[str, Any]]:
    service_name = str(service.get("service") or service.get("service_name") or service.get("name") or "").strip()
    version = str(service.get("version") or "").strip()
    target = str(service.get("target") or service.get("host") or service.get("remote") or "-")
    port = service.get("port")
    exposed = str(service.get("state") or service.get("status") or "").lower() in {"open", "listening"}
    results: list[dict[str, Any]] = []
    for raw_cve in cves:
        cve = normalize_cve_record(raw_cve)
        score, reasons, version_match = _match_confidence(service_name, version, cve)
        if score < min_confidence:
            continue
        risk_score = advisory_risk_score(
            cve.get("cvss_score"),
            exposed=exposed,
            known_exploited=bool(cve.get("known_exploited")),
            version_match=version_match,
        )
        results.append({
            "target": target,
            "port": port,
            "service": service_name or "unknown",
            "version": version,
            "cve_id": cve["id"],
            "severity": cve["severity"],
            "cvss_score": cve["cvss_score"],
            "risk_score": risk_score,
            "confidence": round(score, 2),
            "match_reasons": reasons,
            "known_exploited": bool(cve.get("known_exploited")),
            "ransomware_association": bool(cve.get("ransomware_association")),
            "ransomware_families": list(cve.get("ransomware_families") or []),
            "tags": list(cve.get("tags") or []),
            "summary": cve.get("summary") or "",
            "references": cve.get("references") or [],
            "advisory": _advisory_text(cve, service_name, version),
        })
    return results


def _match_confidence(service_name: str, version: str, cve: dict[str, Any]) -> tuple[float, list[str], bool]:
    service_tokens = _service_tokens(service_name)
    version_tokens = _version_tokens(version)
    haystack = " ".join(
        [
            cve.get("summary") or "",
            " ".join(cve.get("descriptions") or []),
            " ".join(cve.get("cpes") or []),
        ]
    ).lower()
    score = 0.0
    reasons: list[str] = []
    if service_tokens and any(token in haystack for token in service_tokens):
        score += 0.45
        reasons.append("service_name")
    cpe_matches = [cpe for cpe in cve.get("cpes") or [] if any(token in cpe.lower() for token in service_tokens)]
    if cpe_matches:
        score += 0.2
        reasons.append("cpe_service")
    version_match = bool(version_tokens and any(token in haystack for token in version_tokens))
    if version_match:
        score += 0.25
        reasons.append("version")
    if cve.get("id"):
        score += 0.05
    return min(score, 1.0), reasons or ["weak_keyword"], version_match


def _service_tokens(service_name: str) -> set[str]:
    aliases = {
        "http": {"http", "apache", "nginx", "iis", "httpd"},
        "https": {"https", "http", "apache", "nginx", "iis", "httpd"},
        "ssh": {"ssh", "openssh"},
        "smtp": {"smtp", "postfix", "sendmail", "exim"},
        "ftp": {"ftp", "vsftpd", "proftpd"},
        "smb": {"smb", "samba", "windows"},
        "rdp": {"rdp", "remote desktop"},
        "dns": {"dns", "bind"},
    }
    normalized = re.sub(r"[^a-z0-9]+", " ", service_name.lower()).strip()
    tokens = {token for token in normalized.split() if len(token) >= 2}
    for token in list(tokens):
        tokens.update(aliases.get(token, set()))
    return tokens


def _version_tokens(version: str) -> set[str]:
    return {token for token in re.findall(r"\d+(?:\.\d+){1,3}", version) if token}


def _descriptions(cve: dict[str, Any]) -> list[str]:
    values = cve.get("descriptions")
    if isinstance(values, list):
        rows = []
        for value in values:
            if isinstance(value, dict) and value.get("value"):
                rows.append(str(value["value"]))
            elif isinstance(value, str):
                rows.append(value)
        return rows
    summary = cve.get("summary") or cve.get("description")
    return [str(summary)] if summary else []


def _extract_cpes(cve: dict[str, Any]) -> list[str]:
    cpes: set[str] = set()
    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria") if isinstance(match, dict) else None
                if criteria:
                    cpes.add(str(criteria))
    for value in cve.get("cpes") or []:
        cpes.add(str(value))
    return sorted(cpes)


def _extract_cwes(cve: dict[str, Any]) -> list[str]:
    cwes: set[str] = set()
    for weakness in cve.get("weaknesses") or []:
        for description in weakness.get("description") or []:
            if isinstance(description, dict) and description.get("value"):
                cwes.add(str(description["value"]))
    for value in cve.get("cwes") or []:
        cwes.add(str(value))
    return sorted(cwes)


def _extract_references(cve: dict[str, Any]) -> list[str]:
    refs = cve.get("references", {})
    data = refs.get("referenceData") if isinstance(refs, dict) else refs
    urls: list[str] = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict) and item.get("url"):
                urls.append(str(item["url"]))
            elif isinstance(item, str):
                urls.append(item)
    return urls[:20]


def _string_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(item) for item in value if item not in {None, ""}]
    return [str(value)]


def _advisory_text(cve: dict[str, Any], service_name: str, version: str) -> str:
    version_text = f" {version}" if version else ""
    return (
        f"Review {service_name or 'service'}{version_text} exposure against {cve['id']} "
        f"and prioritize vendor patching or compensating controls."
    )
