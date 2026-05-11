from __future__ import annotations

import ipaddress
from hashlib import sha256
from typing import Any, Iterable


DEFAULT_POLICY = {
    "management_ports": [22, 445, 3389, 5900, 5985, 5986],
    "database_ports": [1433, 1521, 3306, 5432, 6379, 9200, 27017],
    "high_payload_bytes": 1_048_576,
    "review_unknown_services": True,
    "review_public_endpoints": True,
    "require_approval": True,
}


def build_visibility_report(
    *,
    assets: Iterable[dict[str, Any]] | None = None,
    services: Iterable[dict[str, Any]] | None = None,
    flows: Iterable[dict[str, Any]] | dict[str, Any] | None = None,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build an offline visibility report from local observability evidence."""
    effective_policy = normalize_visibility_policy(policy)
    asset_rows = _rows(assets)
    service_rows = _rows(services)
    flow_rows = _flow_rows(flows)

    findings: list[dict[str, Any]] = []
    findings.extend(_asset_findings(asset_rows))
    findings.extend(_service_findings(service_rows, effective_policy))
    findings.extend(_flow_findings(flow_rows, effective_policy))
    response_workflows = [_workflow_from_finding(item, effective_policy) for item in findings if item["severity"] in {"high", "critical"}]

    return {
        "ok": True,
        "summary": _summary(asset_rows, service_rows, flow_rows, findings, response_workflows),
        "categories": {
            "assets": _asset_summary(asset_rows),
            "services": _service_summary(service_rows),
            "flows": _flow_summary(flow_rows),
            "response_workflows": {
                "approval_required": sum(1 for item in response_workflows if item["approval_required"]),
                "draft_count": len(response_workflows),
            },
        },
        "findings": findings,
        "response_workflows": response_workflows,
        "policy": effective_policy,
        "automatic_changes": False,
        "administrator_controlled": True,
        "raw_payload_stored": False,
    }


def normalize_visibility_policy(policy: dict[str, Any] | None = None) -> dict[str, Any]:
    merged = dict(DEFAULT_POLICY)
    if policy:
        merged.update({key: value for key, value in policy.items() if value is not None})
    merged["management_ports"] = _normalize_ports(merged.get("management_ports"))
    merged["database_ports"] = _normalize_ports(merged.get("database_ports"))
    merged["high_payload_bytes"] = max(0, int(merged.get("high_payload_bytes") or 0))
    merged["review_unknown_services"] = bool(merged.get("review_unknown_services", True))
    merged["review_public_endpoints"] = bool(merged.get("review_public_endpoints", True))
    merged["require_approval"] = bool(merged.get("require_approval", True))
    return merged


def _rows(value: Iterable[dict[str, Any]] | None) -> list[dict[str, Any]]:
    return [item for item in value or [] if isinstance(item, dict)]


def _flow_rows(value: Iterable[dict[str, Any]] | dict[str, Any] | None) -> list[dict[str, Any]]:
    if isinstance(value, dict):
        return _rows(value.get("flows") if isinstance(value.get("flows"), list) else [])
    return _rows(value)


def _normalize_ports(value: Any) -> list[int]:
    ports: list[int] = []
    seen: set[int] = set()
    for raw in value or []:
        port = int(raw)
        if not 1 <= port <= 65535:
            raise ValueError(f"visibility policy port must be between 1 and 65535: {raw}")
        if port not in seen:
            seen.add(port)
            ports.append(port)
    return ports


def _asset_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = {"reachable": 0, "unreachable": 0, "unknown": 0}
    methods: dict[str, int] = {}
    for row in rows:
        status = str(row.get("status") or "unknown")
        statuses[status if status in statuses else "unknown"] += 1
        for method in row.get("methods") or []:
            methods[str(method)] = methods.get(str(method), 0) + 1
    return {
        "asset_count": len(rows),
        "statuses": statuses,
        "methods": dict(sorted(methods.items())),
    }


def _service_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_service: dict[str, int] = {}
    open_count = 0
    for row in rows:
        if row.get("state") == "open":
            open_count += 1
            name = str(row.get("service") or "unknown")
            by_service[name] = by_service.get(name, 0) + 1
    return {
        "service_count": len(rows),
        "open_services": open_count,
        "by_service": dict(sorted(by_service.items())),
        "unknown_open_services": sum(1 for row in rows if row.get("state") == "open" and str(row.get("service") or "unknown").lower() == "unknown"),
    }


def _flow_summary(rows: list[dict[str, Any]]) -> dict[str, Any]:
    app_counts: dict[str, int] = {}
    external = 0
    for row in rows:
        for app in row.get("application_protocols") or []:
            app_counts[str(app)] = app_counts.get(str(app), 0) + 1
        endpoints = [row.get("initiator") or {}, row.get("responder") or {}]
        if any(_is_public_ip(str(endpoint.get("ip") or "")) for endpoint in endpoints):
            external += 1
    return {
        "flow_count": len(rows),
        "external_flow_count": external,
        "application_protocols": dict(sorted(app_counts.items())),
        "payload_bytes": sum(int(row.get("payload_bytes") or 0) for row in rows),
    }


def _summary(
    assets: list[dict[str, Any]],
    services: list[dict[str, Any]],
    flows: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    workflows: list[dict[str, Any]],
) -> dict[str, Any]:
    severity_counts: dict[str, int] = {}
    for finding in findings:
        severity = str(finding.get("severity") or "info")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    return {
        "asset_count": len(assets),
        "service_count": len(services),
        "flow_count": len(flows),
        "finding_count": len(findings),
        "severity_counts": dict(sorted(severity_counts.items())),
        "response_workflow_count": len(workflows),
    }


def _asset_findings(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for row in rows:
        status = str(row.get("status") or "unknown")
        if status not in {"unreachable", "unknown"}:
            continue
        findings.append(_finding(
            category="asset",
            severity="medium" if status == "unreachable" else "low",
            finding_type=f"asset_{status}",
            target=str(row.get("host") or "unknown"),
            message=f"Asset inventory marked host as {status}.",
            evidence={"methods": row.get("methods") or [], "target_source": row.get("target_source") or "unknown"},
            recommended_action="review_asset_inventory",
        ))
    return findings


def _service_findings(rows: list[dict[str, Any]], policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    management_ports = set(policy["management_ports"])
    database_ports = set(policy["database_ports"])
    for row in rows:
        if row.get("state") != "open":
            continue
        port = int(row.get("port") or 0)
        service = str(row.get("service") or "unknown")
        target = str(row.get("target") or row.get("remote") or "unknown")
        if port in management_ports:
            findings.append(_finding(
                category="service",
                severity="high",
                finding_type="management_service_open",
                target=target,
                message=f"Management service {service} is open on port {port}.",
                evidence={"port": port, "service": service, "confidence": row.get("confidence", 0)},
                recommended_action="review_access_policy",
            ))
        if port in database_ports:
            findings.append(_finding(
                category="service",
                severity="high",
                finding_type="database_service_open",
                target=target,
                message=f"Database or data service {service} is open on port {port}.",
                evidence={"port": port, "service": service, "confidence": row.get("confidence", 0)},
                recommended_action="review_service_exposure",
            ))
        if policy["review_unknown_services"] and service.lower() == "unknown":
            findings.append(_finding(
                category="service",
                severity="medium",
                finding_type="unknown_open_service",
                target=target,
                message=f"Open service on port {port} could not be identified confidently.",
                evidence={"port": port, "reason": row.get("reason") or "unknown"},
                recommended_action="collect_service_evidence",
            ))
        if policy["review_public_endpoints"] and _is_public_ip(target):
            findings.append(_finding(
                category="service",
                severity="medium",
                finding_type="public_service_endpoint",
                target=target,
                message=f"Open service {service} appears on a public endpoint.",
                evidence={"port": port, "service": service},
                recommended_action="verify_authorized_exposure",
            ))
    return findings


def _flow_findings(rows: list[dict[str, Any]], policy: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    high_payload_bytes = int(policy["high_payload_bytes"])
    for row in rows:
        flow_id = str(row.get("flow_id") or row.get("flow_key") or "unknown")
        payload_bytes = int(row.get("payload_bytes") or 0)
        if row.get("findings"):
            findings.append(_finding(
                category="flow",
                severity="high",
                finding_type="flow_security_findings",
                target=flow_id,
                message="Flow contains correlated protocol, DPI, or classifier findings.",
                evidence={"findings": row.get("findings") or [], "application_protocols": row.get("application_protocols") or []},
                recommended_action="review_flow_evidence",
            ))
        if high_payload_bytes and payload_bytes >= high_payload_bytes:
            findings.append(_finding(
                category="flow",
                severity="medium",
                finding_type="high_payload_volume",
                target=flow_id,
                message="Flow payload byte count crossed the configured review threshold.",
                evidence={"payload_bytes": payload_bytes, "threshold": high_payload_bytes},
                recommended_action="review_traffic_volume",
            ))
        endpoints = [row.get("initiator") or {}, row.get("responder") or {}]
        if policy["review_public_endpoints"] and any(_is_public_ip(str(endpoint.get("ip") or "")) for endpoint in endpoints):
            findings.append(_finding(
                category="flow",
                severity="medium",
                finding_type="external_flow_endpoint",
                target=flow_id,
                message="Flow includes a public endpoint and should be reviewed for expected egress or ingress.",
                evidence={"initiator": row.get("initiator") or {}, "responder": row.get("responder") or {}},
                recommended_action="verify_expected_peer",
            ))
    return findings


def _finding(
    *,
    category: str,
    severity: str,
    finding_type: str,
    target: str,
    message: str,
    evidence: dict[str, Any],
    recommended_action: str,
) -> dict[str, Any]:
    finding_id = sha256(f"{category}:{finding_type}:{target}:{message}".encode("utf-8")).hexdigest()[:16]
    return {
        "finding_id": finding_id,
        "category": category,
        "severity": severity,
        "type": finding_type,
        "target": target,
        "message": message,
        "evidence": evidence,
        "recommended_action": recommended_action,
    }


def _workflow_from_finding(finding: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    workflow_id = sha256(f"visibility:{finding['finding_id']}:{finding['recommended_action']}".encode("utf-8")).hexdigest()[:16]
    return {
        "workflow_id": workflow_id,
        "source_finding_id": finding["finding_id"],
        "action": finding["recommended_action"],
        "target": finding["target"],
        "reason": finding["message"],
        "approval_required": bool(policy["require_approval"]),
        "dry_run": True,
        "confirmed": False,
        "automatic_execution": False,
        "status": "pending_operator_review",
    }


def _is_public_ip(value: str) -> bool:
    host = value.rsplit(":", 1)[0] if value.count(":") == 1 and not value.startswith("[") else value.strip("[]")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


__all__ = ["DEFAULT_POLICY", "build_visibility_report", "normalize_visibility_policy"]
