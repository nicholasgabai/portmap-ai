from __future__ import annotations

import json
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Iterable

from core_engine.telemetry.dns_visibility import (
    DNS_VISIBILITY_RECORD_VERSION,
    DNS_VISIBILITY_SAFETY_FLAGS,
    build_dns_anomaly_hints,
    build_dns_query_record,
    build_dns_response_record,
    build_dns_timing_summary,
    build_dns_visibility_api_response,
    build_dns_visibility_dashboard_record,
    build_encrypted_dns_limitation_summary,
    classify_resolver,
    deterministic_dns_visibility_json,
    summarize_dns_visibility_records,
)


def build_dns_visibility_report(
    *,
    queries: Iterable[dict[str, Any]] | None = None,
    responses: Iterable[dict[str, Any]] | None = None,
    enriched_flows: Iterable[dict[str, Any]] | None = None,
    protocol_records: Iterable[dict[str, Any]] | None = None,
    generated_at: str | None = None,
    max_domain_length: int = 120,
) -> dict[str, Any]:
    timestamp = generated_at or _now()
    query_rows = [
        build_dns_query_record(row, generated_at=timestamp, max_domain_length=max_domain_length)
        for row in queries or []
        if isinstance(row, dict)
    ]
    response_rows = [
        build_dns_response_record(row, generated_at=timestamp, max_domain_length=max_domain_length)
        for row in responses or []
        if isinstance(row, dict)
    ]
    flow_rows = [dict(row) for row in enriched_flows or [] if isinstance(row, dict)]
    protocol_rows = [dict(row) for row in protocol_records or [] if isinstance(row, dict)]
    pairings = pair_dns_queries_and_responses(query_rows, response_rows)
    timing_summaries = [
        build_dns_timing_summary(query=pair.get("query"), response=pair.get("response"), generated_at=timestamp)
        for pair in pairings
    ]
    resolver_summaries = [
        classify_resolver(query=pair.get("query"), response=pair.get("response"))
        for pair in pairings
    ]
    correlations = correlate_domains_to_flows(responses=response_rows, enriched_flows=flow_rows, generated_at=timestamp)
    encrypted_limitations = build_encrypted_dns_limitation_summary(
        encrypted_flow_count=_encrypted_dns_flow_count(flow_rows, protocol_rows),
        encrypted_dns_records=[row for row in resolver_summaries if row.get("encrypted_dns_likely")],
        generated_at=timestamp,
    )
    hints = []
    for index, pair in enumerate(pairings):
        hints.extend(
            build_dns_anomaly_hints(
                query=pair.get("query"),
                response=pair.get("response"),
                timing=timing_summaries[index] if index < len(timing_summaries) else None,
                generated_at=timestamp,
            )
        )
    summary = summarize_dns_visibility_records(
        queries=query_rows,
        responses=response_rows,
        correlations=correlations,
        encrypted_limitations=encrypted_limitations,
        anomaly_hints=hints,
        generated_at=timestamp,
    )
    dashboard = build_dns_visibility_dashboard_record(summary=summary, queries=query_rows, responses=response_rows, anomaly_hints=hints, generated_at=timestamp)
    api = build_dns_visibility_api_response(
        summary=summary,
        queries=query_rows,
        responses=response_rows,
        correlations=correlations,
        timing_summaries=timing_summaries,
        encrypted_limitations=encrypted_limitations,
        anomaly_hints=hints,
        dashboard=dashboard,
        generated_at=timestamp,
    )
    return {
        "record_type": "dns_visibility_report",
        "record_version": DNS_VISIBILITY_RECORD_VERSION,
        "report_id": "dns-visibility-" + _digest({"generated_at": timestamp, "queries": [row.get("query_record_id") for row in query_rows], "responses": [row.get("response_record_id") for row in response_rows]})[:16],
        "generated_at": timestamp,
        "queries": query_rows,
        "responses": response_rows,
        "pairings": pairings,
        "timing_summaries": timing_summaries,
        "resolver_summaries": resolver_summaries,
        "domain_flow_correlations": correlations,
        "encrypted_dns_limitations": encrypted_limitations,
        "anomaly_hints": hints,
        "summary": summary,
        "dashboard_status": dashboard,
        "api_status": api,
        **DNS_VISIBILITY_SAFETY_FLAGS,
    }


def pair_dns_queries_and_responses(
    queries: Iterable[dict[str, Any]],
    responses: Iterable[dict[str, Any]],
) -> list[dict[str, Any]]:
    response_index = {}
    for response in responses or []:
        if isinstance(response, dict):
            response_index.setdefault(_pair_key(response), []).append(dict(response))
    pairs = []
    seen_responses = set()
    for query in queries or []:
        if not isinstance(query, dict):
            continue
        matches = response_index.get(_pair_key(query), [])
        response = matches.pop(0) if matches else None
        if response:
            seen_responses.add(str(response.get("response_record_id") or ""))
        pairs.append(
            {
                "record_type": "dns_query_response_pairing",
                "query": dict(query),
                "response": response,
                "status": "paired" if response else "query_only",
                **DNS_VISIBILITY_SAFETY_FLAGS,
            }
        )
    for response in responses or []:
        if isinstance(response, dict) and str(response.get("response_record_id") or "") not in seen_responses:
            pairs.append(
                {
                    "record_type": "dns_query_response_pairing",
                    "query": None,
                    "response": dict(response),
                    "status": "response_only",
                    **DNS_VISIBILITY_SAFETY_FLAGS,
                }
            )
    return pairs


def correlate_domains_to_flows(
    *,
    responses: Iterable[dict[str, Any]],
    enriched_flows: Iterable[dict[str, Any]],
    generated_at: str | None = None,
) -> list[dict[str, Any]]:
    timestamp = generated_at or _now()
    flow_rows = [dict(row) for row in enriched_flows or [] if isinstance(row, dict)]
    records = []
    for response in responses or []:
        if not isinstance(response, dict):
            continue
        answer_value_set = {str(answer.get("value") or "") for answer in response.get("answers") or [] if isinstance(answer, dict)}
        answer_values = sorted(answer_value_set)
        matches = []
        for flow in flow_rows:
            endpoints = _flow_endpoint_values(flow)
            if answer_value_set and answer_value_set.intersection(endpoints):
                matches.append(flow)
        record = {
            "record_type": "domain_flow_correlation",
            "record_version": DNS_VISIBILITY_RECORD_VERSION,
            "generated_at": timestamp,
            "query_name": str(response.get("query_name") or ""),
            "query_ref": str(response.get("query_id") or ""),
            "response_ref": str(response.get("response_record_id") or ""),
            "answer_values": sorted(answer_values),
            "matched_flow_refs": sorted(str(row.get("flow_ref") or "") for row in matches),
            "status": "matched" if matches else "unmatched",
            "confidence": 0.85 if matches else 0.2,
            **DNS_VISIBILITY_SAFETY_FLAGS,
        }
        record["correlation_id"] = "dns-flow-correlation-" + _digest(record)[:16]
        records.append(record)
    return sorted(records, key=lambda item: (str(item.get("query_name") or ""), str(item.get("response_ref") or "")))


def deterministic_dns_correlation_json(record: dict[str, Any]) -> str:
    return deterministic_dns_visibility_json(record)


def _encrypted_dns_flow_count(flows: list[dict[str, Any]], protocol_records: list[dict[str, Any]]) -> int:
    count = 0
    for flow in flows:
        service = flow.get("service_port_hint") if isinstance(flow.get("service_port_hint"), dict) else {}
        if str(service.get("service_name") or "") == "dns-over-tls" or service.get("service_port") == 853:
            count += 1
    for record in protocol_records:
        selected = record.get("selected_metadata") if isinstance(record.get("selected_metadata"), dict) else {}
        if str(record.get("protocol") or "") == "tls" and str(selected.get("protocol") or "") == "tls":
            service = record.get("protocol_fingerprint", {}).get("service_association", {}) if isinstance(record.get("protocol_fingerprint"), dict) else {}
            if service.get("service_port") == 853:
                count += 1
    return count


def _flow_endpoint_values(flow: dict[str, Any]) -> set[str]:
    values = set()
    for field_name in ("initiator", "responder"):
        endpoint = flow.get(field_name) if isinstance(flow.get(field_name), dict) else {}
        if endpoint.get("ip"):
            values.add(str(endpoint["ip"]))
    endpoint_classification = flow.get("endpoint_classification") if isinstance(flow.get("endpoint_classification"), dict) else {}
    for field_name in ("initiator", "responder"):
        endpoint = endpoint_classification.get(field_name) if isinstance(endpoint_classification.get(field_name), dict) else {}
        if endpoint.get("ip"):
            values.add(str(endpoint["ip"]))
    return values


def _pair_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record.get("query_id") or ""),
        str(record.get("query_name") or ""),
        str(record.get("query_type") or ""),
    )


def _digest(payload: Any) -> str:
    material = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(UTC).isoformat()
