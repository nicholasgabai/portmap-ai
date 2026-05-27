import re

import pytest

from core_engine.telemetry import (
    DestinationLearningError,
    build_dns_destination_behavior_report,
    build_dns_visibility_report,
    build_live_telemetry_operator_summary,
    deterministic_dns_destination_behavior_json,
    safe_destination_domain_summary,
)


GENERATED_AT = "2026-01-01T00:30:00+00:00"

PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
    re.compile("/" + "home/"),
    re.compile("/" + "Users/"),
    re.compile(r"BEGIN [A-Z ]*PRIVATE KEY"),
]


def _queries(domain: str = "service.example.test", *, resolver: str = "203.0.113.53", count: int = 4):
    return [
        {
            "query_id": f"q-{index}",
            "query_name": domain,
            "query_type": "A",
            "timestamp": f"2026-01-01T00:2{index}:00+00:00",
            "resolver_ip": resolver,
            "transport_protocol": "udp",
            "source_refs": [f"fixture:dns-query:{index}"],
        }
        for index in range(count)
    ]


def _responses(domain: str = "service.example.test", *, count: int = 4, code: str = "NOERROR"):
    return [
        {
            "query_id": f"q-{index}",
            "query_name": domain,
            "query_type": "A",
            "timestamp": f"2026-01-01T00:2{index}:01+00:00",
            "resolver_ip": "203.0.113.53",
            "response_code": code,
            "answers": [] if code != "NOERROR" else [{"answer_type": "A", "value": "198.51.100.20", "ttl": 120}],
            "source_refs": [f"fixture:dns-response:{index}"],
        }
        for index in range(count)
    ]


def _visibility(domain: str = "service.example.test", *, resolver: str = "203.0.113.53", count: int = 4):
    return build_dns_visibility_report(
        queries=_queries(domain=domain, resolver=resolver, count=count),
        responses=_responses(domain=domain, count=count),
        enriched_flows=[],
        generated_at=GENERATED_AT,
    )


def test_learns_recurring_stable_destination_behavior():
    report = build_dns_destination_behavior_report(
        dns_visibility_report=_visibility(),
        generated_at=GENERATED_AT,
    )
    profile = report["profiles"][0]

    assert report["record_type"] == "dns_destination_behavior_report"
    assert report["summary"]["destination_count"] == 1
    assert report["summary"]["stable_destination_count"] == 1
    assert profile["behavior_state"] == "stable"
    assert "stable_destination_behavior" in profile["classification_labels"]
    assert profile["confidence"] >= 0.8
    assert report["raw_payload_stored"] is False
    assert report["raw_dns_payloads_stored"] is False
    assert report["external_reputation_calls"] is False
    assert report["user_deanonymization"] is False


def test_detects_unusual_resolver_behavior():
    visibility = build_dns_visibility_report(
        queries=[
            *_queries(count=1, resolver="203.0.113.53"),
            *_queries(count=1, resolver="198.51.100.53"),
        ],
        responses=_responses(count=2),
        generated_at=GENERATED_AT,
    )
    report = build_dns_destination_behavior_report(dns_visibility_report=visibility, generated_at=GENERATED_AT)

    assert report["summary"]["unusual_resolver_count"] == 1
    assert "unusual_resolver_behavior" in report["profiles"][0]["classification_labels"]
    assert report["dashboard_status"]["status"] == "review_required"


def test_detects_dormant_destination_return_and_drift():
    first = build_dns_destination_behavior_report(dns_visibility_report=_visibility(), generated_at=GENERATED_AT)
    previous = dict(first["destinations"][0])
    previous["dormant"] = True
    previous["behavior_state"] = "dormant"
    previous["resolver_summary"] = {
        **previous["resolver_summary"],
        "resolver_hashes": ["previous-resolver-hash"],
    }
    second = build_dns_destination_behavior_report(
        dns_visibility_report=_visibility(resolver="198.51.100.53"),
        previous_destinations=[previous],
        generated_at="2026-01-01T01:00:00+00:00",
    )
    profile = second["profiles"][0]

    assert "dormant_destination_returned" in profile["classification_labels"]
    assert "destination_drift_detected" in profile["classification_labels"]
    assert second["summary"]["dormant_return_count"] == 1
    assert second["summary"]["drift_count"] == 1


def test_redaction_and_hashing_are_export_safe():
    summary = safe_destination_domain_summary("very-sensitive-service.example.test", hash_domain=True)
    report = build_dns_destination_behavior_report(
        dns_visibility_report=_visibility(domain="very-sensitive-service.example.test"),
        generated_at=GENERATED_AT,
        hash_domains=True,
    )
    report_json = deterministic_dns_destination_behavior_json(report)

    assert summary["display_domain"] == "<hashed-domain>"
    assert summary["domain_hash"]
    assert summary["raw_domain_stored"] is False
    assert "very-sensitive-service.example.test" not in report_json
    assert "<hashed-domain>" in report_json


def test_malformed_input_and_invalid_bounds_are_safe():
    report = build_dns_destination_behavior_report(dns_visibility_report=None, generated_at=GENERATED_AT)

    assert report["summary"]["destination_count"] == 0
    assert report["dashboard_status"]["status"] == "ok"
    with pytest.raises(DestinationLearningError):
        build_dns_destination_behavior_report(dns_visibility_report=_visibility(), max_destinations=0)


def test_bounds_destination_retention():
    visibility = build_dns_visibility_report(
        queries=[
            *_queries("alpha.example.test", count=1),
            *_queries("beta.example.test", count=1),
            *_queries("gamma.example.test", count=1),
        ],
        responses=[
            *_responses("alpha.example.test", count=1),
            *_responses("beta.example.test", count=1),
            *_responses("gamma.example.test", count=1),
        ],
        generated_at=GENERATED_AT,
    )
    report = build_dns_destination_behavior_report(
        dns_visibility_report=visibility,
        generated_at=GENERATED_AT,
        max_destinations=2,
    )

    assert len(report["destinations"]) == 2
    assert all(row["bounded_retention_applied"] is True for row in report["destinations"])


def test_operator_summary_and_serialization_are_safe_and_deterministic():
    report = build_dns_destination_behavior_report(dns_visibility_report=_visibility(), generated_at=GENERATED_AT)
    operator = build_live_telemetry_operator_summary(dns_destination_behavior_report=report, generated_at=GENERATED_AT)
    report_json = deterministic_dns_destination_behavior_json(report)

    assert operator["panels"]["dns_destination_behavior"]["metrics"]["destination_count"] == report["summary"]["destination_count"]
    assert operator["summary"]["dns_destination_behavior_count"] == report["summary"]["destination_count"]
    assert report["export_summary"]["digest"].startswith("sha256:")
    assert report_json == deterministic_dns_destination_behavior_json(report)
    assert '"raw_payload_stored":false' in report_json
    assert "service.example.test" not in report_json
    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(report_json)
