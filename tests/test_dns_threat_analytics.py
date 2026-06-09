import json

from core_engine.intelligence import (
    analyze_domain_pattern,
    analyze_domain_patterns,
    build_dns_analytics,
    build_ioc_inventory,
    build_ioc_record,
    build_resolver_behavior_summary,
    empty_dns_analytics,
    hash_domain,
    normalize_domain,
)


T1 = "2026-01-01T00:00:00+00:00"
T2 = "2026-01-01T00:05:00+00:00"


def test_domain_normalization_hashing_and_preview_redaction():
    patterns = analyze_domain_pattern(
        {"domain": "HTTPS://Example.TEST/path", "source_mode": "live", "timestamp": T1},
        baseline_domains=["example.test"],
        generated_at=T1,
    )
    payload = patterns[0].to_dict()

    assert normalize_domain("Example.TEST.") == "example.test"
    assert patterns[0].normalized_domain == "example.test"
    assert payload["normalized_domain_hash"] == hash_domain("example.test")
    assert payload["domain_preview"].startswith("domain:")
    assert "example.test" not in json.dumps(payload, sort_keys=True)
    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False


def test_high_entropy_label_detection():
    patterns = analyze_domain_pattern(
        {"domain": "q9x8z7v6b5n4m3p2r1s0.example.test", "source_mode": "fixture", "timestamp": T1},
        baseline_domains=["example.test"],
        generated_at=T1,
    )
    states = {pattern.to_dict()["pattern_type"]: pattern.to_dict()["pattern_state"] for pattern in patterns}

    assert states["high_entropy_label"] == "review_recommended"


def test_long_domain_detection():
    long_label = "a" * 45
    patterns = analyze_domain_pattern(
        {"domain": f"{long_label}.example.test", "source_mode": "fixture", "timestamp": T1},
        baseline_domains=["example.test"],
        generated_at=T1,
    )

    assert "long_domain" in {pattern.to_dict()["pattern_type"] for pattern in patterns}


def test_suspicious_tld_detection():
    patterns = analyze_domain_pattern(
        {"domain": "review-target.zip", "source_mode": "fixture", "timestamp": T1},
        baseline_domains=[],
        generated_at=T1,
    )
    payloads = [pattern.to_dict() for pattern in patterns]

    suspicious = [payload for payload in payloads if payload["pattern_type"] == "suspicious_tld"][0]
    assert suspicious["pattern_state"] == "review_recommended"


def test_repeated_subdomain_detection():
    patterns = analyze_domain_pattern(
        {"domain": "a.a.a.example.test", "source_mode": "fixture", "timestamp": T1},
        baseline_domains=["example.test"],
        generated_at=T1,
    )

    assert "repeated_subdomain" in {pattern.to_dict()["pattern_type"] for pattern in patterns}


def test_dns_tunneling_candidate_heuristic():
    encoded = "q9x8z7v6b5n4m3p2r1s0q9x8z7v6b5n4m3p2r1s0"
    patterns = analyze_domain_pattern(
        {"domain": f"{encoded}.chunk.one.two.example.test", "query_type": "TXT", "source_mode": "fixture", "timestamp": T1},
        baseline_domains=["example.test"],
        generated_at=T1,
    )
    payloads = [pattern.to_dict() for pattern in patterns]

    tunnel = [payload for payload in payloads if payload["pattern_type"] == "dns_tunneling_candidate"][0]
    assert tunnel["pattern_state"] == "review_recommended"
    assert tunnel["confidence_score"] > 0.8


def test_resolver_behavior_summary_sanitizes_resolvers():
    summary = build_resolver_behavior_summary(
        [
            {"domain": "one.example.test", "resolver_reference": "resolver-alpha", "source_mode": "live"},
            {"domain": "two.example.test", "resolver_reference": "resolver-beta", "source_mode": "live"},
        ]
    )
    encoded = json.dumps(summary, sort_keys=True)

    assert summary["resolver_count"] == 2
    assert summary["resolver_change_detected"] is True
    assert "resolver-alpha" not in encoded
    assert "resolver-beta" not in encoded
    assert summary["raw_resolvers_exported"] is False


def test_ioc_match_integration_sets_review_state():
    ioc = build_ioc_record("example.test", ioc_type="domain", source_category="dns", source_mode="fixture", first_seen=T1)
    inventory = build_ioc_inventory([ioc], generated_at=T1)
    record = build_dns_analytics(
        [{"domain": "example.test", "source_mode": "live", "timestamp": T1, "candidate_reference": "dns-observation-one"}],
        ioc_inventory=inventory,
        generated_at=T2,
    )
    payload = record.to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["analytics_state"] == "review_recommended"
    assert payload["ioc_match_count"] == 1
    assert payload["ioc_match_summary"]["matched_count"] == 1
    assert payload["recommended_next_step"] == "review_dns_ioc_matches"
    assert "example.test" not in encoded


def test_dns_analytics_state_transitions():
    normal = build_dns_analytics(
        [{"domain": "stable.example.test", "source_mode": "live", "timestamp": T1}],
        domain_patterns=[],
        generated_at=T1,
    ).to_dict()
    noteworthy = build_dns_analytics(
        [{"domain": "new.example.test", "source_mode": "live", "timestamp": T1}],
        generated_at=T1,
    ).to_dict()
    review = build_dns_analytics(
        [{"domain": "review-target.zip", "source_mode": "fixture", "timestamp": T1}],
        generated_at=T1,
    ).to_dict()

    assert normal["analytics_state"] == "normal"
    assert noteworthy["analytics_state"] == "noteworthy"
    assert review["analytics_state"] == "review_recommended"
    assert review["highest_severity"] == "high"


def test_empty_and_degraded_behavior():
    empty = empty_dns_analytics(generated_at=T1).to_dict()
    degraded = build_dns_analytics([object()], generated_at=T1).to_dict()

    assert empty["analytics_state"] == "empty"
    assert empty["query_count"] == 0
    assert degraded["analytics_state"] == "degraded"
    assert degraded["query_count"] == 0


def test_safety_flags_no_verdicts_or_raw_dns_history():
    patterns = analyze_domain_patterns(
        [{"domain": "internal.example.test", "source_mode": "live", "timestamp": T1}],
        generated_at=T1,
    )
    payload = build_dns_analytics(
        [{"domain": "internal.example.test", "resolver_reference": "resolver-alpha", "source_mode": "live", "timestamp": T1}],
        domain_patterns=patterns,
        generated_at=T2,
    ).to_dict()
    encoded = json.dumps(payload, sort_keys=True)

    assert payload["preview_only"] is True
    assert payload["destructive_action"] is False
    assert payload["external_lookup_performed"] is False
    assert payload["raw_dns_history_stored"] is False
    assert "threat_verdict" not in encoded
    assert "malicious" not in encoded
    assert "internal.example.test" not in encoded
    assert "resolver-alpha" not in encoded


def test_malformed_input_and_source_mode_preservation():
    patterns = analyze_domain_patterns([object(), {"domain": "source.example.test", "source_mode": "replay", "timestamp": T1}], generated_at=T1)
    payloads = [pattern.to_dict() for pattern in patterns]
    analytics = build_dns_analytics(
        [{"domain": "source.example.test", "source_mode": "replay", "timestamp": T1}],
        domain_patterns=patterns,
        generated_at=T2,
    ).to_dict()

    assert any(payload["pattern_state"] == "degraded" for payload in payloads)
    assert "replay" in analytics["source_modes"]
    assert analytics["preview_only"] is True
    assert analytics["destructive_action"] is False
