import json

import pytest

from core_engine.attribution import (
    ApplicationAttributionError,
    SignatureLearningError,
    append_learning_profile_history,
    build_application_attribution_report,
    build_behavioral_signature_record,
    build_learning_profile,
    build_learning_profile_history,
    build_probable_application_attributions,
    build_probabilistic_application_model,
    build_signature_learning_report,
    deterministic_application_attribution_json,
    deterministic_confidence_json,
    deterministic_learning_profile_json,
    deterministic_probabilistic_application_model_json,
    deterministic_signature_json,
    load_learning_profile_histories,
    load_learning_profiles,
    save_learning_profile_histories,
    save_learning_profiles,
    score_application_attribution_confidence,
    summarize_learning_profile_history,
    update_learning_profile,
    update_learning_profile_histories,
    update_learning_profile_history_store,
    update_learning_profile_store,
    update_learning_profiles,
)


FIXED_TIME = "2026-01-01T00:00:00+00:00"


def _observation(**overrides):
    base = {
        "observed_entity_reference": "session-redacted-001",
        "process_hint": "browser-client",
        "service_hint": "https",
        "protocol_hint": "tls",
        "destination_behavior_hint": "redacted_destination",
        "flow_behavior_hint": "recurring",
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def _signature(**overrides):
    base = {
        "signature_class": "process_service_pattern",
        "process_hint": "browser-client",
        "service_hint": "https",
        "protocol_hint": "tls",
        "destination_behavior_hint": "redacted_destination",
        "flow_behavior_hint": "recurring",
        "observation_count": 8,
        "stable_behavior": True,
        "source_mode": "live",
    }
    base.update(overrides)
    return base


def _candidate_probability(record, candidate):
    for row in record["candidates"]:
        if row["candidate"] == candidate:
            return float(row["probability"])
    return 0.0


def _candidate(record, candidate):
    for row in record["candidates"]:
        if row["candidate"] == candidate:
            return row
    raise AssertionError(candidate)


def test_probable_app_attribution_generation_and_candidate_ranking():
    signatures = [build_behavioral_signature_record(_signature(), generated_at=FIXED_TIME)]
    rows = build_probable_application_attributions(
        _observation(),
        signatures=signatures,
        generated_at=FIXED_TIME,
    )

    assert len(rows) >= 2
    assert rows[0]["candidate_app_class"] == "browser_or_web_client"
    assert rows[0]["candidate_service_class"] == "web_service"
    assert rows[0]["attribution_state"] in {"attributed", "probable"}
    assert rows[0]["confidence_score"] >= rows[-1]["confidence_score"]
    assert rows[0]["source_mode"] == "live"
    assert rows[0]["raw_payload_stored"] is False
    assert rows[0]["pcap_generated"] is False
    assert rows[0]["raw_dns_history_stored"] is False


def test_multiple_candidates_include_destination_and_recurring_signature_hints():
    report = build_application_attribution_report(
        [
            _observation(
                observed_entity_reference="session-redacted-002",
                service_hint="dns",
                protocol_hint="udp",
                destination_behavior_hint="resolver_behavior",
                flow_behavior_hint="recurring",
            )
        ],
        signature_observations=[_signature(signature_class="destination_pattern", service_hint="dns", protocol_hint="udp")],
        generated_at=FIXED_TIME,
    )
    classes = {row["candidate_app_class"] for row in report["attributions"]}

    assert "name_resolution_client" in classes
    assert "recurring_application_behavior" in classes
    assert report["summary"]["attribution_count"] >= 2
    assert report["dashboard_status"]["panel"] == "dynamic_application_attribution"
    assert report["api_status"]["summary"]["source_modes"] == ["live"]


def test_unknown_unattributed_live_observation_remains_unresolved():
    rows = build_probable_application_attributions(
        {
            "observed_entity_reference": "session-redacted-003",
            "process_hint": "",
            "service_hint": "",
            "protocol_hint": "",
            "destination_behavior_hint": "",
            "flow_behavior_hint": "",
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert len(rows) == 1
    assert rows[0]["candidate_app_class"] == "Unknown"
    assert rows[0]["candidate_service_class"] == "Unattributed"
    assert rows[0]["attribution_state"] == "unattributed"
    assert "dummy_app" not in deterministic_application_attribution_json(rows[0])
    assert "dummy_db" not in deterministic_application_attribution_json(rows[0])


def test_probabilistic_application_model_ranks_candidates_from_existing_metadata():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-nginx",
            "program": "nginx",
            "service_name": "https",
            "protocol": "tls",
            "port": 443,
            "status": "LISTEN",
            "score_factors": ["sensitive_port:443"],
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert record["record_type"] == "probabilistic_application_model"
    assert record["top_classification"] == "nginx"
    assert record["confidence"] > 0.0
    assert record["candidate_count"] >= 3
    assert {row["candidate"] for row in record["candidates"]} >= {"nginx", "https_service", "unknown_proxy"}
    assert record["evidence_count"] >= 5
    assert "port:443" in record["evidence_signals"]
    assert record["training_performed"] is False
    assert record["inference_executed"] is False
    assert record["automated_action"] is False
    assert record["raw_payload_stored"] is False
    assert record["pcap_generated"] is False


@pytest.mark.parametrize(
    ("expected", "observation"),
    [
        (
            "caddy",
            {
                "program": "caddy",
                "service_name": "https",
                "protocol": "tls",
                "port": 443,
            },
        ),
        (
            "mariadb",
            {
                "process": "mariadbd",
                "service_name": "mariadb",
                "protocol": "mysql",
                "port": 3306,
            },
        ),
        (
            "mongodb",
            {
                "process": "mongod",
                "service_name": "mongodb",
                "port": 27017,
            },
        ),
        (
            "grafana",
            {
                "program": "grafana-server",
                "service_name": "grafana",
                "port": 3000,
            },
        ),
        (
            "docker",
            {
                "process": "dockerd",
                "service_fingerprint": "docker engine api",
                "port": 2375,
            },
        ),
        (
            "kubernetes",
            {
                "process": "kubelet",
                "service_name": "kubernetes",
                "port": 10250,
            },
        ),
        (
            "rdp",
            {
                "service_name": "rdp",
                "protocol": "rdp",
                "port": 3389,
            },
        ),
        (
            "smtp",
            {
                "process": "postfix",
                "protocol": "smtp",
                "port": 25,
            },
        ),
    ],
)
def test_probabilistic_application_catalog_expansion_classifies_common_services(expected, observation):
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": f"session-redacted-{expected}",
            "source_mode": "live",
            **observation,
        },
        generated_at=FIXED_TIME,
    )

    assert record["top_classification"] == expected
    assert record["confidence"] > 0.25
    assert record["alternative_candidates"]
    assert record["evidence_count"] >= 2
    assert record["training_performed"] is False
    assert record["inference_executed"] is False


def test_probabilistic_application_catalog_uses_fingerprint_signals_as_metadata_evidence():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-prometheus",
            "service_fingerprint": "prometheus metrics endpoint",
            "port": 9090,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert record["top_classification"] == "prometheus"
    assert record["confidence"] > 0.4
    assert "observability_service" in {row["candidate"] for row in record["alternative_candidates"]}
    assert "prometheus_metrics_endpoint" in record["evidence_signals"]


def test_probabilistic_application_catalog_reports_ambiguous_web_candidates_without_overconfidence():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-ambiguous-web",
            "protocol": "tls",
            "port": 443,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    candidates = {row["candidate"] for row in record["candidates"]}

    assert record["top_classification"] == "unknown_application"
    assert 0.2 <= record["confidence"] <= 0.6
    assert {"nginx", "apache", "caddy", "unknown_proxy"}.issubset(candidates)
    assert len(record["alternative_candidates"]) >= 3
    assert max(row["probability"] for row in record["candidates"] if row["candidate"] != "unknown_application") < 0.2
    assert record["evidence_signals"] == ["protocol:tls", "port:443"]
    assert record["calibration"]["evidence_strength"] == "weak"
    assert "generic_metadata_only" in record["calibration"]["factors"]


def test_probabilistic_application_preserves_candidate_reasoning_for_ambiguous_attribution():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-ambiguous-reasoning",
            "protocol": "tls",
            "port": 443,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    unknown = _candidate(record, "unknown_application")
    nginx = _candidate(record, "nginx")

    assert len(record["candidate_reasoning"]) == record["candidate_count"]
    assert unknown["supporting_evidence"] == ["protocol:tls", "port:443"]
    assert unknown["missing_evidence"] == ["process_match", "service_match", "fingerprint"]
    assert "generic metadata" in unknown["reasoning"]
    assert nginx["supporting_evidence"] == ["port:443"]
    assert {"process_match", "service_match", "fingerprint"}.issubset(set(nginx["missing_evidence"]))
    assert nginx["confidence_contribution"] == nginx["probability"]


def test_probabilistic_application_generates_missing_evidence_for_port_only_service_candidate():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-postgres-port-only",
            "port": 5432,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    postgresql = _candidate(record, "postgresql")

    assert postgresql["supporting_evidence"] == ["port:5432"]
    assert {"process_match", "service_match", "fingerprint", "protocol_context"}.issubset(
        set(postgresql["missing_evidence"])
    )
    assert "port:5432" in postgresql["reasoning"]
    assert record["top_classification"] == "unknown_application"


def test_probabilistic_application_unknown_candidates_explain_insufficient_metadata():
    record = build_probabilistic_application_model(
        {"observed_entity_reference": "session-redacted-unknown-reasoning", "source_mode": "live"},
        generated_at=FIXED_TIME,
    )
    unknown = _candidate(record, "unknown_application")
    insufficient = _candidate(record, "insufficient_metadata")
    unclassified = _candidate(record, "unclassified_service")

    assert unknown["supporting_evidence"] == ["insufficient_metadata"]
    assert {"process_match", "service_match", "fingerprint"}.issubset(set(unknown["missing_evidence"]))
    assert "not enough process" in insufficient["reasoning"]
    assert {"process_evidence", "service_evidence"}.issubset(set(insufficient["missing_evidence"]))
    assert unclassified["supporting_evidence"] == ["no_catalog_match"]
    assert record["confidence"] == unknown["confidence_contribution"]


def test_probabilistic_application_explainability_for_unknown_classification():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-unknown-explainability",
            "protocol": "tls",
            "port": 443,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert record["top_classification"] == "unknown_application"
    assert record["explanation_summary"] == (
        "Observed generic service metadata, but no strong process, service, or fingerprint match."
    )
    assert record["evidence_quality"] == "weak"
    assert record["confidence_rationale"] == (
        "Confidence is moderate-low because evidence is generic and alternatives remain plausible."
    )
    assert record["ambiguity_reason"] == "Multiple candidates remain because no unique application fingerprint was observed."
    assert record["missing_evidence_summary"] == "Missing process match, service match, service fingerprint."
    assert record["operator_next_steps"] == (
        "Review service name, process owner, expected-service allowlist, and historical observations."
    )


def test_probabilistic_application_explainability_for_strong_classification():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-postgresql-explainability",
            "program": "postgres",
            "service_name": "postgresql",
            "protocol": "tcp",
            "port": 5432,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert record["top_classification"] == "postgresql"
    assert record["explanation_summary"] == (
        "Classified as postgresql because multiple metadata signals corroborate the candidate."
    )
    assert record["evidence_quality"] == "strong"
    assert record["confidence_rationale"] == (
        "Confidence is high because process_match, service_match, port_support corroborate the classification."
    )
    assert record["ambiguity_reason"] == (
        "Alternative candidates survived because shared port, protocol, or generic service metadata also matched."
    )
    assert record["missing_evidence_summary"] == "Missing service fingerprint."
    assert record["operator_next_steps"] == "Review expected-service allowlist and historical observations for confirmation."


def test_learning_profile_creation_from_existing_metadata_only():
    model = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-profile-postgresql",
            "program": "postgres",
            "service_name": "postgresql",
            "protocol": "tcp",
            "port": 5432,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:05:00+00:00",
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    profile = model["learning_profile"]

    assert profile["record_type"] == "application_learning_profile"
    assert profile["profile_name"] == "postgresql"
    assert profile["first_seen"] == "2026-01-01T00:00:00+00:00"
    assert profile["last_seen"] == "2026-01-01T00:05:00+00:00"
    assert profile["observation_count"] == 1
    assert profile["observed_ports"] == [5432]
    assert profile["observed_protocols"] == ["tcp"]
    assert profile["observed_services"] == ["postgresql"]
    assert profile["observed_processes"] == ["postgres"]
    assert profile["confidence_history"] == [
        {
            "observed_at": FIXED_TIME,
            "classification": "postgresql",
            "confidence": model["confidence"],
        }
    ]
    assert 0.0 < profile["stability_score"] <= 1.0
    assert profile["metadata_only"] is True
    assert profile["read_only"] is True
    assert profile["training_performed"] is False
    assert profile["model_mutated"] is False
    assert profile["online_learning_performed"] is False
    assert profile["raw_payload_stored"] is False


def test_learning_profile_updates_repeated_observations_and_stability():
    first_model = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-profile-redis",
            "program": "redis-server",
            "service_name": "redis",
            "protocol": "tcp",
            "port": 6379,
            "last_seen": "2026-01-01T00:01:00+00:00",
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    second_observation = {
        "observed_entity_reference": "session-redacted-profile-redis",
        "program": "redis-server",
        "service_name": "redis",
        "protocol": "tcp",
        "port": 6380,
        "occurrence_count": 2,
        "last_seen": "2026-01-01T00:10:00+00:00",
        "source_mode": "live",
    }
    second_model = build_probabilistic_application_model(second_observation, generated_at="2026-01-01T00:10:00+00:00")
    profile = update_learning_profile(
        first_model["learning_profile"],
        second_observation,
        classification_model=second_model,
        generated_at="2026-01-01T00:10:00+00:00",
    )

    assert profile["profile_name"] == "redis"
    assert profile["observation_count"] == 3
    assert profile["observed_ports"] == [6379, 6380]
    assert profile["observed_protocols"] == ["tcp"]
    assert profile["observed_services"] == ["redis"]
    assert profile["observed_processes"] == ["redis-server"]
    assert len(profile["confidence_history"]) == 2
    assert profile["stability_score"] >= first_model["learning_profile"]["stability_score"]
    assert deterministic_learning_profile_json(profile) == json.dumps(
        profile, sort_keys=True, separators=(",", ":"), default=str
    )


def test_learning_profiles_update_collection_by_profile_identity():
    postgres_model = build_probabilistic_application_model(
        {"program": "postgres", "service_name": "postgresql", "protocol": "tcp", "port": 5432, "source_mode": "live"},
        generated_at=FIXED_TIME,
    )
    redis_model = build_probabilistic_application_model(
        {"program": "redis-server", "service_name": "redis", "protocol": "tcp", "port": 6379, "source_mode": "live"},
        generated_at=FIXED_TIME,
    )

    profiles = update_learning_profiles([], {"program": "postgres", "port": 5432}, classification_model=postgres_model, generated_at=FIXED_TIME)
    profiles = update_learning_profiles(profiles, {"program": "redis-server", "port": 6379}, classification_model=redis_model, generated_at=FIXED_TIME)
    profiles = update_learning_profiles(profiles, {"program": "postgres", "port": 5433}, classification_model=postgres_model, generated_at=FIXED_TIME)

    assert [profile["profile_name"] for profile in profiles] == ["postgresql", "redis"]
    postgresql = next(profile for profile in profiles if profile["profile_name"] == "postgresql")
    assert postgresql["observation_count"] == 2
    assert postgresql["observed_ports"] == [5432, 5433]


def test_learning_profile_persistence_round_trip(tmp_path):
    path = tmp_path / "profiles.json"
    model = build_probabilistic_application_model(
        {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 443, "source_mode": "live"},
        generated_at=FIXED_TIME,
    )
    profile = build_learning_profile(
        {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 443, "source_mode": "live"},
        classification_model=model,
        generated_at=FIXED_TIME,
    )

    payload = save_learning_profiles(path, [profile])
    loaded = load_learning_profiles(path)
    updated = update_learning_profile_store(
        path,
        {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 8443, "source_mode": "live"},
        classification_model=model,
        generated_at="2026-01-01T00:10:00+00:00",
    )

    assert payload["record_type"] == "application_learning_profile_store"
    assert payload["external_system"] is False
    assert payload["cloud_dependency"] is False
    assert loaded == [profile]
    assert updated[0]["observation_count"] == 2
    assert updated[0]["observed_ports"] == [443, 8443]
    assert load_learning_profiles(path) == updated


def test_learning_profile_history_creation_uses_existing_metadata_only():
    model = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-history-postgresql",
            "program": "postgres",
            "service_name": "postgresql",
            "protocol": "tcp",
            "port": 5432,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:05:00+00:00",
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    history = model["learning_profile_history"]

    assert history["record_type"] == "application_learning_profile_history"
    assert history["profile_name"] == "postgresql"
    assert history["first_observed"] == "2026-01-01T00:00:00+00:00"
    assert history["last_observed"] == "2026-01-01T00:05:00+00:00"
    assert history["observation_count"] == 1
    assert history["historical_ports"] == [5432]
    assert history["historical_protocols"] == ["tcp"]
    assert history["historical_services"] == ["postgresql"]
    assert history["historical_processes"] == ["postgres"]
    assert history["observation_timestamps"] == [FIXED_TIME]
    assert history["observation_records"][0]["metadata_only"] is True
    assert history["model_retrained"] is False
    assert history["confidence_evolution_performed"] is False
    assert history["adaptive_scoring_performed"] is False
    assert history["raw_payload_stored"] is False
    assert history["historical_summary"]["historical_observations"] == "1"
    assert history["historical_summary"]["profile_age"] == "5m"


def test_learning_profile_history_repeated_observations_preserve_and_merge_metadata():
    first_observation = {
        "program": "redis-server",
        "service_name": "redis",
        "protocol": "tcp",
        "port": 6379,
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:01:00+00:00",
        "source_mode": "live",
    }
    second_observation = {
        "program": "redis-server",
        "service_name": "redis-cache",
        "protocol": "tcp",
        "port": 6380,
        "occurrence_count": 2,
        "last_seen": "2026-01-01T00:10:00+00:00",
        "source_mode": "live",
    }
    first_model = build_probabilistic_application_model(first_observation, generated_at=FIXED_TIME)
    second_model = build_probabilistic_application_model(
        second_observation,
        generated_at="2026-01-01T00:10:00+00:00",
    )

    history = append_learning_profile_history(
        first_model["learning_profile_history"],
        second_observation,
        classification_model=second_model,
        generated_at="2026-01-01T00:10:00+00:00",
    )

    assert history["profile_name"] == "redis"
    assert history["first_observed"] == "2026-01-01T00:00:00+00:00"
    assert history["last_observed"] == "2026-01-01T00:10:00+00:00"
    assert history["observation_count"] == 3
    assert history["historical_ports"] == [6379, 6380]
    assert history["historical_protocols"] == ["tcp"]
    assert history["historical_services"] == ["redis", "redis-cache"]
    assert history["historical_processes"] == ["redis-server"]
    assert history["observation_timestamps"] == [FIXED_TIME, "2026-01-01T00:10:00+00:00"]
    assert len(history["observation_records"]) == 2
    assert history["historical_summary"]["historical_observations"] == "3"
    assert history["historical_summary"]["profile_age"] == "10m"


def test_learning_profile_history_collection_updates_by_profile_identity():
    postgres_model = build_probabilistic_application_model(
        {"program": "postgres", "service_name": "postgresql", "protocol": "tcp", "port": 5432, "source_mode": "live"},
        generated_at=FIXED_TIME,
    )
    redis_model = build_probabilistic_application_model(
        {"program": "redis-server", "service_name": "redis", "protocol": "tcp", "port": 6379, "source_mode": "live"},
        generated_at=FIXED_TIME,
    )

    histories = update_learning_profile_histories(
        [],
        {"program": "postgres", "port": 5432, "source_mode": "live"},
        classification_model=postgres_model,
        generated_at=FIXED_TIME,
    )
    histories = update_learning_profile_histories(
        histories,
        {"program": "redis-server", "port": 6379, "source_mode": "live"},
        classification_model=redis_model,
        generated_at=FIXED_TIME,
    )
    histories = update_learning_profile_histories(
        histories,
        {"program": "postgres", "port": 5433, "last_seen": "2026-01-01T00:12:00+00:00", "source_mode": "live"},
        classification_model=postgres_model,
        generated_at="2026-01-01T00:12:00+00:00",
    )

    assert [history["profile_name"] for history in histories] == ["postgresql", "redis"]
    postgresql = next(history for history in histories if history["profile_name"] == "postgresql")
    assert postgresql["observation_count"] == 2
    assert postgresql["historical_ports"] == [5432, 5433]
    assert postgresql["last_observed"] == "2026-01-01T00:12:00+00:00"


def test_learning_profile_history_persistence_round_trip(tmp_path):
    path = tmp_path / "profile-history.json"
    model = build_probabilistic_application_model(
        {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 443, "source_mode": "live"},
        generated_at=FIXED_TIME,
    )
    history = build_learning_profile_history(
        {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 443, "source_mode": "live"},
        classification_model=model,
        generated_at=FIXED_TIME,
    )

    payload = save_learning_profile_histories(path, [history])
    loaded = load_learning_profile_histories(path)
    updated = update_learning_profile_history_store(
        path,
        {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 8443, "source_mode": "live"},
        classification_model=model,
        generated_at="2026-01-01T00:10:00+00:00",
    )
    summary = summarize_learning_profile_history(updated[0])

    assert payload["record_type"] == "application_learning_profile_history_store"
    assert payload["external_system"] is False
    assert payload["cloud_dependency"] is False
    assert loaded == [history]
    assert updated[0]["observation_count"] == 2
    assert updated[0]["historical_ports"] == [443, 8443]
    assert updated[0]["observation_timestamps"] == [FIXED_TIME, "2026-01-01T00:10:00+00:00"]
    assert summary["historical_observations"] == "2"
    assert load_learning_profile_histories(path) == updated


def test_learning_profile_history_stability_scores_repeated_consistent_observations():
    model = build_probabilistic_application_model(
        {"program": "postgres", "service_name": "postgresql", "protocol": "tcp", "port": 5432, "source_mode": "live"},
        generated_at="2026-01-01T00:00:00+00:00",
    )
    history = build_learning_profile_history(
        {
            "program": "postgres",
            "service_name": "postgresql",
            "protocol": "tcp",
            "port": 5432,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
            "source_mode": "live",
        },
        classification_model=model,
        generated_at="2026-01-01T00:00:00+00:00",
    )
    for day in range(1, 8):
        timestamp = f"2026-01-0{day + 1}T00:00:00+00:00"
        history = append_learning_profile_history(
            history,
            {
                "program": "postgres",
                "service_name": "postgresql",
                "protocol": "tcp",
                "port": 5432,
                "last_seen": timestamp,
                "source_mode": "live",
            },
            classification_model=model,
            generated_at=timestamp,
        )

    assert history["observation_count"] == 8
    assert history["historical_summary"]["stability_score"] >= 0.8
    assert history["historical_summary"]["stability_label"] == "highly_stable"
    assert history["stability_label"] == "highly_stable"


def test_learning_profile_history_stability_penalizes_sparse_conflicting_and_variable_observations():
    postgresql = {"top_classification": "postgresql", "confidence": 0.9}
    mysql = {"top_classification": "mysql", "confidence": 0.9}
    low_confidence_postgresql = {"top_classification": "postgresql", "confidence": 0.2}
    first = {
        "program": "postgres",
        "service_name": "postgresql",
        "protocol": "tcp",
        "port": 5432,
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "source_mode": "live",
    }
    second = {
        "program": "mysql",
        "service_name": "mysql",
        "protocol": "tcp",
        "port": 3306,
        "last_seen": "2026-01-01T01:00:00+00:00",
        "source_mode": "live",
    }
    sparse = build_learning_profile_history(first, classification_model=postgresql, generated_at="2026-01-01T00:00:00+00:00")
    conflicting = append_learning_profile_history(
        sparse,
        second,
        classification_model=mysql,
        generated_at="2026-01-01T01:00:00+00:00",
    )
    fluctuating = append_learning_profile_history(
        sparse,
        {**first, "last_seen": "2026-01-01T01:00:00+00:00"},
        classification_model=low_confidence_postgresql,
        generated_at="2026-01-01T01:00:00+00:00",
    )
    consistent = append_learning_profile_history(
        sparse,
        {**first, "last_seen": "2026-01-01T01:00:00+00:00"},
        classification_model=postgresql,
        generated_at="2026-01-01T01:00:00+00:00",
    )

    assert sparse["historical_summary"]["stability_label"] == "unstable"
    assert conflicting["historical_summary"]["stability_score"] < consistent["historical_summary"]["stability_score"]
    assert fluctuating["historical_summary"]["stability_score"] < consistent["historical_summary"]["stability_score"]
    assert conflicting["historical_summary"]["stability_label"] in {"developing", "unstable"}
    assert fluctuating["historical_summary"]["stability_label"] in {"developing", "unstable"}


def test_learning_profile_history_stability_increases_with_profile_age():
    model = {"top_classification": "postgresql", "confidence": 0.9}
    short = build_learning_profile_history(
        {
            "program": "postgres",
            "service_name": "postgresql",
            "port": 5432,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:10:00+00:00",
            "observation_count": 3,
        },
        classification_model=model,
        generated_at="2026-01-01T00:10:00+00:00",
    )
    aged = build_learning_profile_history(
        {
            "program": "postgres",
            "service_name": "postgresql",
            "port": 5432,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-08T00:00:00+00:00",
            "observation_count": 3,
        },
        classification_model=model,
        generated_at="2026-01-08T00:00:00+00:00",
    )

    assert aged["historical_summary"]["stability_score"] > short["historical_summary"]["stability_score"]
    assert aged["historical_summary"]["stability_label"] in {"stable", "highly_stable"}


def test_probabilistic_application_catalog_confidence_scales_with_evidence_strength():
    strong = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-strong-postgresql",
            "program": "postgres",
            "service_name": "postgresql",
            "protocol": "tcp",
            "port": 5432,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    moderate = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-strong-caddy",
            "program": "caddy",
            "service_name": "https",
            "protocol": "tls",
            "port": 443,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    weak = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-ambiguous-tls",
            "protocol": "tls",
            "port": 443,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert strong["top_classification"] == "postgresql"
    assert moderate["top_classification"] == "caddy"
    assert weak["top_classification"] == "unknown_application"
    assert strong["confidence"] > moderate["confidence"] > _candidate_probability(weak, "caddy")
    assert strong["calibration"]["evidence_strength"] == "strong"
    assert moderate["calibration"]["evidence_strength"] == "moderate"
    assert weak["calibration"]["evidence_strength"] == "weak"


def test_probabilistic_application_calibration_handles_port_only_weak_evidence():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-weak-port",
            "port": 443,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    assert record["top_classification"] == "unknown_application"
    assert 0.2 <= record["confidence"] <= 0.6
    assert {"nginx", "apache", "caddy", "https_service", "unknown_proxy"}.issubset(
        {row["candidate"] for row in record["candidates"]}
    )
    assert max(row["probability"] for row in record["candidates"] if row["candidate"] != "unknown_application") < 0.15
    assert record["calibration"]["evidence_strength"] == "insufficient"
    assert "port_only" in record["calibration"]["factors"]


def test_probabilistic_application_calibration_handles_conflicting_evidence():
    record = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-conflict",
            "program": "nginx",
            "port": 5432,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )

    candidates = {row["candidate"] for row in record["candidates"]}
    assert record["top_classification"] == "unknown_application"
    assert 0.2 <= record["confidence"] <= 0.6
    assert {"nginx", "postgresql", "database_service"}.issubset(candidates)
    assert record["calibration"]["conflicting_evidence"] is True
    assert "conflicting_metadata" in record["calibration"]["factors"]


def test_probabilistic_application_model_is_deterministic_and_export_safe():
    observation = {
        "observed_entity_reference": "session-redacted-db",
        "program": "postgres",
        "service_name": "postgresql",
        "protocol": "tcp",
        "port": 5432,
        "payload_content": "must-not-export",
        "raw_packet": "ignored",
        "source_mode": "live",
    }
    first = build_probabilistic_application_model(observation, generated_at=FIXED_TIME)
    second = build_probabilistic_application_model(observation, generated_at=FIXED_TIME)
    serialized = deterministic_probabilistic_application_model_json(first)

    assert first == second
    assert first["top_classification"] == "postgresql"
    assert round(sum(float(row["probability"]) for row in first["candidates"]), 3) == 1.0
    assert "must-not-export" not in serialized
    assert "ignored" not in serialized
    assert '"training_performed":false' in serialized


def test_probabilistic_application_model_handles_unknown_metadata():
    record = build_probabilistic_application_model(
        {"observed_entity_reference": "session-redacted-unknown", "source_mode": "live"},
        generated_at=FIXED_TIME,
    )

    assert record["top_classification"] == "unknown_application"
    assert 0.2 <= record["confidence"] <= 0.6
    assert record["candidate_count"] == 3
    assert record["evidence_count"] == 0
    assert record["calibration"]["evidence_strength"] == "insufficient"
    assert "insufficient_metadata" in record["calibration"]["factors"]


def test_dummy_labels_remain_fixture_or_simulated_only():
    fixture = build_probable_application_attributions(
        _observation(process_hint="dummy_app", service_hint="dummy_db", source_mode="fixture"),
        generated_at=FIXED_TIME,
    )[0]
    live = build_probable_application_attributions(
        _observation(process_hint="dummy_app", service_hint="dummy_db", protocol_hint="", destination_behavior_hint="", flow_behavior_hint="", source_mode="live"),
        generated_at=FIXED_TIME,
    )[0]

    assert fixture["candidate_app_class"] == "dummy_app"
    assert fixture["candidate_service_class"] == "dummy_db"
    assert fixture["source_mode"] == "fixture"
    assert live["candidate_app_class"] == "Unknown"
    assert live["candidate_service_class"] == "Unattributed"
    assert "dummy_app" not in deterministic_application_attribution_json(live)
    assert "dummy_db" not in deterministic_application_attribution_json(live)


def test_confidence_score_bounds_and_conflict_penalty_behavior():
    strong = score_application_attribution_confidence(
        process_confidence=1.0,
        service_confidence=1.0,
        protocol_confidence=1.0,
        destination_confidence=1.0,
        flow_confidence=1.0,
        recurrence_confidence=1.0,
    )
    penalized = score_application_attribution_confidence(
        process_confidence=1.0,
        service_confidence=1.0,
        protocol_confidence=1.0,
        destination_confidence=1.0,
        flow_confidence=1.0,
        recurrence_confidence=1.0,
        conflict_penalty=0.4,
    )

    assert strong == 1.0
    assert 0.0 <= penalized < strong <= 1.0
    breakdown_json = deterministic_confidence_json(
        {
            "confidence_score": penalized,
            "raw_payload_stored": False,
            "pcap_generated": False,
        }
    )
    assert '"pcap_generated":false' in breakdown_json


def test_recurring_signature_confidence_and_drift_detection():
    stable = build_behavioral_signature_record(_signature(), generated_at=FIXED_TIME)
    drifted = build_behavioral_signature_record(_signature(drift_detected=True), generated_at=FIXED_TIME)
    report = build_signature_learning_report([_signature(), _signature(drift_detected=True)], generated_at=FIXED_TIME)

    assert stable["signature_class"] == "process_service_pattern"
    assert stable["confidence_score"] > drifted["confidence_score"]
    assert drifted["drift_detected"] is True
    assert report["summary"]["signature_count"] == 2
    assert report["summary"]["drift_detected_count"] == 1
    assert deterministic_signature_json(stable) == json.dumps(stable, sort_keys=True, separators=(",", ":"), default=str)


def test_export_safe_serialization_has_no_payload_pcap_or_dns_history_storage():
    report = build_application_attribution_report(
        [_observation(payload_content="must-not-export", raw_packet="ignored", domain_summary="redacted only")],
        signature_observations=[_signature(domain_summary="redacted only")],
        generated_at=FIXED_TIME,
    )
    serialized = deterministic_application_attribution_json(report)

    assert "must-not-export" not in serialized
    assert "ignored" not in serialized
    assert '"raw_payload_stored":false' in serialized
    assert '"raw_packet_stored":false' in serialized
    assert '"pcap_generated":false' in serialized
    assert '"raw_dns_history_stored":false' in serialized
    assert '"hostname_stored":false' in serialized


def test_malformed_attribution_and_cross_platform_safe_records():
    with pytest.raises(ApplicationAttributionError):
        build_probable_application_attributions("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(ApplicationAttributionError):
        build_application_attribution_report(object(), generated_at=FIXED_TIME)
    with pytest.raises(SignatureLearningError):
        build_behavioral_signature_record("not-an-object", generated_at=FIXED_TIME)
    with pytest.raises(SignatureLearningError):
        build_signature_learning_report(object(), generated_at=FIXED_TIME)

    row = build_probable_application_attributions(
        _observation(
            observed_entity_reference="session-redacted-004",
            process_hint="remote-client",
            service_hint="rdp",
            protocol_hint="tcp",
            destination_behavior_hint="redacted_destination",
            source_mode="unknown",
        ),
        generated_at=FIXED_TIME,
    )[0]

    assert row["source_mode"] == "unknown"
    assert "real_hostname" not in deterministic_application_attribution_json(row)
