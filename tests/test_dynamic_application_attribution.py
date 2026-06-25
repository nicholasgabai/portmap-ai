import json

import pytest

from core_engine.attribution import (
    ApplicationAttributionError,
    SignatureLearningError,
    append_learning_profile_history,
    build_application_attribution_report,
    build_behavior_graph_model,
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
    deterministic_behavior_graph_json,
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


def _history_with_confidences(confidences, *, profile_name="nginx"):
    history = None
    for index, confidence in enumerate(confidences, start=1):
        timestamp = f"2026-01-{index:02d}T00:00:00+00:00"
        observation = {
            "program": profile_name,
            "service_name": profile_name,
            "protocol": "tcp",
            "port": 443,
            "last_seen": timestamp,
            "source_mode": "live",
        }
        model = {
            "top_classification": profile_name,
            "confidence": confidence,
            "evidence_quality": "strong",
            "candidate_count": 1,
        }
        if history is None:
            history = build_learning_profile_history(
                observation,
                classification_model=model,
                generated_at=timestamp,
            )
        else:
            history = append_learning_profile_history(
                history,
                observation,
                classification_model=model,
                generated_at=timestamp,
            )
    return history


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


def test_learning_profile_history_reports_no_drift_for_repeated_consistent_observations():
    model = {"top_classification": "postgresql", "confidence": 0.82}
    first = {
        "program": "postgres",
        "service_name": "postgresql",
        "protocol": "tcp",
        "port": 5432,
        "service_fingerprint": "postgresql_server",
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "source_mode": "live",
    }
    history = build_learning_profile_history(first, classification_model=model, generated_at="2026-01-01T00:00:00+00:00")
    history = append_learning_profile_history(
        history,
        {**first, "last_seen": "2026-01-02T00:00:00+00:00"},
        classification_model=model,
        generated_at="2026-01-02T00:00:00+00:00",
    )

    assert history["historical_summary"]["drift_score"] == 0.0
    assert history["historical_summary"]["drift_label"] == "none"
    assert history["drift_label"] == "none"


def test_learning_profile_history_detects_classification_drift():
    first = {
        "program": "postgres",
        "service_name": "postgresql",
        "protocol": "tcp",
        "port": 5432,
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "source_mode": "live",
    }
    history = build_learning_profile_history(
        first,
        classification_model={"top_classification": "postgresql", "confidence": 0.84},
        generated_at="2026-01-01T00:00:00+00:00",
    )
    for index, classification in enumerate(("mysql", "mongodb", "redis"), start=2):
        history = append_learning_profile_history(
            history,
            {
                "program": classification,
                "service_name": classification,
                "protocol": "tcp",
                "port": 5000 + index,
                "last_seen": f"2026-01-0{index}T00:00:00+00:00",
                "source_mode": "live",
            },
            classification_model={"top_classification": classification, "confidence": 0.84},
            generated_at=f"2026-01-0{index}T00:00:00+00:00",
        )

    assert history["historical_summary"]["drift_score"] >= 0.35
    assert history["historical_summary"]["drift_label"] in {"moderate", "high"}


def test_learning_profile_history_detects_confidence_drift():
    first = {
        "program": "nginx",
        "service_name": "https",
        "protocol": "tls",
        "port": 443,
        "last_seen": "2026-01-01T00:00:00+00:00",
        "source_mode": "live",
    }
    stable = build_learning_profile_history(
        first,
        classification_model={"top_classification": "nginx", "confidence": 0.8},
        generated_at="2026-01-01T00:00:00+00:00",
    )
    fluctuating = append_learning_profile_history(
        stable,
        {**first, "last_seen": "2026-01-01T01:00:00+00:00"},
        classification_model={"top_classification": "nginx", "confidence": 0.15},
        generated_at="2026-01-01T01:00:00+00:00",
    )

    assert fluctuating["historical_summary"]["drift_score"] > stable["historical_summary"]["drift_score"]
    assert fluctuating["historical_summary"]["drift_label"] in {"low", "moderate"}


def test_learning_profile_history_detects_metadata_drift_in_ports_services_protocols_and_fingerprints():
    model = {"top_classification": "nginx", "confidence": 0.75}
    first = {
        "program": "nginx",
        "service_name": "https",
        "protocol": "tls",
        "port": 443,
        "service_fingerprint": "nginx_tls",
        "last_seen": "2026-01-01T00:00:00+00:00",
        "source_mode": "live",
    }
    history = build_learning_profile_history(first, classification_model=model, generated_at="2026-01-01T00:00:00+00:00")
    history = append_learning_profile_history(
        history,
        {
            "program": "nginx",
            "service_name": "http",
            "protocol": "http",
            "port": 8080,
            "service_fingerprint": "nginx_http_alt",
            "last_seen": "2026-01-01T01:00:00+00:00",
            "source_mode": "live",
        },
        classification_model=model,
        generated_at="2026-01-01T01:00:00+00:00",
    )

    assert history["historical_summary"]["drift_score"] >= 0.30
    assert history["historical_summary"]["drift_label"] in {"low", "moderate", "high"}
    assert history["observation_records"][0]["fingerprints"] == ["nginx_tls"]
    assert history["observation_records"][1]["fingerprints"] == ["nginx_http_alt"]


def test_learning_profile_recommendations_classify_stable_profiles():
    model = {"top_classification": "postgresql", "confidence": 0.86, "evidence_quality": "strong", "candidate_count": 1}
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
            {"program": "postgres", "service_name": "postgresql", "protocol": "tcp", "port": 5432},
            classification_model=model,
            generated_at=timestamp,
        )

    summary = history["historical_summary"]
    recommendation_ids = [row["recommendation_id"] for row in summary["recommendation_list"]]

    assert summary["primary_recommendation"] == "classification_stable"
    assert "classification_stable" in recommendation_ids
    assert "continue_observation" in recommendation_ids
    assert summary["recommendation_count"] == str(len(summary["recommendation_list"]))


def test_learning_profile_recommendations_gather_metadata_for_unstable_profiles():
    model = {"top_classification": "nginx", "confidence": 0.72, "evidence_quality": "weak", "candidate_count": 1}
    history = build_learning_profile_history(
        {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 443},
        classification_model=model,
        generated_at="2026-01-01T00:00:00+00:00",
    )

    summary = history["historical_summary"]
    recommendation_ids = [row["recommendation_id"] for row in summary["recommendation_list"]]

    assert summary["primary_recommendation"] == "gather_more_metadata"
    assert "gather_more_metadata" in recommendation_ids
    assert summary["recommendation_list"][0]["read_only"] is True
    assert summary["recommendation_list"][0]["automated_action"] is False


def test_learning_profile_recommendations_review_drifting_profiles():
    first = {"program": "postgres", "service_name": "postgresql", "protocol": "tcp", "port": 5432}
    history = build_learning_profile_history(
        first,
        classification_model={"top_classification": "postgresql", "confidence": 0.82, "evidence_quality": "strong"},
        generated_at="2026-01-01T00:00:00+00:00",
    )
    for index, classification in enumerate(("mysql", "mongodb", "redis"), start=2):
        history = append_learning_profile_history(
            history,
            {"program": classification, "service_name": classification, "protocol": "tcp", "port": 5000 + index},
            classification_model={"top_classification": classification, "confidence": 0.82, "evidence_quality": "strong"},
            generated_at=f"2026-01-0{index}T00:00:00+00:00",
        )

    summary = history["historical_summary"]
    recommendation_ids = [row["recommendation_id"] for row in summary["recommendation_list"]]

    assert summary["primary_recommendation"] == "review_profile_drift"
    assert "review_profile_drift" in recommendation_ids
    assert "monitor_behavior_change" in recommendation_ids


def test_learning_profile_recommendations_review_low_confidence_profiles():
    model = {
        "top_classification": "unknown_application",
        "confidence": 0.34,
        "evidence_quality": "insufficient",
        "candidate_count": 3,
        "ambiguity_reason": "Multiple candidates remain plausible.",
    }
    history = build_learning_profile_history(
        {"protocol": "tcp", "port": 443, "source_mode": "live"},
        classification_model=model,
        generated_at="2026-01-01T00:00:00+00:00",
    )

    recommendation_ids = [row["recommendation_id"] for row in history["historical_summary"]["recommendation_list"]]

    assert "verify_service_identity" in recommendation_ids
    assert "gather_more_metadata" in recommendation_ids


def test_learning_profile_recommendations_preserve_ambiguous_classification_context():
    model = build_probabilistic_application_model(
        {"protocol": "tls", "port": 443, "source_mode": "live"},
        generated_at=FIXED_TIME,
    )
    history = build_learning_profile_history(
        {"protocol": "tls", "port": 443, "source_mode": "live"},
        classification_model=model,
        generated_at=FIXED_TIME,
    )
    summary = history["historical_summary"]
    recommendation = next(
        row for row in summary["recommendation_list"] if row["recommendation_id"] == "verify_service_identity"
    )

    assert summary["primary_recommendation"] == "verify_service_identity"
    assert any(factor.startswith("candidate_count:") for factor in recommendation["supporting_factors"])
    assert "evidence_quality" in ",".join(recommendation["supporting_factors"])


def test_learning_profile_recommendations_for_mature_profiles_remain_advisory():
    model = {
        "top_classification": "nginx",
        "confidence": 0.88,
        "evidence_quality": "strong",
        "candidate_count": 1,
    }
    history = build_learning_profile_history(
        {
            "program": "nginx",
            "service_name": "https",
            "protocol": "tls",
            "port": 443,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
        },
        classification_model=model,
        generated_at="2026-01-01T00:00:00+00:00",
    )
    for day in (8, 15, 22, 31):
        timestamp = f"2026-01-{day:02d}T00:00:00+00:00"
        history = append_learning_profile_history(
            history,
            {"program": "nginx", "service_name": "https", "protocol": "tls", "port": 443},
            classification_model=model,
            generated_at=timestamp,
        )

    summary = summarize_learning_profile_history(history)

    assert summary["stability_label"] == "highly_stable"
    assert summary["primary_recommendation"] == "classification_stable"
    assert all(row["read_only"] is True and row["automated_action"] is False for row in summary["recommendation_list"])


def test_learning_profile_confidence_evolution_detects_improving_profiles():
    history = _history_with_confidences([0.30, 0.45, 0.62])
    summary = history["historical_summary"]

    assert summary["confidence_first"] == 0.30
    assert summary["confidence_latest"] == 0.62
    assert summary["confidence_delta"] == 0.32
    assert summary["confidence_average"] == 0.457
    assert summary["confidence_trend"] == "improving"
    assert history["confidence_trend"] == "improving"


def test_learning_profile_confidence_evolution_detects_stable_profiles():
    history = _history_with_confidences([0.72, 0.74, 0.73])
    summary = history["historical_summary"]

    assert summary["confidence_min"] == 0.72
    assert summary["confidence_max"] == 0.74
    assert summary["confidence_delta"] == 0.01
    assert summary["confidence_average"] == 0.73
    assert summary["confidence_trend"] == "stable"
    assert summary["primary_recommendation"] == "classification_stable"


def test_learning_profile_confidence_evolution_detects_declining_profiles():
    history = _history_with_confidences([0.82, 0.70, 0.58])
    summary = history["historical_summary"]
    recommendation_ids = [row["recommendation_id"] for row in summary["recommendation_list"]]

    assert summary["confidence_delta"] == -0.24
    assert summary["confidence_trend"] == "declining"
    assert "investigate_confidence_change" in recommendation_ids


def test_learning_profile_confidence_evolution_detects_volatile_profiles():
    history = _history_with_confidences([0.30, 0.82, 0.42])
    summary = history["historical_summary"]
    recommendation = next(
        row for row in summary["recommendation_list"] if row["recommendation_id"] == "investigate_confidence_change"
    )

    assert summary["confidence_min"] == 0.30
    assert summary["confidence_max"] == 0.82
    assert summary["confidence_trend"] == "volatile"
    assert "confidence_trend:volatile" in recommendation["supporting_factors"]


def test_learning_profile_confidence_evolution_handles_single_observation_profiles():
    history = _history_with_confidences([0.61])
    summary = history["historical_summary"]

    assert summary["confidence_first"] == 0.61
    assert summary["confidence_latest"] == 0.61
    assert summary["confidence_min"] == 0.61
    assert summary["confidence_max"] == 0.61
    assert summary["confidence_average"] == 0.61
    assert summary["confidence_delta"] == 0.0
    assert summary["confidence_trend"] == "stable"


def test_learning_profile_confidence_evolution_summarizes_mixed_confidence_histories():
    history = _history_with_confidences([0.40, 0.62, 0.52, 0.68])
    summary = summarize_learning_profile_history(history)

    assert summary["confidence_first"] == 0.40
    assert summary["confidence_latest"] == 0.68
    assert summary["confidence_min"] == 0.40
    assert summary["confidence_max"] == 0.68
    assert summary["confidence_average"] == 0.555
    assert summary["confidence_delta"] == 0.28
    assert summary["confidence_trend"] == "volatile"


def test_behavior_graph_generates_nodes_from_existing_metadata_only():
    model = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-graph",
            "node_id": "worker-1",
            "program": "nginx",
            "service_name": "https",
            "protocol": "tls",
            "port": 443,
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    graph = model["behavior_graph"]

    assert graph["record_type"] == "graph_behavior_model"
    assert graph["metadata_only"] is True
    assert graph["read_only"] is True
    assert graph["enforcement_enabled"] is False
    assert {row["node_type"] for row in graph["nodes"]} == {
        "asset_node",
        "service_node",
        "port_node",
        "protocol_node",
        "application_node",
        "profile_node",
    }
    assert graph["summary"]["node_count"] >= 6
    assert graph["summary"]["asset_count"] == 1
    assert graph["summary"]["service_count"] == 1
    assert graph["summary"]["application_count"] >= 1
    assert graph["summary"]["profile_count"] == 1


def test_behavior_graph_generates_required_edges_from_flow_metadata():
    model = build_probabilistic_application_model(
        {
            "observed_entity_reference": "session-redacted-flow-graph",
            "node_id": "worker-1",
            "program": "nginx",
            "service_name": "https",
            "protocol": "tls",
            "port": 443,
            "flow_id": "flow-redacted-1",
            "source_mode": "live",
        },
        generated_at=FIXED_TIME,
    )
    graph = model["behavior_graph"]

    assert {row["edge_type"] for row in graph["edges"]} == {
        "asset_exposes_service",
        "service_uses_port",
        "service_uses_protocol",
        "service_classified_as_application",
        "service_linked_to_profile",
        "asset_observed_flow",
    }
    assert graph["summary"]["edge_count"] == 6
    assert graph["summary"]["relationship_count"] == 6
    assert graph["summary"]["related_asset"] == "worker-1"
    assert graph["summary"]["related_service"] == "https"
    assert graph["summary"]["related_profile"].startswith("learning-profile-")
    assert graph["summary"]["inferred_relationship_count"] > 0
    assert graph["summary"]["strongest_relationship"].startswith("graph-rel-")
    assert graph["summary"]["strongest_relationship_type"] != "-"
    assert graph["summary"]["strongest_relationship_score"] > 0
    assert graph["summary"]["related_entity_count"] > 0


def test_behavior_graph_ids_are_deterministic_and_export_safe():
    observation = {
        "observed_entity_reference": "session-redacted-stable-graph",
        "node_id": "worker-1",
        "program": "postgres",
        "service_name": "postgresql",
        "protocol": "tcp",
        "port": 5432,
        "flow_id": "flow-redacted-postgres",
        "source_mode": "live",
        "payload": "must-not-export",
        "raw_packet": "must-not-export",
    }
    first = build_probabilistic_application_model(observation, generated_at=FIXED_TIME)["behavior_graph"]
    second = build_probabilistic_application_model(observation, generated_at=FIXED_TIME)["behavior_graph"]

    assert deterministic_behavior_graph_json(first) == deterministic_behavior_graph_json(second)
    assert [row["node_id"] for row in first["nodes"]] == [row["node_id"] for row in second["nodes"]]
    assert [row["edge_id"] for row in first["edges"]] == [row["edge_id"] for row in second["edges"]]
    serialized = deterministic_behavior_graph_json(first)
    assert "must-not-export" not in serialized
    assert all(row["node_id"].startswith("graph-node-") for row in first["nodes"])
    assert all(row["edge_id"].startswith("graph-edge-") for row in first["edges"])


def test_behavior_graph_empty_input_is_safe_and_empty():
    graph = build_behavior_graph_model({}, generated_at=FIXED_TIME)

    assert graph["summary"]["node_count"] == 0
    assert graph["summary"]["edge_count"] == 0
    assert graph["summary"]["asset_count"] == 0
    assert graph["summary"]["service_count"] == 0
    assert graph["summary"]["application_count"] == 0
    assert graph["summary"]["profile_count"] == 0
    assert graph["summary"]["relationship_count"] == 0
    assert graph["summary"]["inferred_relationship_count"] == 0
    assert graph["summary"]["strongest_relationship"] == "-"
    assert graph["summary"]["strongest_relationship_type"] == "-"
    assert graph["summary"]["strongest_relationship_score"] == "-"
    assert graph["summary"]["related_entity_count"] == 0
    assert graph["summary"]["cluster_count"] == 0
    assert graph["summary"]["strongest_cluster"] == "-"
    assert graph["summary"]["strongest_cluster_type"] == "-"
    assert graph["summary"]["strongest_cluster_score"] == "-"
    assert graph["summary"]["primary_cluster"] == "-"
    assert graph["summary"]["primary_cluster_type"] == "-"
    assert graph["summary"]["primary_cluster_risk"] == "-"
    assert graph["summary"]["primary_cluster_confidence"] == "-"
    assert graph["summary"]["primary_cluster_reason"] == "-"
    assert graph["summary"]["primary_cluster_trend"] == "-"
    assert graph["summary"]["primary_cluster_age"] == "-"
    assert graph["summary"]["primary_cluster_evolution_score"] == "-"
    assert graph["summary"]["primary_cluster_new_relationships"] == "-"
    assert graph["summary"]["primary_cluster_lost_relationships"] == "-"
    assert graph["summary"]["primary_cluster_new_signals"] == "-"
    assert graph["summary"]["primary_cluster_lost_signals"] == "-"
    assert graph["summary"]["primary_cluster_evolution_summary"] == "-"
    assert graph["summary"]["primary_cluster_trend_summary"] == "-"
    assert graph["summary"]["graph_insight_count"] == 0
    assert graph["summary"]["strongest_graph_insight"] == "-"
    assert graph["summary"]["strongest_graph_insight_type"] == "-"
    assert graph["summary"]["strongest_graph_insight_score"] == "-"
    assert graph["summary"]["graph_insight_summary"] == "-"
    assert graph["summary"]["graph_operator_next_steps"] == "-"
    assert graph["insights"] == []
    assert graph["summary"]["related_asset"] == "-"
    assert graph["summary"]["related_service"] == "-"
    assert graph["summary"]["related_profile"] == "-"
    assert graph["metadata_only"] is True
    assert graph["read_only"] is True


def test_behavior_graph_infers_relationships_from_existing_metadata():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "peer_asset": "asset-b",
            "service_name": "frontend",
            "related_services": ["backend"],
            "protocol": "tcp",
            "port": 443,
            "flow_id": "flow-1",
            "score_factors": ["sensitive_port:443", "new_peer"],
            "related_profiles": ["learning-profile-related"],
            "source_mode": "live",
        },
        classification_model={
            "top_classification": "nginx",
            "confidence": 0.72,
            "candidates": [
                {"candidate": "nginx", "probability": 0.72},
                {"candidate": "apache", "probability": 0.18},
            ],
        },
        learning_profile={"profile_id": "learning-profile-primary"},
        learning_profile_history={
            "profile_id": "learning-profile-primary",
            "historical_services": ["backend"],
        },
        generated_at=FIXED_TIME,
    )

    relationship_types = {row["relationship_type"] for row in graph["relationships"]}
    assert {
        "shared_asset",
        "shared_service",
        "shared_protocol",
        "shared_port",
        "shared_application_candidate",
        "shared_learning_profile",
        "observed_flow_relationship",
        "related_risk_signal",
    }.issubset(relationship_types)
    assert graph["summary"]["inferred_relationship_count"] == len(graph["relationships"])
    assert graph["summary"]["strongest_relationship"].startswith("graph-rel-")
    assert graph["summary"]["strongest_relationship_type"] in relationship_types
    assert graph["summary"]["strongest_relationship_score"] >= 0.5
    assert graph["summary"]["related_entity_count"] >= 6
    assert all(0.0 <= float(row["strength_score"]) <= 1.0 for row in graph["relationships"])
    assert all(row["evidence_count"] == len(row["evidence_summary"]) for row in graph["relationships"])
    assert {row["cluster_type"] for row in graph["clusters"]} == {
        "asset_cluster",
        "service_cluster",
        "application_cluster",
        "profile_cluster",
        "risk_signal_cluster",
    }
    assert graph["summary"]["cluster_count"] == 5
    assert graph["summary"]["strongest_cluster"].startswith("graph-cluster-")
    assert graph["summary"]["strongest_cluster_type"] == "application_cluster"
    assert graph["summary"]["strongest_cluster_score"] > 0
    assert graph["summary"]["primary_cluster"].startswith("graph-cluster-")
    assert graph["summary"]["primary_cluster_type"] in {row["cluster_type"] for row in graph["clusters"]}
    assert graph["summary"]["primary_cluster_risk"] in {"low", "medium", "high", "critical"}
    assert 0.0 <= graph["summary"]["primary_cluster_confidence"] <= 1.0
    assert graph["summary"]["primary_cluster_reason"] != "-"
    assert graph["summary"]["primary_cluster_trend"] in {
        "emerging",
        "growing",
        "shrinking",
        "stable",
        "dormant",
        "unknown",
    }
    assert graph["summary"]["primary_cluster_age"] != "-"
    assert 0.0 <= graph["summary"]["primary_cluster_evolution_score"] <= 1.0
    assert graph["summary"]["primary_cluster_evolution_summary"] != "-"
    assert graph["summary"]["primary_cluster_trend_summary"] != "-"
    assert graph["summary"]["graph_insight_count"] == len(graph["insights"])
    assert graph["summary"]["graph_insight_count"] > 0
    assert graph["summary"]["strongest_graph_insight"].startswith("graph-insight-")
    assert graph["summary"]["strongest_graph_insight_type"] != "-"
    assert 0.0 <= graph["summary"]["strongest_graph_insight_score"] <= 1.0
    assert graph["summary"]["graph_insight_summary"] != "-"
    assert graph["summary"]["graph_operator_next_steps"] != "-"


def test_behavior_graph_relationship_ids_are_stable():
    observation = {
        "node_id": "asset-a",
        "peer_asset": "asset-b",
        "service_name": "frontend",
        "related_services": ["backend"],
        "protocol": "tcp",
        "port": 443,
        "flow_id": "flow-1",
        "score_factors": ["sensitive_port:443"],
        "source_mode": "live",
    }
    classifier = {
        "top_classification": "nginx",
        "confidence": 0.72,
        "candidates": [
            {"candidate": "nginx", "probability": 0.72},
            {"candidate": "apache", "probability": 0.18},
        ],
    }
    first = build_behavior_graph_model(
        observation,
        classification_model=classifier,
        learning_profile={"profile_id": "learning-profile-primary"},
        generated_at=FIXED_TIME,
    )
    second = build_behavior_graph_model(
        observation,
        classification_model=classifier,
        learning_profile={"profile_id": "learning-profile-primary"},
        generated_at=FIXED_TIME,
    )

    assert deterministic_behavior_graph_json(first) == deterministic_behavior_graph_json(second)
    assert [row["relationship_id"] for row in first["relationships"]] == [
        row["relationship_id"] for row in second["relationships"]
    ]
    assert all(row["relationship_id"].startswith("graph-rel-") for row in first["relationships"])


def test_behavior_graph_relationship_strength_reflects_evidence_volume():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "peer_asset": "asset-b",
            "service_name": "frontend",
            "protocol": "tcp",
            "port": 443,
            "flow_id": "flow-1",
            "source_mode": "live",
        },
        classification_model={"top_classification": "nginx", "confidence": 0.72},
        learning_profile={"profile_id": "learning-profile-primary"},
        generated_at=FIXED_TIME,
    )
    by_type = {row["relationship_type"]: row for row in graph["relationships"]}

    assert by_type["observed_flow_relationship"]["strength_score"] > by_type["shared_port"]["strength_score"]
    assert by_type["observed_flow_relationship"]["evidence_count"] > by_type["shared_port"]["evidence_count"]


def test_behavior_graph_relationship_score_distribution_is_calibrated():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "peer_asset": "asset-b",
            "service_name": "frontend",
            "related_services": ["backend"],
            "protocol": "tcp",
            "port": 443,
            "flow_id": "flow-1",
            "score_factors": ["sensitive_port:443", "new_peer"],
            "source_mode": "live",
        },
        classification_model={
            "top_classification": "nginx",
            "confidence": 0.72,
            "candidates": [
                {"candidate": "nginx", "probability": 0.72},
                {"candidate": "apache", "probability": 0.18},
            ],
        },
        learning_profile={"profile_id": "learning-profile-primary"},
        generated_at=FIXED_TIME,
    )
    scores = [float(row["strength_score"]) for row in graph["relationships"]]
    weak = min(
        (row for row in graph["relationships"] if row["relationship_type"] == "shared_port"),
        key=lambda row: row["strength_score"],
    )
    medium = max(
        (row for row in graph["relationships"] if row["relationship_type"] == "shared_service"),
        key=lambda row: row["strength_score"],
    )
    strong = max(
        (row for row in graph["relationships"] if row["relationship_type"] == "observed_flow_relationship"),
        key=lambda row: row["strength_score"],
    )
    strongest = max(graph["relationships"], key=lambda row: (row["strength_score"], row["relationship_id"]))

    assert weak["strength_score"] < 0.50
    assert 0.50 <= medium["strength_score"] < 0.85
    assert strong["strength_score"] >= 0.85
    assert len(set(scores)) >= 4
    assert any(score < 0.98 for score in scores)
    assert all(0.0 <= score <= 1.0 for score in scores)
    assert graph["summary"]["strongest_relationship_score"] == strongest["strength_score"]
    assert graph["summary"]["strongest_relationship"] == strongest["relationship_id"]


def test_behavior_graph_cluster_ids_are_deterministic_and_summarized():
    observation = {
        "node_id": "asset-a",
        "peer_asset": "asset-b",
        "service_name": "frontend",
        "related_services": ["backend"],
        "protocol": "tcp",
        "port": 443,
        "flow_id": "flow-1",
        "score_factors": ["sensitive_port:443"],
        "related_profiles": ["learning-profile-related"],
        "source_mode": "live",
    }
    classifier = {
        "top_classification": "nginx",
        "confidence": 0.72,
        "candidates": [
            {"candidate": "nginx", "probability": 0.72},
            {"candidate": "apache", "probability": 0.18},
        ],
    }
    first = build_behavior_graph_model(
        observation,
        classification_model=classifier,
        learning_profile={"profile_id": "learning-profile-primary"},
        generated_at=FIXED_TIME,
    )
    second = build_behavior_graph_model(
        observation,
        classification_model=classifier,
        learning_profile={"profile_id": "learning-profile-primary"},
        generated_at=FIXED_TIME,
    )

    assert deterministic_behavior_graph_json(first) == deterministic_behavior_graph_json(second)
    assert [row["cluster_id"] for row in first["clusters"]] == [row["cluster_id"] for row in second["clusters"]]
    assert all(row["cluster_id"].startswith("graph-cluster-") for row in first["clusters"])
    assert all(0.0 <= float(row["confidence_score"]) <= 1.0 for row in first["clusters"])
    assert all(row["member_count"] >= 1 for row in first["clusters"])
    assert first["summary"]["cluster_count"] == len(first["clusters"])
    assert first["summary"]["strongest_cluster"].startswith("graph-cluster-")
    assert first["summary"]["strongest_cluster_type"] in {row["cluster_type"] for row in first["clusters"]}


def test_behavior_graph_cluster_analysis_derives_risk_levels_and_primary_cluster():
    base = {
        "node_id": "asset-a",
        "service_name": "frontend",
        "protocol": "tcp",
        "port": 443,
        "flow_id": "flow-1",
        "source_mode": "live",
    }
    cases = [
        (
            "low",
            dict(base),
            {"top_classification": "nginx", "confidence": 0.30},
            {"stability_score": 0.80, "observation_count": 6},
            {"historical_summary": {"stability_score": 0.80, "drift_score": 0.0, "historical_observations": 6}},
        ),
        (
            "medium",
            {**base, "score": 0.45},
            {"top_classification": "nginx", "confidence": 0.55},
            {"stability_score": 0.45, "observation_count": 3},
            {"historical_summary": {"stability_score": 0.45, "drift_score": 0.25, "historical_observations": 3}},
        ),
        (
            "high",
            {**base, "score": 0.75},
            {"top_classification": "nginx", "confidence": 0.65},
            {"stability_score": 0.25, "observation_count": 3},
            {"historical_summary": {"stability_score": 0.25, "drift_score": 0.55, "historical_observations": 3}},
        ),
        (
            "critical",
            {**base, "score": 0.92, "score_factors": ["a", "b", "c", "d"]},
            {"top_classification": "nginx", "confidence": 0.85},
            {"stability_score": 0.20, "observation_count": 5},
            {"historical_summary": {"stability_score": 0.20, "drift_score": 0.85, "historical_observations": 5}},
        ),
    ]

    for expected_risk, observation, classifier, profile, history in cases:
        graph = build_behavior_graph_model(
            observation,
            classification_model=classifier,
            learning_profile=profile,
            learning_profile_history=history,
            generated_at=FIXED_TIME,
        )
        primary = next(row for row in graph["clusters"] if row["cluster_id"] == graph["summary"]["primary_cluster"])

        assert graph["summary"]["primary_cluster_risk"] == expected_risk
        assert primary["cluster_risk_level"] == expected_risk
        assert 0.0 <= primary["cluster_confidence"] <= 1.0
        assert 0.0 <= graph["summary"]["primary_cluster_confidence"] <= 1.0
        assert primary["primary_reason"].startswith(f"{expected_risk}_risk_")
        assert primary["evidence_summary"]


def test_behavior_graph_cluster_analysis_derives_stability_and_drift_labels():
    sparse = build_behavior_graph_model(
        {"node_id": "asset-a", "service_name": "frontend", "protocol": "tcp", "port": 443},
        classification_model={"top_classification": "nginx", "confidence": 0.40},
        learning_profile={"stability_score": 0.0, "observation_count": 1},
        learning_profile_history={"historical_summary": {"stability_score": 0.0, "drift_score": 0.0, "historical_observations": 1}},
        generated_at=FIXED_TIME,
    )
    stable = build_behavior_graph_model(
        {"node_id": "asset-a", "service_name": "frontend", "protocol": "tcp", "port": 443, "flow_id": "flow-1"},
        classification_model={"top_classification": "nginx", "confidence": 0.70},
        learning_profile={"stability_score": 0.80, "observation_count": 6},
        learning_profile_history={"historical_summary": {"stability_score": 0.80, "drift_score": 0.0, "historical_observations": 6}},
        generated_at=FIXED_TIME,
    )
    unstable = build_behavior_graph_model(
        {"node_id": "asset-a", "service_name": "frontend", "protocol": "tcp", "port": 443, "flow_id": "flow-1"},
        classification_model={"top_classification": "nginx", "confidence": 0.70},
        learning_profile={"stability_score": 0.20, "observation_count": 4},
        learning_profile_history={"historical_summary": {"stability_score": 0.20, "drift_score": 0.72, "historical_observations": 4}},
        generated_at=FIXED_TIME,
    )

    assert {row["cluster_stability"] for row in sparse["clusters"]}.issubset({"sparse", "unknown"})
    assert "stable" in {row["cluster_stability"] for row in stable["clusters"]}
    assert "unstable" in {row["cluster_stability"] for row in unstable["clusters"]}
    assert {row["cluster_drift"] for row in sparse["clusters"]} == {"none"}
    assert "high" in {row["cluster_drift"] for row in unstable["clusters"]}


def test_behavior_graph_cluster_evolution_derives_temporal_trends_and_deltas():
    base = {
        "node_id": "asset-a",
        "service_name": "frontend",
        "protocol": "tcp",
        "port": 443,
        "flow_id": "flow-1",
        "score_factors": ["risk-signal-a"],
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-02T00:00:00+00:00",
        "source_mode": "live",
    }
    classifier = {"top_classification": "nginx", "confidence": 0.70}
    cases = [
        ("emerging", dict(base), 1, 0, 1, 0),
        (
            "growing",
            {**base, "previous_relationship_count": 0, "previous_signal_count": 0, "previous_entity_count": 0},
            1,
            0,
            1,
            0,
        ),
        (
            "shrinking",
            {**base, "previous_relationship_count": 9, "previous_signal_count": 4, "previous_entity_count": 9},
            0,
            8,
            0,
            3,
        ),
        (
            "stable",
            {**base, "previous_relationship_count": 1, "previous_signal_count": 1, "previous_entity_count": 2},
            0,
            0,
            0,
            0,
        ),
    ]

    for trend, observation, new_relationships, lost_relationships, new_signals, lost_signals in cases:
        graph = build_behavior_graph_model(
            observation,
            classification_model=classifier,
            generated_at="2026-01-02T00:00:00+00:00",
        )
        primary = next(row for row in graph["clusters"] if row["cluster_id"] == graph["summary"]["primary_cluster"])

        assert primary["cluster_trend"] == trend
        assert graph["summary"]["primary_cluster_trend"] == trend
        assert primary["cluster_age"] == "24h"
        assert graph["summary"]["primary_cluster_age"] == "24h"
        assert primary["new_relationships"] == new_relationships
        assert primary["lost_relationships"] == lost_relationships
        assert primary["new_signals"] == new_signals
        assert primary["lost_signals"] == lost_signals
        assert 0.0 <= primary["cluster_evolution_score"] <= 1.0
        assert graph["summary"]["primary_cluster_evolution_score"] == primary["cluster_evolution_score"]
        assert f"{primary['cluster_type']}:{trend}" in primary["evolution_summary"]
        assert f"trend:{trend}" in primary["trend_summary"]


def test_behavior_graph_cluster_evolution_derives_dormant_and_unknown_states():
    dormant = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-02T00:00:00+00:00",
            "source_mode": "live",
        },
        generated_at="2026-01-02T00:00:00+00:00",
    )
    dormant_primary = next(
        row for row in dormant["clusters"] if row["cluster_id"] == dormant["summary"]["primary_cluster"]
    )
    unknown = build_behavior_graph_model(
        {"node_id": "asset-a", "source_mode": "fixture"},
    )
    unknown_primary = next(
        row for row in unknown["clusters"] if row["cluster_id"] == unknown["summary"]["primary_cluster"]
    )

    assert dormant_primary["cluster_trend"] == "dormant"
    assert dormant["summary"]["primary_cluster_trend"] == "dormant"
    assert dormant_primary["cluster_age"] == "24h"
    assert dormant_primary["new_relationships"] == 0
    assert dormant_primary["lost_relationships"] == 0
    assert dormant_primary["new_signals"] == 0
    assert dormant_primary["lost_signals"] == 0
    assert unknown_primary["cluster_trend"] == "unknown"
    assert unknown["summary"]["primary_cluster_trend"] == "unknown"
    assert unknown["summary"]["primary_cluster_age"] == "-"


def test_behavior_graph_cluster_evolution_primary_summary_selects_primary_cluster_fields():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "service_name": "frontend",
            "protocol": "tcp",
            "port": 443,
            "flow_id": "flow-1",
            "score": 0.72,
            "score_factors": ["risk-signal-a", "risk-signal-b"],
            "previous_relationship_count": 9,
            "previous_signal_count": 5,
            "previous_entity_count": 9,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-03T00:00:00+00:00",
            "source_mode": "live",
        },
        classification_model={"top_classification": "nginx", "confidence": 0.72},
        learning_profile_history={"historical_summary": {"drift_score": 0.65}},
        generated_at="2026-01-03T00:00:00+00:00",
    )
    primary = next(row for row in graph["clusters"] if row["cluster_id"] == graph["summary"]["primary_cluster"])

    assert graph["summary"]["primary_cluster_trend"] == primary["cluster_trend"]
    assert graph["summary"]["primary_cluster_age"] == primary["cluster_age"]
    assert graph["summary"]["primary_cluster_evolution_score"] == primary["cluster_evolution_score"]
    assert graph["summary"]["primary_cluster_new_relationships"] == primary["new_relationships"]
    assert graph["summary"]["primary_cluster_lost_relationships"] == primary["lost_relationships"]
    assert graph["summary"]["primary_cluster_new_signals"] == primary["new_signals"]
    assert graph["summary"]["primary_cluster_lost_signals"] == primary["lost_signals"]
    assert graph["summary"]["primary_cluster_evolution_summary"] == primary["evolution_summary"]
    assert graph["summary"]["primary_cluster_trend_summary"] == primary["trend_summary"]


def test_behavior_graph_insights_are_generated_ranked_and_deterministic():
    observation = {
        "node_id": "asset-a",
        "service_name": "frontend",
        "protocol": "tcp",
        "port": 443,
        "flow_id": "flow-1",
        "score": 0.92,
        "score_factors": ["s1", "s2", "s3", "s4"],
        "previous_relationship_count": 0,
        "previous_signal_count": 0,
        "previous_entity_count": 0,
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-02T00:00:00+00:00",
        "source_mode": "live",
    }
    classifier = {
        "top_classification": "nginx",
        "confidence": 0.42,
        "candidates": [
            {"candidate": "nginx", "probability": 0.42},
            {"candidate": "apache", "probability": 0.35},
            {"candidate": "caddy", "probability": 0.23},
        ],
    }
    history = {"historical_summary": {"stability_score": 0.20, "drift_score": 0.72, "historical_observations": 4}}

    first = build_behavior_graph_model(
        observation,
        classification_model=classifier,
        learning_profile_history=history,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    second = build_behavior_graph_model(
        observation,
        classification_model=classifier,
        learning_profile_history=history,
        generated_at="2026-01-02T00:00:00+00:00",
    )
    strongest = sorted(
        first["insights"],
        key=lambda row: (-float(row["insight_score"]), row["insight_type"], row["insight_id"]),
    )[0]

    assert deterministic_behavior_graph_json(first) == deterministic_behavior_graph_json(second)
    assert [row["insight_id"] for row in first["insights"]] == [row["insight_id"] for row in second["insights"]]
    assert first["summary"]["graph_insight_count"] == len(first["insights"])
    assert first["summary"]["strongest_graph_insight"] == strongest["insight_id"]
    assert first["summary"]["strongest_graph_insight_score"] == strongest["insight_score"]
    assert first["summary"]["strongest_graph_insight_type"] == strongest["insight_type"]
    assert first["summary"]["graph_insight_summary"] != "-"
    assert first["summary"]["graph_operator_next_steps"] == strongest["operator_next_steps"]
    assert all(row["insight_id"].startswith("graph-insight-") for row in first["insights"])
    assert all(0.0 <= row["insight_score"] <= 1.0 for row in first["insights"])
    assert all(row["advisory_only"] is True and row["read_only"] is True for row in first["insights"])


def test_behavior_graph_insights_cover_high_risk_repeated_and_dense_relationships():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "service_name": "frontend",
            "related_services": ["backend"],
            "protocol": "tcp",
            "port": 443,
            "flow_id": "flow-1",
            "score": 0.94,
            "score_factors": ["risk-a", "risk-b", "risk-c", "risk-d"],
            "previous_relationship_count": 0,
            "previous_signal_count": 0,
            "previous_entity_count": 0,
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-02T00:00:00+00:00",
            "source_mode": "live",
        },
        classification_model={"top_classification": "nginx", "confidence": 0.62},
        learning_profile_history={"historical_summary": {"stability_score": 0.25, "drift_score": 0.65}},
        generated_at="2026-01-02T00:00:00+00:00",
    )
    insight_types = {row["insight_type"] for row in graph["insights"]}

    assert "emerging_risk_cluster" in insight_types
    assert "repeated_risk_signal" in insight_types
    assert "high_relationship_density" in insight_types
    assert graph["summary"]["graph_insight_count"] >= 3
    assert "emerging_risk_cluster" in graph["summary"]["graph_insight_summary"]


def test_behavior_graph_insights_cover_ambiguous_application_clusters():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "service_name": "web",
            "protocol": "tcp",
            "port": 443,
            "flow_id": "flow-1",
            "source_mode": "live",
        },
        classification_model={
            "top_classification": "nginx",
            "confidence": 0.44,
            "candidates": [
                {"candidate": "nginx", "probability": 0.44},
                {"candidate": "apache", "probability": 0.36},
                {"candidate": "caddy", "probability": 0.20},
            ],
        },
        generated_at=FIXED_TIME,
    )
    ambiguous = [row for row in graph["insights"] if row["insight_type"] == "ambiguous_application_cluster"]

    assert ambiguous
    assert ambiguous[0]["evidence_count"] >= 2
    assert "Multiple application candidates" in ambiguous[0]["summary"]


def test_behavior_graph_insights_cover_low_confidence_high_risk_clusters():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "service_name": "unknown-admin",
            "protocol": "tcp",
            "port": 9443,
            "score": 0.95,
            "score_factors": ["risk-a", "risk-b", "risk-c", "risk-d"],
            "source_mode": "live",
        },
        classification_model={"top_classification": "unknown_application", "confidence": 0.20},
        learning_profile_history={"historical_summary": {"stability_score": 0.10, "drift_score": 0.82}},
        generated_at=FIXED_TIME,
    )
    low_confidence = [row for row in graph["insights"] if row["insight_type"] == "low_confidence_high_risk"]

    assert low_confidence
    assert low_confidence[0]["insight_score"] > 0.50
    assert "Gather more metadata" in low_confidence[0]["operator_next_steps"]


def test_behavior_graph_risk_evolution_handles_insufficient_history():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "service_name": "web",
            "protocol": "tcp",
            "port": 443,
            "score": 0.62,
            "score_factors": ["risk-a"],
            "count": 1,
            "source_mode": "live",
        },
        classification_model={"top_classification": "nginx", "confidence": 0.58},
        generated_at=FIXED_TIME,
    )
    summary = graph["summary"]

    assert summary["previous_risk_score"] == "-"
    assert summary["current_risk_score"] == 0.62
    assert summary["risk_delta"] == "-"
    assert summary["risk_evolution_direction"] == "insufficient_history"
    assert summary["risk_evolution_velocity"] == "unknown"
    assert summary["risk_evolution_confidence"] == 0.20
    assert "insufficient_history" in summary["risk_change_reasons"]
    assert "Collect additional observations" in summary["risk_operator_next_steps"]


def test_behavior_graph_risk_evolution_derives_direction_and_velocity():
    cases = [
        (0.30, 0.74, [0.30, 0.52, 0.74], "increasing", "rapid"),
        (0.82, 0.56, [0.82, 0.70, 0.56], "decreasing", "moderate"),
        (0.50, 0.53, [0.50, 0.52, 0.53], "stable", "slow"),
        (0.40, 0.78, [0.40, 0.72, 0.48, 0.78], "fluctuating", "rapid"),
    ]

    for previous, current, history, direction, velocity in cases:
        graph = build_behavior_graph_model(
            {
                "node_id": "asset-a",
                "service_name": "web",
                "protocol": "tcp",
                "port": 443,
                "score": current,
                "previous_risk_score": previous,
                "risk_score_history": history,
                "score_factors": ["risk-a", "risk-b"],
                "count": len(history),
                "source_mode": "live",
            },
            classification_model={"top_classification": "nginx", "confidence": 0.72},
            generated_at=FIXED_TIME,
        )
        summary = graph["summary"]

        assert summary["risk_evolution_direction"] == direction
        assert summary["risk_evolution_velocity"] == velocity
        assert 0.0 <= summary["risk_evolution_confidence"] <= 1.0
        assert summary["risk_delta"] == round(current - previous, 2)


def test_behavior_graph_risk_evolution_tracks_signal_relationship_and_cluster_changes():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "service_name": "frontend",
            "related_services": ["backend", "cache"],
            "protocol": "tcp",
            "port": 443,
            "score": 0.88,
            "previous_risk_score": 0.44,
            "risk_score_history": [0.44, 0.60, 0.88],
            "score_factors": ["risk-b", "risk-c"],
            "previous_risk_signals": ["risk-a", "risk-b"],
            "previous_relationship_count": 0,
            "previous_signal_count": 4,
            "previous_cluster_count": 0,
            "count": 3,
            "source_mode": "live",
        },
        classification_model={
            "top_classification": "nginx",
            "confidence": 0.42,
            "candidates": [
                {"candidate": "nginx", "probability": 0.42},
                {"candidate": "apache", "probability": 0.35},
            ],
        },
        learning_profile_history={"historical_summary": {"stability_score": 0.20, "drift_score": 0.70}},
        generated_at=FIXED_TIME,
    )
    reasons = graph["summary"]["risk_change_reasons"].split("; ")

    assert reasons == sorted(reasons)
    assert "signal_added:risk-c" in reasons
    assert "signal_removed:risk-a" in reasons
    assert any(reason.startswith("relationships_added:") for reason in reasons)
    assert any(reason.startswith("signals_removed:") for reason in reasons)
    assert any(reason.startswith("clusters_expanded:") for reason in reasons)
    assert "classification_confidence:0.42" in reasons


def test_behavior_graph_risk_evolution_tracks_relationship_removal_and_cluster_shrinkage():
    graph = build_behavior_graph_model(
        {
            "node_id": "asset-a",
            "service_name": "frontend",
            "protocol": "tcp",
            "port": 443,
            "score": 0.30,
            "previous_risk_score": 0.68,
            "risk_score_history": [0.68, 0.44, 0.30],
            "score_factors": ["risk-a"],
            "previous_relationship_count": 20,
            "previous_signal_count": 0,
            "previous_cluster_count": 20,
            "count": 4,
            "source_mode": "live",
        },
        classification_model={"top_classification": "nginx", "confidence": 0.74},
        generated_at=FIXED_TIME,
    )
    reasons = graph["summary"]["risk_change_reasons"].split("; ")

    assert graph["summary"]["risk_evolution_direction"] == "decreasing"
    assert any(reason.startswith("relationships_removed:") for reason in reasons)
    assert any(reason.startswith("signals_added:") for reason in reasons)
    assert any(reason.startswith("clusters_shrank:") for reason in reasons)


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
