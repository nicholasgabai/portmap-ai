import ai_agent.scoring as scoring
from ai_agent.interface import AIAnalysisResult
from ai_agent.scoring import explain_score, get_score, heuristic_score


def test_heuristic_score_is_deterministic_for_same_connection():
    connection = {
        "program": "postgres",
        "pid": 101,
        "port": 5432,
        "payload": "",
        "flags": "L",
        "protocol": "TCP",
        "status": "LISTEN",
        "direction": "incoming",
        "local": "127.0.0.1:5432",
        "remote": "-",
    }

    score_a, factors_a = heuristic_score(connection)
    score_b, factors_b = heuristic_score(connection)

    assert score_a == score_b
    assert factors_a == factors_b


def test_public_remote_connection_scores_higher_than_loopback():
    base = {
        "program": "python",
        "pid": 202,
        "port": 8080,
        "payload": "",
        "flags": "E",
        "protocol": "HTTP",
        "status": "ESTABLISHED",
        "direction": "outgoing",
        "local": "10.0.0.5:54000",
    }

    public_score, public_factors = heuristic_score({**base, "remote": "8.8.8.8:443"})
    loopback_score, loopback_factors = heuristic_score({**base, "remote": "127.0.0.1:443"})

    assert public_score > loopback_score
    assert "public_remote_ip" in public_factors
    assert "loopback_remote" in loopback_factors


def test_get_score_persists_factors_without_ml(monkeypatch):
    monkeypatch.setattr(scoring, "load_settings", lambda defaults=None: {"expected_services": []})

    connection = {
        "program": "unknown",
        "pid": 0,
        "port": 3306,
        "payload": "SELECT 1",
        "flags": "",
        "protocol": "MySQL",
        "status": "ESTABLISHED",
        "direction": "outgoing",
        "local": "10.0.0.5:3306",
        "remote": "44.55.66.77:5000",
    }

    score = get_score(connection, use_ml=False)

    assert isinstance(score, float)
    assert score >= 0.75
    assert "score_factors" in connection
    assert "public_remote_ip" in connection["score_factors"]
    assert "risk_explanation" in connection
    assert "Risk score" in connection["risk_explanation"]


def test_expected_service_reduces_score_and_explains_factor():
    connection = {
        "program": "mysqld",
        "pid": 303,
        "port": 3306,
        "payload": "",
        "flags": "L",
        "protocol": "MySQL",
        "status": "LISTEN",
        "direction": "incoming",
        "local": "127.0.0.1:3306",
        "remote": "-",
    }

    baseline_score, baseline_factors = heuristic_score(connection)
    expected_score, expected_factors = heuristic_score(
        connection,
        expected_services=[
            {"port": 3306, "protocol": "MySQL", "program": "mysql", "reason": "local dev database"}
        ],
    )

    assert expected_score < baseline_score
    assert "sensitive_port:3306" in baseline_factors
    assert "expected_service:local dev database" in expected_factors


def test_known_risky_port_adds_service_severity_factor():
    connection = {
        "program": "rdp-service",
        "pid": 404,
        "port": 3389,
        "payload": "",
        "flags": "L",
        "protocol": "TCP",
        "status": "LISTEN",
        "direction": "incoming",
        "local": "0.0.0.0:3389",
        "remote": "-",
    }

    score, factors = heuristic_score(connection)

    assert score >= 0.75
    assert "risky_port:3389:RDP:critical" in factors
    assert "binds_all_interfaces" in factors


def test_explain_score_turns_factors_into_reasoning():
    explanation = explain_score(
        0.91,
        ["risky_port:3389:RDP:critical", "binds_all_interfaces", "public_remote_ip"],
    )

    assert "RDP on port 3389 is classified as critical risk" in explanation
    assert "listening on all interfaces" in explanation


def test_get_score_uses_injected_ai_provider(monkeypatch):
    monkeypatch.setattr(scoring, "load_settings", lambda defaults=None: {"expected_services": []})

    class StubProvider:
        name = "stub"

        def analyze(self, connection, context=None):
            return AIAnalysisResult(
                score=0.42,
                factors=["stub_factor"],
                explanation="Risk score 0.420: stub factor.",
                provider="stub",
                label="normal",
            )

    connection = {"program": "demo", "port": 8080, "protocol": "TCP"}

    try:
        scoring.set_ai_provider(StubProvider())
        score = get_score(connection, use_ml=False)
    finally:
        scoring.reset_ai_provider()

    assert score == 0.42
    assert connection["score"] == 0.42
    assert connection["score_factors"] == ["stub_factor"]
    assert connection["risk_explanation"] == "Risk score 0.420: stub factor."
    assert connection["ai_provider"] == "stub"
    assert connection["ml_flag"] == "normal"


def test_get_score_falls_back_when_ai_provider_fails(monkeypatch):
    monkeypatch.setattr(scoring, "load_settings", lambda defaults=None: {"expected_services": []})

    class BrokenProvider:
        name = "broken"

        def analyze(self, connection, context=None):
            raise RuntimeError("provider unavailable")

    connection = {
        "program": "unknown",
        "pid": 0,
        "port": 23,
        "payload": "",
        "flags": "",
        "protocol": "Telnet",
        "status": "LISTEN",
        "direction": "incoming",
        "local": "0.0.0.0:23",
        "remote": "-",
    }

    try:
        scoring.set_ai_provider(BrokenProvider())
        score = get_score(connection, use_ml=False)
    finally:
        scoring.reset_ai_provider()

    assert score > 0
    assert connection["ai_provider"] == "heuristic_fallback"
    assert "ai_provider_failed" in connection["score_factors"]
    assert connection["ai_metadata"]["failed_provider"] == "broken"
