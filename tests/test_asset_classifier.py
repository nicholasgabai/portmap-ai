from core_engine.visualization import classify_asset, score_asset_confidence


def test_asset_classifier_uses_explicit_category():
    observation = {
        "asset_category": "printer",
        "service_hint": "ipp",
        "local_port": 631,
        "source_mode": "fixture",
    }

    assert classify_asset(observation) == "PRINTER"
    assert 0.0 <= score_asset_confidence(observation) <= 1.0
    assert score_asset_confidence(observation) >= 0.7


def test_asset_classifier_infers_common_asset_categories():
    assert classify_asset({"service_hint": "ssh", "local_port": 22}) == "SERVER"
    assert classify_asset({"service_hint": "nfs", "local_port": 2049}) == "NAS"
    assert classify_asset({"service_hint": "sip", "local_port": 5060}) == "PHONE"
    assert classify_asset({"service_hint": "mqtt", "local_port": 1883}) == "IOT"
    assert classify_asset({"role_hint": "gateway", "local_port": 53}) == "ROUTER"
    assert classify_asset({"role_hint": "switch"}) == "SWITCH"


def test_asset_classifier_keeps_unknown_when_evidence_is_sparse():
    observation = {"source_mode": "live", "local_endpoint_class": "unknown"}

    assert classify_asset(observation) == "UNKNOWN"
    assert score_asset_confidence(observation) <= 0.45


def test_asset_classifier_avoids_private_identifier_requirements():
    observation = {
        "service_hint": "browser",
        "local_endpoint_class": "client",
        "local_port": 52444,
        "source_mode": "live",
    }

    assert classify_asset(observation) == "WORKSTATION"
    assert 0.0 <= score_asset_confidence(observation) <= 1.0
