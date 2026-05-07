from core_engine.security import (
    extract_bearer_token,
    redact_secret,
    scrub_secrets,
    token_fingerprint,
    validate_node_identity,
    verify_bearer_header,
    verify_token,
)


def test_bearer_token_helpers_use_expected_scheme():
    assert extract_bearer_token("Bearer abc123") == "abc123"
    assert extract_bearer_token("Basic abc123") is None
    assert verify_bearer_header("Bearer abc123", "abc123") is True
    assert verify_bearer_header("Bearer wrong", "abc123") is False


def test_verify_token_allows_empty_expected_for_dev_mode():
    assert verify_token(None, None) is True
    assert verify_token("anything", "") is True
    assert verify_token(None, "required") is False


def test_scrub_secrets_redacts_nested_sensitive_keys():
    payload = {
        "node_id": "worker-1",
        "token": "secret-token",
        "nested": {"api_key": "abc", "safe": "value"},
    }

    scrubbed = scrub_secrets(payload)

    assert scrubbed["node_id"] == "worker-1"
    assert scrubbed["token"] == redact_secret("secret-token")
    assert scrubbed["nested"]["api_key"] == redact_secret("abc")
    assert scrubbed["nested"]["safe"] == "value"
    assert token_fingerprint("secret-token") in scrubbed["token"]


def test_validate_node_identity_rejects_bad_values():
    assert validate_node_identity("worker-1", "worker") == []
    errors = validate_node_identity("../bad", "router")

    assert "node_id must be" in errors[0]
    assert "role must be one of" in errors[1]
