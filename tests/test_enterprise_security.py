from core_engine.agent_identity import (
    build_enterprise_agent_identity,
    sign_agent_message,
    validate_enterprise_agent_identity,
    verify_agent_message_signature,
)
from core_engine.enterprise_audit import build_enterprise_audit_event
from core_engine.enterprise_auth import (
    build_user_record,
    issue_token,
    public_user_record,
    verify_password,
    verify_token,
)
from core_engine.rbac import authorize, has_permission, permissions_for_roles, role_report, validate_roles


def test_rbac_role_inheritance_and_authorization():
    assert has_permission(["admin"], "read:nodes") is True
    assert has_permission(["analyst"], "generate:recommendations") is True
    assert has_permission(["viewer"], "manage:users") is False
    assert "read:nodes" in permissions_for_roles(["analyst"])

    decision = authorize(["viewer"], "manage:users")

    assert decision["ok"] is False
    assert decision["granted"] is False
    assert validate_roles(["unknown"]) == ["unknown role: unknown"]
    assert "admin" in role_report()["roles"]


def test_issue_and_verify_enterprise_token():
    token = issue_token(
        subject="alice",
        roles=["analyst"],
        secret="signing-secret",
        now=100,
        ttl_seconds=60,
        extra_claims={"tenant_id": "tenant.local"},
    )

    verified = verify_token(token, secret="signing-secret", now=120)

    assert verified["ok"] is True
    assert verified["claims"]["sub"] == "alice"
    assert verified["claims"]["roles"] == ["analyst"]
    assert verified["claims"]["tenant_id"] == "tenant.local"
    assert verified["raw_token_stored"] is False


def test_verify_enterprise_token_rejects_expired_and_tampered_values():
    token = issue_token(subject="alice", roles=["viewer"], secret="signing-secret", now=100, ttl_seconds=10)

    expired = verify_token(token, secret="signing-secret", now=111)
    tampered = verify_token(token + "x", secret="signing-secret", now=105)

    assert expired["ok"] is False
    assert "token is expired" in expired["errors"]
    assert tampered["ok"] is False
    assert "invalid signature" in tampered["errors"]


def test_password_records_store_hashes_and_public_records_redact_hash():
    user = build_user_record(username="alice", password="correct horse battery staple", roles="admin", now=123)

    assert verify_password("correct horse battery staple", user["password_hash"]) is True
    assert verify_password("wrong", user["password_hash"]) is False
    public = public_user_record(user)
    assert "password_hash" not in public
    assert public["password_hash_fingerprint"]
    assert public["roles"] == ["admin"]


def test_enterprise_audit_scrubs_secret_metadata():
    event = build_enterprise_audit_event(
        actor="alice",
        action="manage:users",
        status="denied",
        resource="users/bob",
        roles=["viewer"],
        tenant_id="tenant.local",
        metadata={"api_key": "secret-value", "safe": "ok"},
        timestamp=123.0,
    )

    assert event["event_type"] == "enterprise_security"
    assert event["metadata"]["safe"] == "ok"
    assert "secret-value" not in str(event)
    assert event["metadata"]["api_key"].startswith("<redacted:")


def test_enterprise_agent_identity_stores_fingerprints_and_supports_mtls_marker():
    identity, generated_secret = build_enterprise_agent_identity(
        agent_id="worker-001",
        tenant_id="tenant.local",
        role="agent",
        certificate_fingerprint="sha256:abc123",
        issued_at=100,
    )

    payload = identity.to_dict()

    assert generated_secret
    assert generated_secret not in str(payload)
    assert payload["mtls_ready"] is True
    assert validate_enterprise_agent_identity(payload) == []


def test_agent_message_signature_checks_hmac_and_timestamp_skew():
    secret = "agent-secret"
    signature = sign_agent_message("worker-001", secret, 100, "{}")

    valid = verify_agent_message_signature(
        agent_id="worker-001",
        shared_secret=secret,
        timestamp=100,
        body="{}",
        signature=signature,
        now=120,
    )
    stale = verify_agent_message_signature(
        agent_id="worker-001",
        shared_secret=secret,
        timestamp=100,
        body="{}",
        signature=signature,
        now=1000,
    )
    bad = verify_agent_message_signature(
        agent_id="worker-001",
        shared_secret=secret,
        timestamp=100,
        body="{\"changed\":true}",
        signature=signature,
        now=100,
    )

    assert valid["ok"] is True
    assert stale["ok"] is False
    assert "agent signature timestamp outside allowed skew" in stale["errors"]
    assert bad["ok"] is False
    assert "invalid agent message signature" in bad["errors"]
