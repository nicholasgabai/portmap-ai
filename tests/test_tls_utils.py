import ssl
import pytest

from core_engine.tls_utils import create_client_context, create_server_context, merge_tls_config


def test_merge_tls_config():
    base = {"enabled": False, "verify": True}
    override = {"enabled": True, "cert": "worker.crt"}
    merged = merge_tls_config(base, override)
    assert merged["enabled"] is True
    assert merged["verify"] is True
    assert merged["cert"] == "worker.crt"


def test_client_context_no_verify(monkeypatch, tmp_path):
    ctx = create_client_context({"enabled": True, "verify": False})
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode == ssl.CERT_NONE
    assert ctx.check_hostname is False


def test_server_context_requires_cert(tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("dummy")
    key.write_text("dummy")
    with pytest.raises(Exception):
        create_server_context({"enabled": True, "cert": str(cert), "key": str(key), "require_client_auth": False})
