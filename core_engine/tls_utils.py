from __future__ import annotations

import ssl
from pathlib import Path
from typing import Dict, Optional


def _resolve_path(path: str | None) -> Optional[str]:
    if not path:
        return None
    return str(Path(path).expanduser())


def create_client_context(config: Dict[str, any]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    verify = config.get("verify", True)
    ca_cert = _resolve_path(config.get("ca_cert"))
    if verify:
        if ca_cert:
            ctx.load_verify_locations(cafile=ca_cert)
        else:
            ctx.load_default_certs()
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    cert = _resolve_path(config.get("cert"))
    key = _resolve_path(config.get("key"))
    if cert and key:
        ctx.load_cert_chain(certfile=cert, keyfile=key, password=config.get("key_password"))

    if ciphers := config.get("ciphers"):
        ctx.set_ciphers(ciphers)
    return ctx


def create_server_context(config: Dict[str, any]) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    cert = _resolve_path(config.get("cert"))
    key = _resolve_path(config.get("key"))
    if not cert or not key:
        raise ValueError("Server TLS requires cert and key")
    ctx.load_cert_chain(certfile=cert, keyfile=key, password=config.get("key_password"))

    ca_cert = _resolve_path(config.get("ca_cert"))
    require_client = config.get("require_client_auth", False)
    if ca_cert:
        ctx.load_verify_locations(cafile=ca_cert)
        ctx.verify_mode = ssl.CERT_REQUIRED if require_client else ssl.CERT_OPTIONAL
    else:
        ctx.verify_mode = ssl.CERT_NONE

    if ciphers := config.get("ciphers"):
        ctx.set_ciphers(ciphers)

    return ctx


def merge_tls_config(settings: Dict[str, any], config: Dict[str, any]) -> Dict[str, any]:
    base = dict(settings or {})
    overrides = dict(config or {})
    merged = {**base, **overrides}
    return merged
