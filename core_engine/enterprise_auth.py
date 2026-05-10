from __future__ import annotations

import base64
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
import time
from typing import Any

from core_engine.rbac import normalize_roles, validate_roles
from core_engine.security import token_fingerprint


JWT_ALGORITHM = "HS256"
PASSWORD_SCHEME = "pbkdf2_sha256"
DEFAULT_PASSWORD_ITERATIONS = 200_000


def issue_token(
    *,
    subject: str,
    secret: str,
    roles: list[str] | tuple[str, ...] | str,
    issuer: str = "portmap-ai",
    audience: str = "portmap-ai",
    ttl_seconds: int = 3600,
    now: int | None = None,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    if not subject:
        raise ValueError("subject is required")
    if not secret:
        raise ValueError("secret is required")
    role_list = normalize_roles(roles)
    role_errors = validate_roles(role_list)
    if role_errors:
        raise ValueError("; ".join(role_errors))
    issued_at = int(now if now is not None else time.time())
    payload = {
        "sub": subject,
        "iss": issuer,
        "aud": audience,
        "iat": issued_at,
        "nbf": issued_at,
        "exp": issued_at + int(ttl_seconds),
        "roles": role_list,
    }
    if extra_claims:
        protected = set(payload)
        payload.update({key: value for key, value in extra_claims.items() if key not in protected})
    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    signing_input = f"{_b64_json(header)}.{_b64_json(payload)}"
    signature = _sign(signing_input, secret)
    return f"{signing_input}.{signature}"


def verify_token(
    token: str,
    *,
    secret: str,
    audience: str | None = "portmap-ai",
    now: int | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    parts = str(token or "").split(".")
    if len(parts) != 3:
        return _verification_result(False, {}, ["token must have three JWT segments"], token)
    header_segment, payload_segment, signature = parts
    signing_input = f"{header_segment}.{payload_segment}"
    expected_signature = _sign(signing_input, secret)
    if not hmac.compare_digest(signature, expected_signature):
        errors.append("invalid signature")
    try:
        header = json.loads(_b64_decode(header_segment).decode("utf-8"))
        payload = json.loads(_b64_decode(payload_segment).decode("utf-8"))
    except (ValueError, json.JSONDecodeError) as exc:
        return _verification_result(False, {}, [f"invalid token encoding: {exc}"], token)
    if header.get("alg") != JWT_ALGORITHM:
        errors.append(f"unsupported algorithm: {header.get('alg')}")
    current_time = int(now if now is not None else time.time())
    if payload.get("nbf") is not None and current_time < int(payload["nbf"]):
        errors.append("token is not yet valid")
    if payload.get("exp") is not None and current_time >= int(payload["exp"]):
        errors.append("token is expired")
    if audience is not None and payload.get("aud") != audience:
        errors.append("token audience mismatch")
    errors.extend(validate_roles(payload.get("roles") or []))
    return _verification_result(not errors, payload, errors, token)


def create_password_hash(
    password: str,
    *,
    salt: bytes | None = None,
    iterations: int = DEFAULT_PASSWORD_ITERATIONS,
) -> str:
    if not password:
        raise ValueError("password is required")
    if iterations < 100_000:
        raise ValueError("password hash iterations must be at least 100000")
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return "$".join([
        PASSWORD_SCHEME,
        str(iterations),
        _b64_bytes(salt),
        _b64_bytes(digest),
    ])


def verify_password(password: str, password_hash: str) -> bool:
    try:
        scheme, iterations_text, salt_text, digest_text = password_hash.split("$", 3)
        if scheme != PASSWORD_SCHEME:
            return False
        iterations = int(iterations_text)
        salt = _b64_decode(salt_text)
        expected = _b64_decode(digest_text)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def build_user_record(
    *,
    username: str,
    password: str,
    roles: list[str] | tuple[str, ...] | str,
    display_name: str | None = None,
    now: int | None = None,
) -> dict[str, Any]:
    if not username:
        raise ValueError("username is required")
    role_list = normalize_roles(roles)
    role_errors = validate_roles(role_list)
    if role_errors:
        raise ValueError("; ".join(role_errors))
    created_at = int(now if now is not None else time.time())
    return {
        "username": username,
        "display_name": display_name or username,
        "roles": role_list,
        "password_hash": create_password_hash(password),
        "created_at": created_at,
        "disabled": False,
    }


def public_user_record(user: dict[str, Any]) -> dict[str, Any]:
    return {
        "username": user.get("username"),
        "display_name": user.get("display_name"),
        "roles": list(user.get("roles") or []),
        "created_at": user.get("created_at"),
        "disabled": bool(user.get("disabled")),
        "password_hash_fingerprint": token_fingerprint(user.get("password_hash")),
    }


def _verification_result(ok: bool, claims: dict[str, Any], errors: list[str], token: str) -> dict[str, Any]:
    return {
        "ok": ok,
        "claims": claims if ok else claims,
        "errors": errors,
        "token_fingerprint": token_fingerprint(token),
        "raw_token_stored": False,
    }


def _b64_json(value: dict[str, Any]) -> str:
    return _b64_bytes(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def _b64_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode((value + padding).encode("ascii"))


def _sign(signing_input: str, secret: str) -> str:
    digest = hmac.new(str(secret).encode("utf-8"), signing_input.encode("ascii"), hashlib.sha256).digest()
    return _b64_bytes(digest)


def utc_timestamp() -> int:
    return int(datetime.now(UTC).timestamp())
