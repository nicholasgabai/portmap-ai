# TLS Intelligence Layer

Phase 28 adds a read-only TLS intelligence layer for authorized endpoints. It evaluates TLS protocol posture, cipher-suite strength, and certificate metadata without attempting authentication, exploitation, remediation, or configuration changes.

## Scope

The TLS inspector lives in `core_engine.modules.tls_inspector` and provides:

- TLS version classification for modern, deprecated, and unknown protocol versions.
- Cipher-suite analysis for weak markers such as RC4, DES/3DES, MD5, NULL, EXPORT, anonymous suites, small key sizes, and CBC-mode warnings.
- Certificate parsing from Python `ssl` peer-certificate dictionaries and offline observations.
- Certificate expiration, soon-to-expire, self-signed, and hostname-mismatch warnings.
- SHA-256 certificate fingerprint capture when DER bytes are available from a live handshake.
- JSON-serializable output for CLI use, future dashboard surfaces, and future correlation layers.

The module supports live TLS handshakes where network access is available, and offline observation analysis for tests, logs, and operator-provided evidence.

## CLI Usage

Inspect an authorized endpoint:

```bash
portmap tls --target example.com --ports 443 --server-name example.com --output json
```

Inspect multiple authorized ports:

```bash
portmap tls --target 127.0.0.1 --ports 443,8443 --server-name localhost --output json
```

Analyze an offline observation without making a network connection:

```bash
portmap tls \
  --observation-json '{"target":"legacy.example.com","server_name":"legacy.example.com","tls_version":"TLSv1.0","cipher":{"name":"RC4-MD5","bits":64},"certificate":{"subject":{"commonName":"legacy.example.com"},"issuer":{"commonName":"Legacy CA"},"san_dns":["legacy.example.com"],"not_after":"2026-04-01T00:00:00+00:00"}}' \
  --output json
```

## Output Fields

Each row includes:

- `target`, `port`, `remote`, and optional `server_name`
- `ok`, `source`, and `duration_ms` for live checks
- `tls_version` with `version`, `status`, and warnings
- `cipher` with name, protocol, key bits, weak flag, and warnings
- `certificate` with subject, issuer, SANs, validity dates, expiry status, hostname match, self-signed status, and warnings
- consolidated `warnings`
- `risk_score`

Risk scores are advisory evidence for operator review. They do not trigger automatic blocking or remediation.

## Developer API

```python
from core_engine.modules.tls_inspector import analyze_tls_observation, inspect_tls_targets

offline = analyze_tls_observation({
    "target": "api.example.com",
    "server_name": "api.example.com",
    "tls_version": "TLSv1.3",
    "cipher": {"name": "TLS_AES_256_GCM_SHA384", "bits": 256},
    "certificate": {"san_dns": ["api.example.com"], "not_after": "2026-12-01T00:00:00+00:00"},
})

live_rows = inspect_tls_targets("api.example.com", ports=[443], server_name="api.example.com")
```

Tests should prefer offline observations or injected inspectors so CI does not depend on external networks.

## Safety Boundaries

TLS intelligence is inspection-only and follows the global PortMap-AI safety guarantees. It stores no private keys or secrets.

Future flow-correlation and anomaly phases should consume these structured TLS findings rather than raw certificate or packet material whenever possible.
