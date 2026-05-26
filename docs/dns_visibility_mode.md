# DNS Visibility Mode

Phase 95 adds metadata-only DNS visibility records and domain-to-flow correlation for enriched telemetry. The feature is designed for local operator review and gateway-readiness workflows without intercepting traffic or changing DNS settings.

This feature does not capture credentials, retain packet payload contents, decrypt encrypted DNS, perform traffic interception, modify DNS settings, or automatically block anything.

## Records

`core_engine.telemetry.dns_visibility` provides:

- DNS query metadata records.
- DNS response metadata records.
- Resolver classification records.
- DNS timing summaries.
- Encrypted DNS visibility limitation summaries.
- NXDOMAIN and error response summaries.
- DNS anomaly hints.
- Dashboard/API-ready DNS visibility dictionaries.

Records include explicit safety fields such as:

- `metadata_only: true`
- `raw_payload_stored: false`
- `payload_bytes_stored: 0`
- `credentials_retained: false`
- `traffic_interception: false`
- `dns_settings_modified: false`
- `automatic_blocking: false`

## Domain Redaction

DNS visibility supports safe domain normalization and truncation. Public examples use documentation-safe domains only.

```python
from core_engine.telemetry import sanitize_domain_name

domain, governance = sanitize_domain_name(
    "service.example.test",
    max_length=120,
)
```

Governance fields report whether output was truncated or redacted and confirm that raw domains are not stored separately.

## Domain-To-Flow Correlation

`core_engine.telemetry.dns_correlation.build_dns_visibility_report` can correlate DNS response answers to enriched flow endpoints.

The correlation is advisory and local-only:

- DNS answer metadata is compared with flow endpoint metadata.
- Matched flow references are listed with confidence.
- Unmatched DNS responses remain visible.
- No DNS settings are changed.

## Resolver Classification

Resolver classification reports local, remote, encrypted, and unknown resolver states. Encrypted DNS is reported as a visibility limitation. PortMap-AI does not decrypt or intercept encrypted DNS.

## Anomaly Hints

DNS anomaly hints include DNS response errors, missing responses in the provided metadata window, empty NOERROR responses, and slow DNS response timing.

Hints are review evidence only and do not trigger enforcement.

## Safe Example

```python
from core_engine.telemetry import build_dns_visibility_report

report = build_dns_visibility_report(
    queries=[
        {
            "query_id": "query-placeholder",
            "query_name": "service.example.test",
            "query_type": "A",
            "timestamp": "2026-01-01T00:00:01+00:00",
            "resolver_ip": "203.0.113.53",
        }
    ],
    responses=[
        {
            "query_id": "query-placeholder",
            "query_name": "service.example.test",
            "query_type": "A",
            "timestamp": "2026-01-01T00:00:01.120000+00:00",
            "resolver_ip": "203.0.113.53",
            "response_code": "NOERROR",
            "answers": [{"answer_type": "A", "value": "198.51.100.20"}],
        }
    ],
    enriched_flows=enriched_flows,
)
```

Use sanitized fixtures and documentation ranges in public examples.
