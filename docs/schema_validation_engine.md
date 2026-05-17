# Bounded Schema Validation Engine

Phase 54 adds local mock-service fixture validation helpers for PortMap-AI. The schema validation engine checks sanitized message-like or packet-like fixture dictionaries against bounded schema definitions. The fixture mutation engine creates controlled local variants for tests and operator review.

This phase is local-only and test-fixture based. It does not contact live targets, transmit data, capture interfaces, install services, modify configuration, change routers, or perform automatic response actions.

## Schema Shape

A schema defines expected fields and bounded validation rules:

```python
schema = {
    "name": "sample_message",
    "version": "sample-version",
    "fields": {
        "message_type": {
            "type": "str",
            "required": True,
            "allowed_values": ["sample_request", "sample_response"],
        },
        "sequence": {
            "type": "int",
            "required": True,
            "min_value": 1,
            "max_value": 99,
        },
        "payload_hex": {
            "type": "hex",
            "required": True,
            "min_length": 2,
            "max_length": 16,
        },
    },
}
```

Supported field types:

- `str`
- `hex`
- `int`
- `float`
- `bool`
- `bytes`
- `dict`
- `list`

Validation is intentionally bounded. Callers can set maximum field counts, string lengths, byte lengths, fixture sizes, and mutation counts.

## Validation Results

`validate_fixture()` returns JSON-serializable summaries:

```python
from core_engine.diagnostics import validate_fixture

fixture = {
    "message_type": "sample_request",
    "sequence": 7,
    "payload_hex": "414243",
}

result = validate_fixture(schema, fixture)
```

Result records include:

- `ok`
- `status`
- `classification`
- `schema_id`
- `field_results`
- `errors`
- `warnings`
- `raw_payload_stored: false`
- `automatic_changes: false`
- `administrator_controlled: true`

Classifications include:

- `valid`
- `invalid`
- `malformed`
- `unsupported`
- `mutation_limited`

## Fixture Mutation

`mutate_fixture()` creates bounded local variants for testing validators and mock-service behavior:

```python
from core_engine.diagnostics import mutate_fixture

mutation_result = mutate_fixture(schema, fixture, max_mutations=4)
```

Mutation types include:

- Missing required fields.
- Field length below minimum.
- Field length above maximum.
- Byte value mutation for byte or hex fields.
- Unexpected field insertion.
- Simple value boundary mutations.

Mutation output is JSON-safe. Byte values are summarized by type, length, and bounded hex summary instead of storing raw payload bytes.

## Intended Use

Use this phase for:

- Local unit tests.
- Local mock-service validation.
- Fixture quality checks.
- Operator review of schema mismatch summaries.
- Controlled mutation of sanitized test fixtures.

Do not use this phase for:

- Live target testing.
- Network transmission.
- Packet injection.
- External export.
- Automatic enforcement.
- Router or firewall changes.
- Service installation.

## Safety Boundaries

- Local mock-service testing only.
- No live targets.
- No external network transport.
- No background scanning.
- No automatic remediation.
- No raw payload persistence by default.
- Operator-controlled and advisory by design.

Use placeholders and sanitized examples only. Do not commit real IP addresses, MAC addresses, hostnames, usernames, tokens, secrets, screenshots, logs, local paths, runtime artifacts, or private validation notes.
