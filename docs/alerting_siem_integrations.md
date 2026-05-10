# Alerting and SIEM Integrations

Phase 37 adds local alert-formatting and explicitly invoked delivery helpers for common operator and SIEM destinations. The implementation focuses on deterministic payload generation, dry-run defaults, and failure isolation.

## Scope

The implementation lives under `core_engine.integrations`:

- `common.py` normalizes alert events and delivery results.
- `webhook.py` formats generic webhook, Slack-compatible, and Teams-compatible payloads and can explicitly POST JSON.
- `splunk.py` formats Splunk HEC events and can explicitly send to HEC with a token.
- `elastic.py` formats Elastic documents and bulk NDJSON payloads.
- `sentinel.py` formats Microsoft Sentinel-ready alert JSON.
- `email.py` formats email alerts and can explicitly send through SMTP.

The CLI command is:

```bash
portmap alert --event-json '{"severity":"critical","title":"Critical Apache vulnerability","summary":"Apache HTTP Server requires review.","target":"203.0.113.10"}' --format slack --output json
```

Formatting is the default. Network or SMTP delivery only occurs when `--send` is provided with the required destination options.

## Formats

Supported formats:

- `generic`
- `slack`
- `teams`
- `splunk`
- `elastic`
- `sentinel`
- `email`

Examples:

```bash
portmap alert --event-json '{"title":"High risk service","severity":"high"}' --format teams --output json
portmap alert --event-json '{"title":"High risk service","severity":"high"}' --format splunk --index security --output json
portmap alert --event-json '{"title":"High risk service","severity":"high"}' --format elastic --bulk --output json
portmap alert --event-json '{"title":"High risk service","severity":"high"}' --format email --sender alerts@example.test --recipient ops@example.test --output json
```

Explicit delivery examples:

```bash
portmap alert --event-json '{"title":"High risk service","severity":"high"}' --format slack --url https://hooks.example.test/services/... --send --output json
portmap alert --event-json '{"title":"High risk service","severity":"high"}' --format email --sender alerts@example.test --recipient ops@example.test --smtp-host smtp.example.test --send --output json
```

## Output

The command returns:

- `ok`
- `format`
- `payload`
- `delivery`
- `automatic_changes`
- `raw_payload_stored`

Delivery results include:

- `ok`
- `integration`
- `destination`
- `status`
- `detail`
- `dry_run`

Delivery helpers catch exceptions and return structured failed results instead of interrupting the caller.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. The integration layer sends network or email traffic only when `--send` is explicitly used, does not store destination secrets, and avoids background delivery loops.

Future background alerting should keep failure isolation, bounded retries, and secret redaction as hard requirements.
