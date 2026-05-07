# Security And Authentication

Phase 15 hardens the existing bearer-token model without changing the local developer workflow.

## Orchestrator Bearer Token

The orchestrator API uses `Authorization: Bearer <token>` when a token is configured.

Token checks use constant-time comparison. Empty orchestrator tokens keep the API unauthenticated for isolated development only; remote, shared, Docker, Raspberry Pi, or SaaS-adjacent deployments should always set a long random token.

Recommended configuration:

```json
{
  "auth_token": "${secret:PORTMAP_ORCHESTRATOR_TOKEN}"
}
```

Then set the environment variable before launch:

```bash
export PORTMAP_ORCHESTRATOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

Workers, masters, dashboard, and CLI calls should use the same token through `orchestrator_token` or the `PORTMAP_ORCHESTRATOR_TOKEN` environment variable.

## Secret Interpolation

Configuration supports environment-backed secret placeholders:

```json
{
  "orchestrator_token": "${secret:PORTMAP_ORCHESTRATOR_TOKEN}"
}
```

The secret value is read from the named environment variable. Missing secret variables resolve to an empty string so validation and startup behavior remain explicit.

## Registration Hardening

Node registration now validates:

- `node_id` format and length;
- node role (`orchestrator`, `master`, or `worker`);
- command payload type for queued commands.

Invalid identities are rejected before they are persisted to orchestrator state.

## State Secret Scrubbing

Node metadata is scrubbed before being persisted. Keys containing words such as `token`, `secret`, `password`, `key`, or `credential` are replaced with a stable redacted fingerprint.

Example:

```json
{
  "orchestrator_token": "<redacted:abcd1234ef56>"
}
```

This preserves enough context for debugging without storing raw secrets in `~/.portmap-ai/data/orchestrator_state.json`.

## Validation

Config validation checks token field types and warns when default development tokens such as `test-token` remain configured.

Use:

```bash
portmap config validate core_engine/default_configs/orchestrator.json
portmap doctor
```

## Current Boundary

This phase hardens local/shared-token authentication. It does not yet implement:

- per-node credentials;
- token rotation protocol;
- mTLS enrollment;
- multi-tenant SaaS identity;
- browser/session authentication.

Those belong to later production/SaaS phases.
