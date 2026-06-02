# Encrypted Orchestration Transport

Phase 124 adds encrypted orchestration transport readiness records for future orchestrator, master, worker, and edge communication.

This phase is planning and preview only. It does not create certificates, create private keys, open network listeners, modify live orchestrator authentication, perform credential exchange, or run real mTLS handshakes.

## Transport Security Roadmap

PortMap-AI currently supports local and distributed runtime records without enabling encrypted live orchestration transport. Phase 124 introduces the metadata layer needed to review future secure transport posture before implementation.

The core record is `TransportSecurityProfile` in `core_engine/security/transport_security.py`.

Supported profiles:

- `plaintext_dev` - degraded local development posture.
- `tls_ready` - server-authenticated TLS readiness.
- `mtls_ready` - mutual TLS readiness.
- `pinned_cert_ready` - pinned certificate readiness.
- `production_required` - production policy requiring encrypted mutual authentication.

Supported states:

- `unavailable`
- `degraded`
- `ready`
- `required`

Every profile exports explicit safety fields:

- `certificate_generated: false`
- `private_key_material_present: false`
- `network_listener_changed: false`
- `live_auth_exchange_performed: false`
- `dry_run_only: true`
- `export_safe: true`

## Plaintext Development Versus Future mTLS

`plaintext_dev` is retained as a degraded local development profile for dry-run previews and tests. It should not be treated as production ready.

Future production transport should move toward:

- encrypted heartbeat channels
- mTLS readiness
- certificate rotation readiness
- pinned certificate or CA validation options
- explicit downgrade handling
- secure session negotiation

Phase 124 models these outcomes without generating certificates or private keys.

## Downgrade Warnings

Transport profiles and session previews include downgrade fields so operators can identify weaker negotiated transport posture.

A downgrade is reported when the negotiated transport is weaker than the requested transport. For example, a `production_required` request that falls back to `plaintext_dev` sets:

- `downgrade_detected: true`
- `operator_action_required: true`
- `downgrade_reason` with an operator-readable warning

## Session Negotiation Previews

`core_engine/security/session_negotiation.py` defines `SessionNegotiationPreview` records for:

- `orchestrator -> master`
- `orchestrator -> worker`
- `master -> worker`
- `edge -> orchestrator`

Preview records include:

- `session_id`
- `source_role`
- `target_role`
- `requested_transport`
- `negotiated_transport`
- `encryption_required`
- `mutual_auth_required`
- `downgrade_detected`
- `downgrade_reason`
- `trust_state`
- `operator_action_required`
- `dry_run_only`

Preview records do not perform live negotiation, credential exchange, or mTLS handshakes.

## Secure Heartbeat Goals

Future encrypted orchestration transport should support secure heartbeat summaries between approved nodes. The Phase 124 records are intended to feed:

- secure node identity
- enrollment previews
- trust-chain summaries
- federation diagnostics
- active federation validation
- deployment readiness
- dashboard/API-safe security posture views

Heartbeat channels remain unchanged in this phase.

## Operator Safety

Phase 124 remains local-first, advisory-only, and export-safe. Public docs and tests use sanitized placeholders only. No hostnames, private IP addresses, usernames, MAC addresses, certificate material, private keys, credentials, logs, screenshots, runtime databases, or private validation notes should be committed.
