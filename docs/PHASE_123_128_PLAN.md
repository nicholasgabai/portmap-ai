# Phase 123-128 Security Foundation And Trusted Runtime Plan

Milestone U defines the next implementation milestone for hardening PortMap-AI's distributed runtime trust model. The focus is secure logical node identity, encrypted orchestration transport, secure configuration and secret handling, role-based operator permissions, tamper detection, and secure update previews.

This is a planning document. It does not create certificates, open network listeners, exchange credentials, install services, modify host configuration, or enable privileged enrollment.

## Milestone U: Security Foundation And Trusted Runtime

Goal:
Transform PortMap-AI into a trusted deployable distributed security platform while preserving the current local-first, operator-controlled, advisory-by-default posture.

Milestone U should connect existing node identity, federation transport models, signed summary exchange, deployment readiness, export safety, runtime health, and operator visibility into security-ready records that can later support encrypted orchestration and trusted distributed operations.

All work should remain:

- local-first
- advisory by default
- dry-run safe
- metadata-only unless a future phase explicitly adds protected secrets handling
- cross-platform aware
- Raspberry Pi/Linux ARM compatible
- Windows/macOS/Linux compatible
- export-safe
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 123:

- Local node identity and registry primitives.
- Trusted federation transport models.
- Signed runtime summary exchange records.
- Active federation runtime manager records.
- Trusted peer lifecycle records.
- Runtime exchange scheduler records.
- Active federation validation summaries.
- Cross-platform runtime, filesystem, service, firewall, and packet capture readiness records.
- Deployment manifests, service lifecycle previews, backup/restore planning, and deployment operator summaries.
- Source-mode labeling and live snapshot deduplication hardening.

Milestone U should add secure-trust foundations without enabling real remote enrollment, certificate issuance, privileged registration, automatic trust changes, or live network listener behavior.

## Phase 123 - Secure Node Identity

Status: Complete Baseline

Goal:
Introduce trusted logical node identity and enrollment foundations for distributed orchestration without exposing hardware identifiers, storing credentials insecurely, or enabling privileged enrollment actions.

Build:

- `core_engine/security/node_identity.py`
- `core_engine/security/enrollment.py`
- `core_engine/security/trust_chain.py`
- `core_engine/security/__init__.py`
- `tests/test_secure_node_identity.py`
- `docs/secure_node_identity.md`

Features:

- Deterministic logical node identities.
- No raw hardware fingerprints, MAC addresses, serial numbers, usernames, or hostnames in identity records.
- Secure node identity export dictionaries.
- Identity regeneration and rotation previews.
- Worker enrollment preview records.
- Pending, trusted, rejected, rotated, and expired enrollment states.
- Orchestrator, master, worker, and edge trust relationship summaries.
- Trusted, degraded, untrusted, and unknown trust states.
- Advisory-only and dry-run-only safety fields.

Acceptance:

- Logical identities are deterministic from installation-scoped references.
- Export dictionaries do not expose raw installation references or hardware identifiers.
- Enrollment previews do not exchange credentials or perform privileged registration.
- Trust-chain summaries are export-safe and advisory-only.
- Tests cover malformed records, state transitions, serialization, and cross-platform-safe behavior.

## Phase 124 - Encrypted Orchestration Transport

Status: Complete Baseline

Goal:
Prepare encrypted orchestration transport records for trusted node communication without opening network listeners automatically.

Build:

- `core_engine/security/transport_security.py`
- `core_engine/security/session_negotiation.py`
- `tests/test_encrypted_orchestration_transport.py`
- `docs/encrypted_orchestration_transport.md`

Features:

- Mutual TLS readiness records.
- Encrypted heartbeat channel summaries.
- Session negotiation preview records.
- Certificate reference placeholders.
- Graceful degraded states for unsupported platforms.
- Export-safe transport dictionaries.
- Plaintext development, TLS-ready, mTLS-ready, pinned-certificate-ready, and production-required profile records.
- Downgrade warning fields and operator action summaries.
- Dry-run-only session negotiation previews for orchestrator/master/worker/edge role pairs.

Acceptance:

- Transport summaries are deterministic and sanitized.
- No live sockets are opened.
- No certificates or private keys are generated or stored in public fixtures.
- Degraded and unavailable states are explicit.
- No live authentication exchange or mTLS handshake is performed.

## Phase 125 - Secure Config And Secrets Management

Status: Complete Baseline

Goal:
Add secure configuration and secret-handling readiness records without storing credentials in plaintext.

Build:

- `core_engine/security/secure_config.py`
- `core_engine/security/secrets.py`
- `tests/test_secure_config_and_secrets.py`
- `docs/secure_config_and_secrets.md`

Features:

- Encrypted configuration readiness records.
- Runtime secret isolation summaries.
- Secret rotation preview records.
- Environment abstraction summaries.
- Redaction/export-safety fields.
- Development, staging, production, edge, and ephemeral-runtime configuration profile records.
- Orchestrator token, worker enrollment secret, future mTLS material, API/session token, and runtime encryption key preview records.
- Plaintext persistence rejection fields.
- External secret provider readiness records.

Acceptance:

- No secret material appears in docs, tests, or export-safe dictionaries.
- Rotation remains preview-only.
- Unsupported platform behavior is safely degraded.
- No OS keychain, credential store, live encryption, real key generation, or live secret exchange is performed.

## Phase 126 - RBAC And Operator Permissions

Goal:
Add role-based access and permission summary models for future secured operator workflows.

Build:

- `core_engine/security/rbac.py`
- `core_engine/security/permissions.py`
- `tests/test_rbac_operator_permissions.py`
- `docs/rbac_operator_permissions.md`

Features:

- Admin, operator, auditor, and read-only role summaries.
- Permission scope records.
- Enforcement-mode protection flags.
- Dashboard/API-safe permission dictionaries.

Acceptance:

- Permission summaries are deterministic.
- No authentication backend is required in this phase.
- Unsafe or unknown permission states are reported, not hidden.

## Phase 127 - Tamper Detection

Goal:
Add tamper detection readiness records for runtime integrity, configuration integrity, and signed artifact validation.

Build:

- `core_engine/security/integrity.py`
- `core_engine/security/tamper_detection.py`
- `tests/test_tamper_detection.py`
- `docs/tamper_detection.md`

Features:

- Runtime integrity summary records.
- Config tamper alert previews.
- Binary verification support records.
- Degraded and unknown integrity states.
- Export-safe tamper summaries.

Acceptance:

- No privileged file watching is started.
- No system files are modified.
- Tamper summaries use sanitized fixture paths only.

## Phase 128 - Secure Update Framework

Goal:
Add signed update and rollback readiness records without executing updates or migrations.

Build:

- `core_engine/security/update_verification.py`
- `core_engine/security/rollback_plans.py`
- `tests/test_secure_update_framework.py`
- `docs/secure_update_framework.md`

Features:

- Signed update manifest summaries.
- Update verification preview records.
- Rollback safety records.
- Migration verification hooks.
- Operator-approved update checklist.

Acceptance:

- No updates are downloaded or installed.
- No migrations execute automatically.
- Rollback plans are preview-only and export-safe.

## Cross-Phase Data Flow

```text
logical node identity
  -> enrollment preview
  -> trust-chain summary
  -> encrypted transport readiness
  -> secure config and permissions
  -> tamper/update readiness
  -> deployment and federation validation
```

The flow is operator-triggered and local-only. No phase should add credential exchange, automatic enrollment, certificate issuance, service installation, public internet exposure, or external data transmission unless a later milestone explicitly adds an operator-approved transport.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Confirm no logs, screenshots, archives, database files, cache folders, runtime data, environment files, credentials, private keys, certificates, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm public docs use sanitized placeholders only.
- Confirm no raw hardware identifiers, usernames, hostnames, MAC addresses, serial numbers, or private IP addresses are emitted.
- Confirm dry-run and advisory posture remains default.

## macOS Validation Checklist

Use sanitized fixtures and temporary local test locations only.

- Generate a logical identity from a sanitized installation reference.
- Build a worker enrollment preview.
- Build orchestrator/master/worker trust relationship summaries.
- Verify export dictionaries contain no hardware identifiers or plaintext secrets.
- Run full tests on the repo-local environment.

## Raspberry Pi Validation Checklist

Use sanitized records and temporary local test locations only.

- Generate an edge or worker logical identity from a sanitized installation reference.
- Build a trusted-node enrollment preview without remote communication.
- Build a trust-chain summary for orchestrator, master, worker, and edge roles.
- Confirm CPU and memory use remain modest.
- Confirm no external network calls are required.
- Confirm no private identifiers, logs, screenshots, database files, cache files, environment files, certificates, keys, runtime data, or private validation notes are staged.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/secure_node_identity.md`
- `docs/encrypted_orchestration_transport.md`
- `docs/secure_config_and_secrets.md`
- `docs/rbac_operator_permissions.md`
- `docs/tamper_detection.md`
- `docs/secure_update_framework.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Hosted SaaS.
- Cloud billing.
- Public internet exposure.
- Automatic trust acceptance.
- Credential exchange without protected storage.
- Raw hardware fingerprint storage.
- Router modification.
- Firewall rule changes.
- Automatic service installation or startup.
- Background collection without explicit operator opt-in.
- Replacement of the existing Textual terminal dashboard.
