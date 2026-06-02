# Secure Node Identity

Phase 123 adds secure logical node identity records, worker enrollment previews, and trust-chain summaries for future trusted distributed orchestration.

This phase is advisory and dry-run only. It does not create certificates, exchange credentials, register nodes remotely, open listeners, request elevated permissions, or install services.

## Logical Identity Philosophy

PortMap-AI uses logical node identities rather than raw hardware fingerprints. A logical identity is deterministic for an installation-scoped reference, but the reference is hashed before an export-safe UUID is generated. The exported identity does not include the installation reference.

Identity records avoid:

- MAC addresses.
- Serial numbers.
- Hostnames.
- Usernames.
- Raw hardware fingerprints.
- Plaintext secrets.

The core record is `SecureNodeIdentity` in `core_engine/security/node_identity.py`.

Important fields:

- `node_uuid` - deterministic export-safe UUID for the logical node.
- `logical_node_class` - `orchestrator`, `master`, `worker`, or `edge`.
- `enrollment_state` - advisory enrollment posture such as `pending` or `trusted`.
- `trust_state` - trust posture such as `trusted`, `degraded`, `untrusted`, or `unknown`.
- `identity_version` - identity schema version.
- `issued_timestamp` - operator-visible issue time.
- `rotation_supported` - whether identity rotation can be previewed.

Export dictionaries include explicit safety fields:

- `hardware_identifiers_stored: false`
- `plaintext_secrets_stored: false`
- `raw_hardware_identifiers_used: false`
- `automatic_privileged_enrollment: false`

## Identity Previews

Phase 123 supports preview-only identity regeneration and rotation helpers. These helpers return future identity IDs and operator review fields without mutating local state.

Preview fields include:

- `dry_run_only: true`
- `destructive_action: false`
- `requires_operator_approval: true`
- `plaintext_secrets_stored: false`
- `hardware_identifiers_stored: false`

## Enrollment Preview Model

`core_engine/security/enrollment.py` defines `WorkerEnrollmentPreview`.

Supported enrollment states:

- `pending`
- `trusted`
- `rejected`
- `rotated`
- `expired`

Enrollment preview records include an export-safe `enrollment_id`, the logical `node_identity_reference`, trust level, method, issued timestamp, expiration preview, and advisory notes.

Enrollment remains advisory-only:

- No real remote enrollment.
- No credential exchange.
- No privileged registration.
- No service installation.
- No network listener startup.

## Trust-Chain Concepts

`core_engine/security/trust_chain.py` defines trust relationship summaries between:

- Orchestrator nodes.
- Master nodes.
- Worker nodes.
- Edge nodes.

Supported trust states:

- `trusted`
- `degraded`
- `untrusted`
- `unknown`

Trust summaries include:

- `trust_reason`
- `verification_mode`
- `rotation_ready`
- `degraded_reason`
- export-safety fields
- advisory-only fields

Trust-chain summaries can be used by future encrypted orchestration transport, secure configuration, RBAC, tamper detection, update verification, deployment validation, and federation health checks.

## Future Encrypted Orchestration

This phase prepares the identity and trust model for later encrypted orchestration work. Future phases may add mutual TLS readiness, session negotiation, certificate references, secure configuration storage, RBAC, integrity checks, and signed update manifests.

Those future phases must continue to avoid public test secrets, raw hardware identifiers, private hostnames, private paths, usernames, MAC addresses, serial numbers, logs, screenshots, runtime databases, and private validation notes.

## Operator Safety

Secure node identity outputs are safe to include in local dashboard, API, and export summaries because they are metadata-only and sanitized. Operators should still review identity and enrollment previews before trusting nodes in a distributed runtime.

Phase 123 does not change firewall state, install services, open ports, enroll remote workers, or transmit data externally.
