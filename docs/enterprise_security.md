# Enterprise Security Layer

Phase 36 adds local enterprise-security primitives for future multi-user and SaaS control-plane work. The layer is intentionally isolated from the existing local orchestrator defaults and does not change current development authentication behavior.

## Scope

The implementation includes:

- `core_engine.enterprise_auth` for stdlib-only HS256 token issuing/verification and PBKDF2-SHA256 password records.
- `core_engine.rbac` for role/permission mapping and local authorization decisions.
- `core_engine.enterprise_audit` for normalized enterprise security audit events with secret scrubbing.
- `core_engine.agent_identity` for secure agent identity records, generated agent secrets, HMAC message signatures, and mTLS-ready certificate fingerprint fields.
- `portmap rbac` for local role/permission inspection.

## Roles

Built-in roles:

- `viewer`: read-only health, metrics, nodes, logs, scan results, and vulnerabilities.
- `analyst`: inherits viewer and can run scans, generate recommendations, manage expected services, and acknowledge alerts.
- `admin`: inherits analyst and can manage users, agents, config, remediation approvals, and audit reads.
- `agent`: can submit telemetry, read commands, and heartbeat to the orchestrator.

Inspect role definitions:

```bash
portmap rbac --output json
```

Check a permission:

```bash
portmap rbac --roles analyst --permission generate:recommendations --output json
```

## Token And Password Helpers

`enterprise_auth.issue_token()` creates a signed local token with subject, issuer, audience, roles, issued-at, not-before, and expiration claims. `enterprise_auth.verify_token()` validates the signature, expiration, audience, and role names.

Password records use PBKDF2-SHA256 with per-user salts and at least 100,000 iterations. Public user records include a password-hash fingerprint, not the hash itself.

These helpers are building blocks. They are not yet wired into the local orchestrator's existing development bearer-token path.

## Agent Identity

`agent_identity.build_enterprise_agent_identity()` creates an agent identity that stores only a shared-secret fingerprint. When a secret is generated, it is returned once to the caller and is not stored in the identity record.

Agent identities can include a `certificate_fingerprint` and `mtls_ready: true` for future mTLS enrollment flows. HMAC request signing helpers support timestamp-skew checks for future agent/control-plane communication.

## Audit Events

`enterprise_audit.build_enterprise_audit_event()` creates normalized events with:

- `event_type: enterprise_security`
- actor, action, status, resource, roles, tenant ID
- timestamp
- scrubbed metadata

Secret-like metadata keys are redacted using the existing shared security helpers.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. The enterprise security layer does not replace current local development auth defaults and stores no raw bearer tokens or generated agent secrets.

Future SaaS/control-plane work should build on these primitives while preserving explicit operator approval for destructive actions.
