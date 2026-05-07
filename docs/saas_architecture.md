# PortMap-AI SaaS Architecture Preparation

Phase 16 defines the future SaaS shape without changing the current local-first product. The local agent, local stack, CLI, TUI, audit trail, and remediation safety rules remain the baseline. No cloud dependency is required to run PortMap-AI 0.1.0.

## Separation of Responsibilities

### Local Agent

The local agent is responsible for work that must happen close to the host or network:

- scan local processes, ports, listeners, and network interfaces;
- calculate local risk factors and AI-assisted explanations;
- enforce remediation only through local safety policy;
- write local logs and audit records;
- keep operating when a future control plane is unreachable.

The local agent includes the standalone worker path, the master/worker stack, and the orchestrator API used for local coordination.

### Future Control Plane

A future SaaS control plane should coordinate fleets, not replace local inspection:

- tenant, organization, site, and node inventory;
- enrollment package issuance and revocation;
- policy distribution;
- aggregated metrics, audit search, and operator views;
- optional AI provider configuration;
- update and release-channel metadata.

The control plane must not require inbound access to customer networks. Agents should initiate outbound communication.

## Multi-Tenant Model

The planned hierarchy is:

- `tenant_id`: billing or account boundary.
- `org_id`: administrative organization inside a tenant.
- `site_id`: optional physical or logical deployment location.
- `node_id`: stable local agent identity.
- `role`: `standalone`, `master`, or `worker`.

Phase 16 adds local schema helpers in `core_engine.enrollment` for tenant identity, enrollment requests, enrollment packages, and persisted agent identities. These helpers validate shape and redact enrollment tokens, but they do not contact any external service.

## Enrollment Model

The future enrollment flow should be:

1. Operator creates an enrollment package in the control plane.
2. Package contains tenant identity, node role, control-plane URL, expiry, and a one-time enrollment token.
3. Local operator applies the package to a PortMap-AI install.
4. Agent validates the package, stores only an agent identity and token fingerprint, and discards the raw token after exchange.
5. Control plane records the node and begins issuing policy and command metadata.

The current 0.1.0 repository supports only the local schema and validation pieces of this flow.

## Communication Model

Future remote communication should use outbound agent-initiated traffic:

- short polling or long polling for the first SaaS version;
- WebSocket or message queue transport only after the contract is stable;
- signed commands with idempotency keys;
- structured command outcomes mirrored to the local audit trail;
- explicit offline behavior when the control plane is unavailable.

Remote control must preserve the Phase 7 safety gates. Destructive remediation remains blocked unless the local policy allows active enforcement and the specific command is confirmed.

## Security Boundaries

Required before real SaaS enrollment:

- non-default bearer tokens or mTLS for remote endpoints;
- enrollment token hashing or one-time exchange;
- per-tenant authorization checks on every control-plane request;
- command signing or equivalent integrity protection;
- secret storage through OS-native key stores where practical;
- audit export that separates local evidence from SaaS metadata.

## Not Implemented in 0.1.0

The following are intentionally not implemented in this release candidate:

- hosted control plane;
- multi-tenant database;
- billing or user management;
- remote operator console;
- automatic SaaS enrollment;
- router/firewall changes from a SaaS command.

PortMap-AI 0.1.0 is a packaged local product with documented SaaS contracts for future expansion.
