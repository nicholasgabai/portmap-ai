# PortMap-AI Security Model

This document centralizes the project safety and trust boundaries. The main handoff remains the source of truth for detailed implementation status.

## Global Safety Guarantees

- PortMap-AI supports authorized observability, telemetry analysis, packet inspection, protocol-aware diagnostics, service discovery, topology mapping, TLS analysis, flow reconstruction, and administrator-controlled remediation workflows.
- Some platform capabilities may generate standards-compliant diagnostic network traffic for observability and validation purposes.
- PortMap-AI is not designed for unauthorized access, credential theft, brute forcing, malware deployment, persistence, destructive exploitation, denial-of-service activity, or autonomous offensive operations.

## Authentication and Secrets

- Orchestrator APIs use bearer-token authentication.
- Token comparisons use constant-time verification helpers.
- Secret placeholders can be loaded from environment variables.
- Persisted orchestrator state scrubs secret-like metadata.
- Enterprise helpers support local signed tokens, password records, RBAC decisions, audit records, and agent identity metadata.

## Remediation Controls

Remediation workflows are administrator-controlled. Destructive actions remain gated by dry-run defaults, explicit active-enforcement configuration, confirmation requirements, and audit records.

## Telemetry Handling

Telemetry outputs are structured and JSON serializable. Packet, DPI, payload, and flow features avoid raw payload storage by default and use bounded redaction where previews are explicitly requested.

## Deployment Boundary

Local install is the recommended default. Docker is optional. Cloud sync helpers create local encrypted manifests and do not send network requests by themselves.

## References

- `PORTMAP_AI_HANDOFF.md`
- `SECURITY.md`
- `docs/security_authentication.md`
- `docs/remediation_safety.md`
- `docs/enterprise_security.md`
- `docs/enterprise_cloud_orchestration.md`
