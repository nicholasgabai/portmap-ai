# Quarantine and Isolation Provider Readiness

Phase 137 adds dry-run provider readiness records for quarantine, isolation, and firewall-backed containment planning across macOS, Linux/Raspberry Pi, and Windows.

This phase does not execute firewall commands, call subprocesses, modify firewall rules, quarantine services, kill processes, disable services, isolate nodes, write system configuration, store credentials, or perform live containment.

## Provider Readiness

`core_engine/remediation/isolation_providers.py` models these providers:

- `windows_defender_firewall`
- `linux_nftables`
- `linux_ufw`
- `linux_iptables`
- `macos_pf`
- `raspberry_pi_edge`
- `generic_manual_operator`

Provider records include:

- provider name
- platform family
- supported and unavailable preview actions
- readiness state
- permission and elevation requirement summaries
- dry-run support
- sanitized command preview text
- safety warnings
- advisory notes

Readiness states are `ready`, `degraded`, `unavailable`, and `unknown`.

## Quarantine and Isolation Previews

`core_engine/remediation/quarantine_readiness.py` models preview records for:

- `rate_limit_preview`
- `block_port_preview`
- `block_destination_preview`
- `quarantine_service_preview`
- `isolate_node_preview`
- `manual_review`

Preview records include sanitized targets, provider linkage, readiness state, approval requirements, rollback requirements, blast-radius summaries, safety blockers, operator steps, and export-safe safety fields.

## Safety Boundary

Every Phase 137 record is advisory-only:

- `preview_only: true`
- `destructive_action: false`
- `automatic_changes: false`
- `firewall_changes: false`
- `service_changes: false`
- `process_changes: false`
- `node_isolation_performed: false`
- `credentials_stored: false`
- `raw_payload_stored: false`

Command previews are static, sanitized text. PortMap-AI does not execute them.

## Operator Approval and Rollback

All containment previews require operator review. Previews that could become containment actions in a future supervised mode also require rollback planning. Unsupported or degraded providers add safety blockers instead of attempting fallback execution.

## Future Path

Later Milestone W phases can connect these readiness records to risk escalation, safety guardrails, response simulations, and enforcement-mode modeling. Real containment remains out of scope until separate production validation, explicit operator approval, audited rollback plans, and provider-specific safety controls exist.
