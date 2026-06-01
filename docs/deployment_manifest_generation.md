# Deployment Manifest Generation

Phase 119 adds sanitized deployment manifest generation for PortMap-AI deployment planning. Manifests describe deployment shape, runtime posture, node profile, service-provider preview mode, retention policy, component requirements, export paths, and backup recommendations without performing deployment actions.

This phase is metadata-only. It does not create deployment packages, create installers, write deployment configs to system locations, install services, generate credentials, start processes, change firewall state, or include private runtime identifiers.

## Manifest Modes

Deployment manifests are available for:

- `standalone` - local single-node operation for a workstation or endpoint.
- `orchestrator` - local orchestrator-managed operation for multi-node summaries.
- `worker` - trusted lightweight worker planning.
- `edge` - Raspberry Pi or Linux edge-node planning.
- `lab` - sanitized fixture and temporary validation planning.
- `production_preview` - production deployment preview with explicit operator review.

Each manifest includes:

- `deployment_mode`
- `runtime_profile`
- `node_profile`
- `supported_platforms`
- `telemetry_mode`
- `orchestration_mode`
- `service_provider_mode`
- `retention_policy_mode`
- `deployment_readiness`
- `required_components`
- `optional_components`
- `export_paths`
- `backup_recommendations`
- `advisory_notes`
- `dry_run_only`

## Node Profiles

Node deployment profiles summarize the expected role and resource envelope for:

- Raspberry Pi edge node
- macOS workstation
- Windows workstation
- Linux server
- lab node
- lightweight worker

Node profiles include estimated memory and disk envelopes, deployment suitability, telemetry suitability, orchestration suitability, degraded-mode recommendations, and advisory-only warnings.

## Orchestrator, Worker, And Edge Planning

An orchestrator manifest favors a Linux server node profile, production runtime profile, enhanced telemetry, and systemd preview mode. A worker manifest favors a lightweight worker profile, edge runtime profile, bounded telemetry, and foreground process preview mode. An edge manifest favors a Raspberry Pi edge node profile, bounded retention, minimal telemetry, and Raspberry Pi systemd edge preview mode.

These modes are planning records only. They do not contact nodes, enroll peers, generate credentials, write config files, or install services.

## Sanitization And Export Safety

Manifest output uses placeholders such as:

- `<operator-approved-export-dir>`
- `<operator-approved-backup-dir>`
- `<portmap-install-dir>`

Public records must not contain real paths from operator machines, usernames, hostnames, IP addresses, MAC addresses, credentials, raw logs, screenshots, database files, or runtime artifacts.

## Readiness States

Manifest readiness can be:

- `supported` - runtime profile, node suitability, service provider, and platform overlap are compatible.
- `degraded` - one or more checks requires operator review.
- `unsupported` - the selected manifest inputs do not support the requested deployment mode.

Unsupported or degraded manifests are still useful for planning because they explain what must change before a real deployment attempt.

## Safety Philosophy

Deployment manifests are advisory-first. They answer what should be reviewed before deployment, not how to perform deployment automatically. Later deployment phases may build on these records, but Phase 119 keeps all outputs dry-run, deterministic, sanitized, and export-safe.
