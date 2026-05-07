# Changelog

## 0.1.0 - Release Candidate

Initial local product baseline for PortMap-AI.

### Added

- Reproducible runtime and development dependency manifests.
- Unified `portmap` CLI with scan, stack, TUI, API status, log export, config validation, setup, doctor, and network posture commands.
- Installable package metadata, console scripts, package data, and local packaging script.
- Configuration validation and environment-backed secret interpolation.
- Cross-platform platform abstraction layer for host, process, network, and subprocess operations.
- Stack restart supervision, stale-node handling, re-registration, and graceful shutdown helpers.
- Structured JSONL audit events, log filtering, and archive export.
- Remediation safety gates with dry-run defaults and confirmation requirements for destructive actions.
- Risky-port database, service hints, risk explanations, and AI provider interface.
- Textual TUI dashboard improvements for health, metrics, scans, remediation, commands, expected services, and logs.
- Optional Docker Compose deployment assets.
- Raspberry Pi and general Linux service profile, user-scoped systemd templates, and installation helper.
- Runtime setup and diagnostics commands for local packaged use.
- Advisory-only network control layer.
- Orchestrator authentication, node identity validation, and secret scrubbing.
- SaaS preparation contracts for tenant identity, enrollment packages, and future agent identity.
- GitHub-readiness cleanup with explicit Docker tokens, loopback local master default, token-fingerprint error messages, systemd environment-file token generation, runtime artifact ignores, and security policy documentation.

### Documentation

- Added setup, usage, architecture, deployment, Docker, Raspberry Pi, packaging, security, network control, AI, scanner/risk, TUI, logging/audit, remediation safety, and SaaS architecture guides.

### Known Limitations

- Docker is optional and requires a user-installed Docker Engine plus Compose plugin.
- Windows support is not yet validated as a release target.
- SaaS control-plane functionality is planned and documented but not implemented.
- Active destructive remediation is intentionally opt-in.
