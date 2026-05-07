# PortMap-AI Next Session Handoff

## Current State

PortMap-AI has completed Phases 0 through 18 of the master roadmap through the 0.1.0 release-candidate baseline.

Latest verified baseline:

- Full test suite: `154 passed, 1 skipped`
- Focused Phase 16-18 tests: `14 passed`
- Wheel build smoke: `portmap_ai-0.1.0-py3-none-any.whl` built successfully
- `portmap --help` works from the repo-local environment
- `portmap doctor --output json` runs and reports overall `ok: true`
- GitHub-readiness cleanup completed and full suite still passes: `154 passed, 1 skipped`
- Current next step: review `git status`, commit, optionally run real-device runtime smoke checks, then tag `0.1.0`

## Important Product Direction

PortMap-AI is multi-platform:

- macOS: supported development/local CLI/TUI baseline.
- Linux: supported local/server baseline.
- Linux/ARM/Raspberry Pi OS: supported through the same package, low-resource profile, and systemd templates.
- Windows: experimental/future for native service packaging.

Do not make Raspberry Pi or Docker the only path.

Deployment options are:

1. Local install/CLI - recommended default.
2. Native service mode - always-on Linux/Raspberry Pi path.
3. Docker Compose - optional advanced container path.

Docker should not be auto-installed for users.

GitHub-readiness rules:

- Do not commit runtime logs, local state, virtual environments, build output, archives, or generated JSONL files.
- Docker Compose requires an explicit `PORTMAP_ORCHESTRATOR_TOKEN`; it must not fall back to `test-token`.
- Default local master binding is `127.0.0.1`, not `0.0.0.0`.
- Shared/remote deployments need long random tokens and firewall rules.

## Completed Phases

### Phase 0 - Reproducible Setup

- Runtime and dev requirements are defined.
- Repo-local `portmap-ai-env` is the standard environment.
- Stack, tests, TUI, and docs are reproducible.

### Phase 1 - CLI Interface

- Unified `portmap` CLI exists.
- Commands include scan, stack, tui, health, nodes, metrics, logs, config validate, setup, doctor, and network.

### Phase 2 - Packaged Local Install

- `pyproject.toml` defines package metadata and console scripts.
- Editable and wheel install paths are supported.

### Phase 3 - Configuration Hardening

- Config validation exists in `core_engine.config_validation`.
- Runtime services validate configs before startup.
- `portmap config validate` is available.

### Phase 4 - Platform Abstraction

- `core_engine.platform_utils` centralizes OS/process/network helpers.

### Phase 5 - Stack Stability

- Stack launcher supervises services, handles restarts, detects port conflicts, and shuts down cleanly.
- Worker/agent re-register after orchestrator state loss.

### Phase 6 - Logging and Audit

- Structured JSONL audit events exist.
- Log export and filtering are available through `portmap logs`.

### Phase 7 - Remediation Safety

- Destructive remediation is dry-run by default.
- Active destructive action requires explicit policy and confirmation.

### Phase 8 - Scanner and Risk Engine

- Risky-port database exists.
- Scanner rows include service hints.
- Scoring produces score factors and explanations.

### Phase 9 - AI Layer

- `ai_agent.interface` defines provider/result contracts.
- Local heuristic/ML provider remains default.
- Provider failures fall back safely.

### Phase 10 - TUI Improvements

- Textual dashboard shows nodes, metrics, scan results, remediation feed, command outcomes, expected services, and log tail.

### Phase 11 - Docker Deployment

- `docker-compose.yml` exists.
- Docker-specific configs and Dockerfiles exist.
- Docker remains optional.
- Local machine did not have Docker Compose plugin, so runtime compose smoke was not possible here.

### Phase 12 - Raspberry Pi / Linux Service Deployment

- `config/profiles/raspberry_pi.json` exists.
- User-scoped systemd templates exist under `deploy/systemd/`.
- `scripts/install_systemd_user.sh` exists.
- Raspberry Pi is treated as Linux/ARM support, not a separate architecture.

### Phase 13 - Packaging

- `portmap setup` initializes runtime paths/settings.
- `portmap doctor` reports platform/package readiness.
- `docs/packaging.md` exists.

### Phase 14 - Network Control Layer

- `core_engine.network_control` exists.
- `portmap network` reports gateway/local-network/exposed-service posture.
- It is advisory-only and makes no router/firewall/NAT/port-forward changes.

### Phase 15 - Security and Authentication

- `core_engine.security` exists.
- Bearer-token auth uses constant-time comparison.
- `${secret:ENV_VAR}` config interpolation works.
- Orchestrator registration/heartbeat/command paths validate node identity.
- Command payloads must be objects.
- Secret-like metadata is scrubbed before orchestrator state persistence.
- `docs/security_authentication.md` exists.

### Phase 16 - SaaS Preparation

- `core_engine.enrollment` defines local-only tenant identity, enrollment request, enrollment package, and agent identity schemas.
- Enrollment validation covers tenant/org/node identity, role, token shape, control-plane URL shape, and expiry type.
- Agent identity stores a token fingerprint instead of the raw enrollment secret.
- `docs/saas_architecture.md` documents the future control plane, multi-tenant model, enrollment flow, communication model, and non-implemented SaaS scope.

### Phase 17 - Documentation

- `docs/architecture.md` documents the current local-first architecture.
- `docs/README.txt` links setup, usage, deployment, security, SaaS, and release-candidate guides.
- `test_instructions.md` includes Phase 16-18 verification.

### Phase 18 - Release Candidate

- `pyproject.toml` version is `0.1.0`.
- `CHANGELOG.md` exists.
- `docs/release_candidate.md` defines scope, verification checklist, package notes, known limitations, and release decision.
- Release-candidate tests verify version/docs alignment.

### GitHub Readiness Cleanup

- `SECURITY.md` exists.
- Docker Compose now requires explicit `PORTMAP_ORCHESTRATOR_TOKEN`.
- Default local master config now binds to `127.0.0.1`.
- Stack-launcher token mismatch errors use token fingerprints, not raw token values.
- Systemd install helper creates `~/.portmap-ai/portmap-ai.env` with a generated token when absent.
- Runtime logs/state were removed from the Git index and ignore rules were expanded.
- Stale planning docs, sandbox simulation files, deprecated core-engine experiments, and `scriptsrun_orchestrator.bat` were removed.
- Root-owned old runtime files may still exist locally under ignored `data/` or `core_engine/logs/`; they are removed from Git and ignored.

## Key Files

- `PORTMAP_AI_HANDOFF.md` - full current handoff.
- `PORTMAP_AI_NEXT_SESSION.md` - compact handoff for low-context continuation.
- `CHANGELOG.md` - 0.1.0 release-candidate changelog.
- `SECURITY.md` - GitHub security policy and deployment hardening notes.
- `docs/release_candidate.md` - final release checklist.
- `docs/architecture.md` - current architecture guide.
- `docs/saas_architecture.md` - future SaaS/control-plane guide.
- `docs/master_roadmap.md` - roadmap.
- `test_instructions.md` - verification checklist.
- `pyproject.toml` - package metadata/version/package data.
- `cli/main.py` - unified CLI.
- `core_engine/orchestrator.py` - HTTP API.
- `core_engine/orchestrator_service.py` - persisted orchestrator state.
- `core_engine/worker_node.py` - worker scan/heartbeat loop.
- `core_engine/master_node.py` - master socket server and remediation command dispatch.
- `core_engine/enrollment.py` - SaaS-prep schema helpers.
- `core_engine/security.py` - auth helpers.
- `core_engine/network_control.py` - posture assessment.
- `core_engine/runtime_setup.py` - setup/doctor helpers.

## Verification Commands

Use the repo-local environment:

```bash
cd <repo-root>
source portmap-ai-env/bin/activate
python -m pytest
python -m pip wheel --no-deps -w /tmp/portmap-ai-wheel .
portmap --help
portmap doctor --output json
```

Optional real-runtime checks before tagging:

```bash
portmap stack --no-dashboard --verbose
portmap tui
portmap network --output json
docker compose config
```

`docker compose` requires Docker Engine with the Compose plugin. Docker is not required for the default product path.

## Next Step

Review `git status`, commit the release-candidate cleanup, perform any desired Linux/Raspberry Pi/Docker Compose real-device smoke checks, then tag `0.1.0`.
