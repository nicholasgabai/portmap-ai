# PortMap-AI Master Roadmap

## System Directive

Work inside the existing PortMap-AI repository. Do not rebuild the architecture from scratch. Inspect the current codebase first, preserve working modules, and extend functionality incrementally.

Do not break existing tests. Do not introduce unnecessary renaming or restructuring unless required for stability or portability.

All work must be done in small, testable increments. After each phase, update documentation and include clear test instructions.

## Current Verified State

The project is no longer a prototype. It already includes a functional local distributed system.

Existing components:
- Orchestrator HTTP API (`core_engine/orchestrator.py`)
- Master node task dispatcher
- Worker node scanner and remediation executor
- Socket-based communication with remediation-aware acknowledgements
- Textual terminal UI (`gui/app.py`)
- Local stack launcher (`scripts/run_stack.py`)

Additional implemented features:
- TLS utilities
- Firewall plugin system
- Command audit logging
- Structured logging and log export
- CI workflow
- Dockerfiles and packaging scaffolding
- Comprehensive test suite

Validation status:
- Full test suite passes.
- Local stack successfully runs orchestrator on `127.0.0.1:9100`, master on `127.0.0.1:9000` by default, and a worker that registers, sends heartbeats, performs scans, and receives remediation acknowledgements.
- API endpoints `/healthz`, `/nodes`, and `/metrics` respond correctly.

Known issues:
- Older work created more than one virtual environment.
- The repo-local `portmap-ai-env` is the standard reproducible environment.
- Dependency manifests must stay complete as imports change.

## Product Goal

PortMap-AI is a cross-platform network security agent that:
- Runs on macOS, Linux, and Raspberry Pi OS.
- Can operate as a standalone node or distributed system.
- Continuously monitors network activity and port exposure.
- Scores and explains risk.
- Uses AI as an advisory analysis layer.
- Provides controlled, auditable remediation actions.
- Evolves into a packaged local product before SaaS expansion.

## Platform Requirements

Target environments:
- macOS for development
- Linux for primary deployment
- Raspberry Pi OS on ARM
- Windows in a future support phase

Constraints:
- No hardcoded absolute paths.
- Use `pathlib` for file handling.
- Abstract OS-specific behavior.
- Use `psutil` for process and network inspection.
- Avoid dependencies that break on ARM unless optional.
- Core functionality must work identically across macOS and Linux.

## Phase 0 - Reproducible Setup

Goal: Make the repository fully reproducible from a fresh clone.

Tasks:
- Audit imports across the repository.
- Maintain complete `requirements.txt` runtime dependencies.
- Maintain complete `requirements-dev.txt` development and testing dependencies.
- Add clear setup instructions for virtualenv creation, dependency installation, tests, stack launch, and TUI launch.
- Document the dual-virtualenv issue and standardize on the repo-local environment.
- Update `PORTMAP_AI_HANDOFF.md` to reflect the current system.

Definition of done:
- Fresh environment can run `pytest`, `scripts/run_stack.py`, and the TUI.
- All tests pass.
- Documentation matches actual system behavior.

## Phase 1 - CLI Interface

Goal: Provide a unified command interface.

Tasks:
- Implement CLI entrypoints for scan, stack, tui, health, nodes, metrics, and logs.
- Connect CLI commands to existing modules.
- Add help output and argument parsing.
- Support configuration file overrides.

Definition of done:
- All core actions can be triggered via CLI.
- CLI is tested and documented.

## Phase 2 - Packaged Local Install

Goal: Make the system installable as a local tool.

Tasks:
- Configure `pyproject.toml` or setup configuration.
- Support `pip install -e .`.
- Ensure CLI commands are available after install.
- Include necessary package data such as configs and docs.
- Remove hardcoded paths.

Definition of done:
- Fresh install works on a clean environment.
- Tests pass after installation.

## Phase 3 - Configuration Hardening

Goal: Ensure configuration is validated and reliable.

Tasks:
- Define a configuration schema.
- Validate node roles, ports, hosts, scan intervals, remediation modes, log paths, and TLS settings.
- Provide example configuration files.
- Add a config validation command.

Definition of done:
- Invalid configurations fail with clear errors.
- Example configurations work out of the box.

## Phase 4 - Platform Abstraction Layer

Goal: Ensure cross-platform compatibility.

Tasks:
- Create a platform abstraction module.
- Handle process management, port and connection mapping, network interface detection, and OS detection.
- Remove direct OS-specific logic from core modules.

Definition of done:
- System runs on macOS and Linux without modification.
- Raspberry Pi works without special-case logic.

## Phase 5 - Stack Stability

Goal: Harden distributed system behavior.

Tasks:
- Validate worker registration and heartbeat logic.
- Handle disconnects and reconnections.
- Support master and orchestrator restarts.
- Add graceful shutdown handling.
- Detect port conflicts.

Definition of done:
- Stack recovers from common failures.
- Behavior is predictable and logged.

## Phase 6 - Logging and Audit

Goal: Standardize and improve logs.

Tasks:
- Define structured JSONL log format.
- Ensure all actions and decisions are logged.
- Include timestamps, node IDs, risk scores, and actions taken.
- Add log export and filtering.

Definition of done:
- Logs are structured, searchable, and exportable.

## Phase 7 - Remediation Safety

Goal: Ensure safe operation.

Tasks:
- Enforce prompt mode as default.
- Require confirmation for destructive actions.
- Implement silent mode as opt-in.
- Add dry-run capability.
- Add allowlists and policies.

Definition of done:
- No unsafe automatic actions occur.
- Remediation is fully auditable.

## Phase 8 - Scanner and Risk Engine

Goal: Improve detection accuracy.

Tasks:
- Improve port and process mapping.
- Add known risky ports database.
- Add behavior-based heuristics.
- Provide explanations for risk scores.

Definition of done:
- Every risk score includes reasoning.
- Scanner output is stable.

## Phase 9 - AI Layer

Goal: Clean and modular AI integration.

Tasks:
- Define an AI interface.
- Support a local stub and future API integration.
- Validate inputs and outputs.
- Handle failures gracefully.

Definition of done:
- AI layer is optional and replaceable.
- System remains stable without AI.

## Phase 10 - TUI Improvements

Goal: Make terminal UI production-ready.

Tasks:
- Display nodes, health, and metrics.
- Show scan results and risks.
- Display remediation events.
- Add user interactions and controls.

Definition of done:
- TUI can be used as the primary interface.

## Phase 11 - Docker Deployment

Goal: Enable containerized local deployment.

Tasks:
- Add docker-compose setup.
- Configure services for orchestrator, master, and worker.
- Add environment configuration.
- Persist logs.

Definition of done:
- Stack runs via Docker Compose.

## Phase 12 - Raspberry Pi Deployment

Goal: Enable continuous local monitoring.

Tasks:
- Ensure ARM compatibility.
- Optimize resource usage.
- Add systemd service.
- Support LAN scanning safely.
- Document setup process.

Definition of done:
- System runs continuously on Raspberry Pi.

## Phase 13 - Packaging

Goal: Distribute as a local application.

Tasks:
- Create executable or installable package.
- Include configs and documentation.
- Test clean install flow.

Definition of done:
- Non-developers can install and run the system.

## Phase 14 - Network Control Layer

Goal: Extend to router-level awareness.

Tasks:
- Detect local gateway and router.
- Identify exposed services and settings.
- Provide recommendations without automatic changes.

Definition of done:
- System can assess network posture safely.

## Phase 15 - Security and Authentication

Goal: Prepare for remote access.

Tasks:
- Add API authentication.
- Secure worker registration.
- Manage secrets properly.

Definition of done:
- System is secure by default.

## Phase 16 - SaaS Preparation

Goal: Define future architecture.

Tasks:
- Separate local agent and control plane.
- Define multi-tenant structure.
- Design enrollment and communication model.

Definition of done:
- SaaS architecture is documented.

## Phase 17 - Documentation

Goal: Make the system usable and understandable.

Tasks:
- Update README and handoff documentation.
- Add setup, usage, and architecture guides.

Definition of done:
- New user can install and operate the system.

## Phase 18 - Release Candidate

Goal: Prepare initial release.

Tasks:
- Final testing.
- Packaging.
- Versioning.
- Changelog.

Definition of done:
- Version `0.1.0` is ready.

## Execution Order

Start with:
1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 4
6. Phase 5
7. Phase 6
8. Phase 7
9. Phase 10
10. Phase 11
11. Phase 12
12. Phase 13

Then proceed to advanced features.

## Immediate Next Step

Complete Phase 0. Ensure the repository is fully reproducible, dependencies are complete, tests pass in a fresh environment, and documentation reflects the current system.
