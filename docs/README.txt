# PortMap-AI Documentation Index

PortMap-AI is currently a functional local distributed network-security stack with an orchestrator API, master node, worker node, Textual terminal dashboard, remediation audit trail, and local stack launcher.

Start here:
- `PORTMAP_AI_HANDOFF.md` - current system state, verified baseline, and operating notes.
- `docs/master_roadmap.md` - phased roadmap from reproducible setup through release candidate.
- `docs/quick_start.md` - setup, stack launch, dashboard, tests, and log export.
- `docs/architecture.md` - current local-first architecture and component boundaries.
- `test_instructions.md` - focused local verification checklist.
- `docs/deployment_options.md` - default local install path, always-on service path, and optional Docker path.
- `docs/packaging.md` - install, setup, diagnostics, and build artifact guidance.
- `docs/release_candidate.md` - version 0.1.0 release-candidate checklist and known limitations.
- `docs/raspberry_pi_deployment.md` - Linux/ARM service setup and low-resource guidance.
- `docs/configuration.md` - configuration layering, environment placeholders, and runtime settings.
- `docs/docker_deployment.md` - Docker Compose deployment for orchestrator, master, and worker.
- `docs/api_reference.md` - orchestrator HTTP endpoints and command payloads.
- `docs/saas_architecture.md` - future SaaS control-plane, tenant, enrollment, and communication design.
- `docs/network_control_layer.md` - advisory gateway and exposed-service posture assessment.
- `docs/security_authentication.md` - bearer-token auth, secret interpolation, and state scrubbing.
- `docs/firewall_plugins.md` - firewall plugin model and safety notes.
- `docs/beginner_guide.md` - conceptual guide for local network/firewall terminology.
- `docs/tui_dashboard.md` - Textual dashboard panels, controls, and data sources.

Current baseline:
- Use the repo-local `portmap-ai-env` created by `scripts/setup_environment.sh`.
- Install development dependencies with `pip install -r requirements-dev.txt`.
- Install the package locally with `pip install -e .`.
- Run the full suite with `python -m pytest`.
- Run the local stack with `portmap stack` or `scripts/run_stack.py`.
- Run the Textual dashboard with `portmap tui`, `scripts/run_dashboard.sh`, or allow the stack launcher to launch it.
- Review `CHANGELOG.md` and `docs/release_candidate.md` before cutting version `0.1.0`.

The dashboard is a terminal UI, not a browser UI. Browser-based product work belongs to a later roadmap phase.
