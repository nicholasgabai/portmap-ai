# PortMap-AI Test Instructions

## 1. Environment Setup
```bash
cd <repo-root>
scripts/setup_environment.sh
source portmap-ai-env/bin/activate
pip install -e .
```

Use the repo-local `portmap-ai-env`. Older sibling environments from previous experiments should not be treated as the reproducible baseline.

## 2. Launch Full Stack (orchestrator, master, worker, dashboard)
```bash
scripts/run_stack.py --verbose
```
Observe orchestrator/master/worker logs for successful connections; the dashboard should open automatically.

Docker is not required for the normal local stack. The default user path is local install plus `portmap stack`; Docker Compose is an optional advanced deployment path.

## 3. Dashboard Functional Checks
- Click **Scan Now** and **Toggle Autolearn** buttons; confirm log lines appear in worker/master consoles.
- Use **Detect Orchestrator**; verify dashboard logs detection line.
- Press **Export Logs**; confirm archive path printed.
- Hit `?` to view help overlay; `Esc` to close.

## 4. CLI Tests (new terminal, same venv)
```bash
python -m pytest
```

## 4a. Unified CLI Checks
```bash
python -m cli.main --help
portmap --help
python -m cli.main scan --output json
portmap scan --output json
python -m cli.main stack --no-dashboard --verbose
```

With the stack running in another terminal:
```bash
python -m cli.main health
python -m cli.main nodes
python -m cli.main metrics
portmap health
portmap nodes
portmap metrics
```

## 4b. Config Validation Checks
```bash
portmap config validate core_engine/default_configs/orchestrator.json
portmap config validate core_engine/default_configs/master1.json core_engine/default_configs/worker_orchestrated.json
portmap config validate core_engine/default_configs/worker_orchestrated.json --role worker
```

Invalid configs should return exit code `1` with readable errors:

```bash
portmap config validate tests/node_configs/master_config_multi_nodes.json
```

## 4c. Audit Log Checks
```bash
portmap logs --filter-event-type command_event --tail 10
portmap logs --filter-event-type remediation_decision --tail 10
portmap logs --output-dir ./artifacts
```

## 4d. Remediation Safety Checks
```bash
python -m pytest tests/test_remediation_safety.py tests/test_master_remediation.py tests/test_agent_service.py
```

## 4e. Scanner and Risk Engine Checks
```bash
python -m pytest tests/test_scanner.py tests/test_scoring.py
portmap scan --output json
```

## 4f. AI Layer Checks
```bash
python -m pytest tests/test_ai_interface.py tests/test_scoring.py
```

## 4g. TUI Dashboard Checks
```bash
python -m pytest tests/test_gui_app.py
portmap tui
```

## 4h. Docker Deployment Checks
```bash
python -m pytest tests/test_docker_deployment.py tests/test_packaging.py
docker compose config
docker compose up --build
```
Requires Docker Engine with the Compose plugin available as `docker compose`.
Skip the compose commands on machines without Docker Compose; the Python tests still validate the repository-side Docker contract.

## 4i. Deployment Option Documentation Checks
```bash
python -m pytest tests/test_packaging.py
```
Read `docs/deployment_options.md` and confirm it presents:
- Local Install as the recommended default.
- Raspberry Pi / always-on service as the continuous monitoring path.
- Docker Compose as optional advanced mode.

## 4j. Raspberry Pi / Linux Service Checks
```bash
python -m pytest tests/test_raspberry_pi_deployment.py tests/test_packaging.py
portmap config validate core_engine/default_configs/worker_orchestrated.json --profile raspberry_pi --role worker
```
Read `docs/raspberry_pi_deployment.md` and confirm the guidance remains Linux/ARM compatible without making Raspberry Pi the only supported platform.

## 4k. Network Control Layer Checks
```bash
python -m pytest tests/test_network_control.py tests/test_cli_main.py
portmap network
portmap network --output json
```
Confirm output is advisory-only and does not claim to modify router, firewall, NAT, or port-forward settings.

## 4l. Security and Authentication Checks
```bash
python -m pytest tests/test_security.py tests/test_config_loader.py tests/test_config_validation.py tests/test_orchestrator_state.py
PORTMAP_ORCHESTRATOR_TOKEN=secret-from-env portmap config validate core_engine/default_configs/orchestrator.json
```
Read `docs/security_authentication.md` and confirm shared/remote deployments are directed to use non-default bearer tokens via environment-backed secrets.

## 4m. SaaS Preparation and Release Candidate Checks
```bash
python -m pytest tests/test_enrollment.py tests/test_release_candidate.py tests/test_packaging.py
```
Read `docs/architecture.md`, `docs/saas_architecture.md`, `docs/release_candidate.md`, and `CHANGELOG.md`.
Confirm 0.1.0 remains local-first, SaaS is documented but not required, Docker is optional, and release checks include tests, wheel build, setup, and doctor.

## 5. Integration Test
```bash
scripts/run_integration_tests.sh
```
(Skips automatically if ports unavailable.)

## 6. Packaging Smoke Test
```bash
scripts/package_local.sh
ls dist/
python -m pip wheel --no-deps -w /tmp/portmap-ai-wheel .
python -m pip install --force-reinstall --no-deps /tmp/portmap-ai-wheel/portmap_ai-0.1.0-py3-none-any.whl
cd /tmp
portmap --help
portmap setup --output json
portmap doctor --output json
portmap stack --no-dashboard --verbose
```

## 7. Optional: Docker Build
```bash
docker build -f docker/orchestrator.Dockerfile -t portmap-orch:dev .
docker build -f docker/worker.Dockerfile -t portmap-worker:dev .
```

## 8. Shutdown
- For `run_stack.py`, press `Ctrl+C` once to stop all services.
- Deactivate environment: `deactivate`
