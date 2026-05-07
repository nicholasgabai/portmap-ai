# Deployment Options

PortMap-AI should not require users to understand Docker. Docker is powerful, but it is only one deployment mode.

## Recommended Path For Most Users

Use the local install and CLI.

Current developer/local flow:

```bash
scripts/setup_environment.sh
source portmap-ai-env/bin/activate
pip install -e .
portmap stack --verbose
```

Future packaged-user flow should be simpler:

```bash
pipx install portmap-ai
portmap setup
portmap doctor
portmap stack
portmap tui
```

The local install path runs the same core system:

- Orchestrator API
- Master node
- Worker node
- Textual dashboard
- Logs and settings under `~/.portmap-ai`

This is the default product path because it avoids container concepts, Docker Desktop setup, compose plugins, named volumes, image builds, and port mapping.

The default local stack binds the orchestrator and master to loopback addresses for release safety. Bind services to non-loopback interfaces only for trusted LAN deployments with explicit firewall rules and non-default authentication tokens.

## Always-On Local Monitoring

For 24/7 monitoring, PortMap-AI should run as a native service.

Target service managers:

- Linux and Raspberry Pi OS: `systemd`
- macOS: `launchd`
- Windows: Windows Service in a future phase

The service should start the local agent/stack on boot, write logs to `~/.portmap-ai/logs`, and keep configuration under `~/.portmap-ai/data`.

This is the right path for Raspberry Pi deployments and home-network monitoring.

Raspberry Pi is one Linux/ARM target, not a separate architecture. The same service approach should also work on other systemd-based Linux hosts. See `docs/raspberry_pi_deployment.md` for the current systemd templates, low-resource profile, and LAN-scanning safety notes.

## Docker Compose

Docker Compose is the advanced deployment path.

Use it when the operator already wants containers:

- Homelab or server environments
- Repeatable lab deployments
- CI or isolated integration testing
- Users who already run Docker-based network tools

Docker mode is documented in `docs/docker_deployment.md` and uses:

- `docker-compose.yml`
- `docker/config/*.json`
- named volume `portmap-runtime`

Docker Compose requires an explicit `PORTMAP_ORCHESTRATOR_TOKEN` because it publishes ports on the host. It intentionally does not fall back to the local development token.

Do not install Docker automatically for users. Installing Docker is a system-level action with platform-specific permissions, licensing/desktop choices, background services, and security implications. PortMap-AI should detect/document Docker support, not silently modify the user's machine to add it.

## Product Guidance

The user-facing choice should be:

1. Local Install - recommended for most users.
2. Raspberry Pi / Always-On Agent - recommended for continuous monitoring.
3. Docker Compose - optional advanced mode.

Phase 13 packaging should focus on making the Local Install path feel like a product:

- One setup command.
- One start/stop/status command set.
- Clear config location.
- Clear log/export location.
- No requirement to know repo paths.
- No Docker requirement.

Docker should remain available for users who prefer it, but it should never be presented as the only way to run PortMap-AI.
