# Raspberry Pi And Small Linux Deployment

Phase 12 targets Raspberry Pi OS as one supported Linux/ARM deployment. The implementation should remain multi-platform: Raspberry Pi support must not create a Pi-only architecture or remove macOS, general Linux, Docker, or future Windows paths.

## Positioning

Use this path for always-on local monitoring:

- Raspberry Pi OS on ARM.
- Debian/Ubuntu small-form-factor Linux hosts.
- Low-power home-network monitors.

Use the normal local install/CLI path for laptops and desktops. Use Docker Compose only when the operator explicitly wants containers.

## Install

On Raspberry Pi OS or Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
git clone https://github.com/<your-org>/portmap-ai.git
cd portmap-ai
scripts/setup_environment.sh
source portmap-ai-env/bin/activate
pip install -e .
```

Validate the install:

```bash
portmap --help
portmap scan --output json
python -m pytest tests/test_platform_utils.py tests/test_scanner.py tests/test_scoring.py
```

## Low-Resource Profile

The `raspberry_pi` profile is a conservative Linux/ARM profile:

- 15 second scan interval by default.
- Smaller rotating log size.
- Environment overrides for master host, ports, timeout, and scan interval.

Validate a worker config with the profile:

```bash
portmap config validate core_engine/default_configs/worker_orchestrated.json --profile raspberry_pi --role worker
```

Environment overrides:

```bash
PORTMAP_SCAN_INTERVAL=30 \
PORTMAP_MASTER_HOST=192.168.1.20 \
portmap-worker --config core_engine/default_configs/worker_orchestrated.json --profile raspberry_pi --continuous
```

## Native Service Mode

Linux and Raspberry Pi OS should run PortMap-AI through `systemd`. This keeps the product independent of Docker and suitable for 24/7 monitoring.

Two user-service templates are provided:

- `deploy/systemd/portmap-ai-stack.service`: runs a local all-in-one stack without the dashboard.
- `deploy/systemd/portmap-ai-worker.service`: runs only a worker that connects to an orchestrator/master configured in `~/.portmap-ai/data/worker.json`.

Install the all-in-one stack user service:

```bash
bash scripts/install_systemd_user.sh portmap-ai-stack.service
systemctl --user start portmap-ai-stack.service
systemctl --user status portmap-ai-stack.service
```

The install helper creates `~/.portmap-ai/portmap-ai.env` with a generated `PORTMAP_ORCHESTRATOR_TOKEN` when the file does not already exist. Keep this file private; it is installed with `0600` permissions.

Enable user services after reboot on headless systems:

```bash
loginctl enable-linger "$USER"
```

View logs:

```bash
journalctl --user -u portmap-ai-stack.service -f
portmap logs --output-dir ~/.portmap-ai/exports
```

Stop or disable:

```bash
systemctl --user stop portmap-ai-stack.service
systemctl --user disable portmap-ai-stack.service
```

## Worker-Only Mode

For a dedicated Raspberry Pi worker, create `~/.portmap-ai/data/worker.json`:

```json
{
  "node_role": "worker",
  "node_id": "pi-worker-001",
  "master_ip": "192.168.1.20",
  "port": 9000,
  "scan_interval": 15,
  "orchestrator_url": "http://192.168.1.20:9100",
  "orchestrator_token": "${secret:PORTMAP_ORCHESTRATOR_TOKEN}"
}
```

Then install the worker service:

```bash
bash scripts/install_systemd_user.sh portmap-ai-worker.service
systemctl --user start portmap-ai-worker.service
```

## Resource Guidance

Recommended baseline:

- Raspberry Pi 4 or newer.
- 2 GB RAM minimum.
- Reliable power supply.
- Wired Ethernet if available.
- Python 3.11 when possible.

Operational guidance:

- Start with scan intervals of 15 to 30 seconds.
- Keep remediation in prompt/dry-run mode.
- Use expected-service allowlists for normal local services.
- Keep logs rotated; the profile defaults to 1 MB logs with 3 backups.
- Export logs periodically if the SD card is small.

## LAN Scanning Safety

Current PortMap-AI scanner behavior is local host/socket focused. Do not add broad LAN scanning as a default behavior.

For future LAN scanning:

- Require explicit opt-in.
- Document the target CIDR.
- Rate-limit scans.
- Avoid destructive network actions.
- Keep remediation dry-run unless confirmed by policy.

## Multi-Platform Boundary

Raspberry Pi support should reuse existing cross-platform modules:

- `core_engine.platform_utils`
- `core_engine.config_loader`
- `core_engine.config_validation`
- `core_engine.stack_launcher`

Any Pi-specific behavior should be configuration, documentation, or service packaging. Core scanner, scoring, remediation, and orchestrator logic should remain portable across macOS, Linux, ARM Linux, Docker, and future Windows support.
