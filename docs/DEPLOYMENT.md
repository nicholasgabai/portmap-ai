# PortMap-AI Deployment

PortMap-AI supports local-first operation. This document summarizes deployment choices; detailed historical context lives in `PORTMAP_AI_HANDOFF.md`.

## Recommended Local Install

```bash
python3 -m venv portmap-ai-env
source portmap-ai-env/bin/activate
pip install -r requirements-dev.txt
pip install -e .
portmap setup
portmap doctor
portmap stack --no-dashboard --verbose
portmap tui
```

Use the local install path for development, demos, and most operator testing.

## Linux and Raspberry Pi

Use the same package install path, then choose either:

- foreground stack testing with `portmap stack --no-dashboard --verbose`;
- user-scoped `systemd` templates from `deploy/systemd/` for always-on operation.

Raspberry Pi is a supported Linux/ARM deployment target, not a product boundary. Validate the target device with `docs/real_device_validation.md` before claiming runtime support for that device class.

## macOS

macOS is suitable for local CLI, stack, dashboard, and non-privileged validation. Packet capture paths can return graceful unsupported or permission-denied results depending on host capabilities.

## Docker Compose

Docker Compose is optional and intended for operators who already want containers. It requires an explicit `PORTMAP_ORCHESTRATOR_TOKEN` when publishing host ports.

## Windows

Windows support remains pending external runtime validation. Keep Windows documentation conservative until validation results are returned.

## Validation

Use `docs/real_device_validation.md` for device-specific checklists and record results before release notes or GitHub publication.
