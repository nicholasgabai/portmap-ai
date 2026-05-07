# PortMap-AI 0.1.0 Release Candidate

This document defines the 0.1.0 release-candidate baseline.

## Release Scope

PortMap-AI 0.1.0 is a packaged local network security product with:

- reproducible Python dependency setup;
- installable package metadata and console scripts;
- local orchestrator/master/worker stack;
- CLI, TUI, scanner, risk scoring, logging, audit export, and remediation safety;
- Docker Compose assets as an optional deployment path;
- Raspberry Pi and general Linux service templates;
- security/authentication baseline for local and shared deployments;
- SaaS architecture and enrollment schema preparation.
- GitHub-readiness cleanup for ignored runtime artifacts, explicit Docker tokens, loopback local defaults, and security policy documentation.

## Verification Checklist

Before tagging 0.1.0:

```bash
python -m pytest
python -m pip wheel --no-deps -w /tmp/portmap-ai-wheel .
python -m pip install --force-reinstall --no-deps /tmp/portmap-ai-wheel/portmap_ai-0.1.0-py3-none-any.whl
portmap setup --output json
portmap doctor --output json
portmap --help
```

Optional runtime checks:

```bash
portmap stack --no-dashboard --verbose
portmap tui
portmap network --output json
docker compose config
```

`docker compose` requires Docker Engine with the Compose plugin. Docker is not required for the default local product path.

## Packaging Notes

The canonical package version is `0.1.0` in `pyproject.toml`.

Package data includes:

- default stack configs;
- local and Raspberry Pi profiles;
- user-scoped systemd service templates;
- the systemd install helper;
- operator documentation;
- example node configs.

## Known Limitations

- Windows support is planned but not release-candidate validated.
- Docker Compose assets are repository-validated, but local runtime validation depends on Docker availability.
- SaaS control-plane architecture is documented, but no hosted control plane is implemented.
- Router and network-control output is advisory-only.
- Active destructive remediation is opt-in and remains blocked by default.
- The local development token remains available only for loopback development flows; Docker/systemd/shared deployments should use generated or operator-provided tokens.

## Release Decision

0.1.0 is ready when the full test suite passes in the repo-local environment and the package can be built, installed, initialized, and diagnosed through the `portmap` CLI.
