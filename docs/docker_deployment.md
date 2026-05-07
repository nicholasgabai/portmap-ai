# Docker Deployment

Phase 11 adds a local Docker Compose deployment for the orchestrator, master, and worker services.

Docker is optional. Most users should start with the local install/CLI path documented in `docs/quick_start.md` and `docs/deployment_options.md`. Use Docker Compose when you specifically want a containerized lab/server deployment.

## Services

`docker-compose.yml` defines three services:

- `orchestrator`: HTTP API on container port `9100`, published to host port `9100` by default.
- `master`: worker socket listener on container port `9000`, published to host port `9000` by default.
- `worker`: continuous scanner that connects to `master:9000` and registers with `http://orchestrator:9100`.

All services mount the named volume `portmap-runtime` at `/root/.portmap-ai` so logs, state, settings, and exports persist across container restarts.

## Run

Requires Docker Engine with the Compose plugin (`docker compose`). On older Docker installs, install the plugin or use a compatible `docker-compose` binary.

```bash
export PORTMAP_ORCHESTRATOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build
```

Run in the background:

```bash
export PORTMAP_ORCHESTRATOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose up --build -d
```

Stop the stack:

```bash
docker compose down
```

Remove persisted runtime state:

```bash
docker compose down -v
```

## Configuration

Docker-specific config files live under `docker/config/`:

- `docker/config/orchestrator.json`
- `docker/config/master.json`
- `docker/config/worker.json`

These use environment placeholders so the same files work locally and in containers. Docker Compose requires `PORTMAP_ORCHESTRATOR_TOKEN`; it intentionally does not fall back to the local development token because the compose stack publishes ports on the host.

Common overrides:

```bash
PORTMAP_ORCHESTRATOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')" \
PORTMAP_NODE_ID=worker-lab-01 \
PORTMAP_SCAN_INTERVAL=10 \
docker compose up --build
```

Published host ports can also be changed:

```bash
PORTMAP_ORCHESTRATOR_PORT=19100 \
PORTMAP_MASTER_PORT=19000 \
docker compose up --build
```

Inside the compose network, service-to-service traffic still uses `orchestrator:9100` and `master:9000`.

## Logs And State

Runtime files are stored in the `portmap-runtime` volume:

- `/root/.portmap-ai/logs`
- `/root/.portmap-ai/data`
- `/root/.portmap-ai/exports`

Inspect logs with:

```bash
docker compose logs -f orchestrator master worker
```

Copy persisted logs out of the volume by running a temporary container:

```bash
docker compose run --rm worker portmap logs --output-dir /root/.portmap-ai/exports
```

## Health Checks

The orchestrator service has a health check against `/healthz` with bearer-token auth. `master` waits for the orchestrator to become healthy, and `worker` waits for the orchestrator plus the master service start.

Manual API checks from the host:

```bash
curl -H "Authorization: Bearer ${PORTMAP_ORCHESTRATOR_TOKEN}" http://127.0.0.1:9100/healthz
curl -H "Authorization: Bearer ${PORTMAP_ORCHESTRATOR_TOKEN}" http://127.0.0.1:9100/nodes
curl -H "Authorization: Bearer ${PORTMAP_ORCHESTRATOR_TOKEN}" http://127.0.0.1:9100/metrics
```

## Safety

Docker deployment keeps the existing remediation safety defaults. Firewall enforcement remains dry-run unless configuration explicitly enables active enforcement and commands include confirmation.
