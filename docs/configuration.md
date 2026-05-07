# Configuration Architecture (Draft)

PortMap-AI uses a layered JSON configuration model designed for local testing, packaged deployments, and future SaaS multi-tenant scenarios.

## Layers

1. **Runtime defaults** – Code-level defaults supplied by each component (`defaults` param in `load_node_config`).
2. **Profile overrides** – Optional profile file under `config/profiles/<name>.json` selected via CLI (`--profile`) or config field `"profile"`.
3. **Instance config** – The JSON file passed to the component (e.g. `tests/node_configs/worker_orchestrated.json`).
4. **Environment substitutions** – Any string containing `${ENV_VAR}` or `${ENV_VAR:default}` is replaced at load time.
5. **Secrets** – Environment variables referenced via `${secret:ENV_VAR}` pattern.

Merging is deep (nested dictionaries combined recursively). Later layers override earlier ones.

## Example profile

```json
{
  "profile": "edge-lab",
  "master_ip": "${MASTER_IP:127.0.0.1}",
  "port": 9100,
  "secrets": {
    "tls_cert": "${PORTMAP_CERT_PATH}",
    "tls_key": "${PORTMAP_KEY_PATH}"
  }
}
```

## Hot reload (phase 1 scope)

The worker node will watch its config file (optional `--watch-config`) and apply safe fields without restart:

- `scan_interval`
- `enable_autolearn`
- `master_ip`
- `port`
- `timeout`

A future update will expand this to orchestrator/master hot reload once token rotation and service-level secret reload are designed.

## Settings file

Global settings remain at `~/.portmap-ai/data/settings.json` but now support env placeholders as above.

Common settings:

```json
{
  "enable_autolearn": false,
  "remediation_mode": "prompt",
  "remediation_threshold": 0.75,
  "orchestrator_url": "http://127.0.0.1:9100",
  "orchestrator_token": "${PORTMAP_ORCHESTRATOR_TOKEN:test-token}",
  "export_dir": "${PORTMAP_EXPORT_DIR:~/Downloads/portmap-ai-exports}",
  "expected_services": [
    {
      "port": 3306,
      "protocol": "MySQL",
      "program": "mysqld",
      "reason": "local development database"
    }
  ]
}
```

For shared or remote deployments, prefer secret interpolation:

```json
{
  "orchestrator_token": "${secret:PORTMAP_ORCHESTRATOR_TOKEN}"
}
```

Default development tokens such as `test-token` are accepted for local testing but should be replaced before remote, shared, Docker, Raspberry Pi, or SaaS-adjacent deployments.

`remediation_safety` controls the second safety gate for destructive actions. Active firewall enforcement requires active opt-in and command confirmation:

```json
{
  "remediation_safety": {
    "active_enforcement_enabled": false,
    "require_confirmation": true,
    "confirmation_token": "optional-shared-token"
  }
}
```

By default, destructive actions remain dry-run even if a firewall plugin is configured with `dry_run: false`.

`export_dir` controls where dashboard and CLI log exports are written when no explicit `--output-dir` is provided. The runtime default is `~/Downloads/portmap-ai-exports` so exported audit bundles are easy to find from Finder.

`expected_services` is the local allowlist. Use it for normal services you expect to see on the host. The dashboard can add/remove entries from observed remediation rows, and the scorer adds an `expected_service:<reason>` signal while lowering risk for matching services.

## Backwards compatibility

Existing sample configs remain valid. Profiles are optional; if omitted, only defaults + config file apply.

## Validation

Use the unified CLI to validate one or more config files before launching services:

```bash
portmap config validate core_engine/default_configs/orchestrator.json
portmap config validate core_engine/default_configs/master1.json core_engine/default_configs/worker_orchestrated.json
portmap config validate core_engine/default_configs/worker_orchestrated.json --role worker
portmap config validate ./my-worker.json --output json
```

The validator checks:

- `node_role` / legacy `mode`
- port ranges
- host fields
- scan intervals and timeouts
- orchestrator URLs
- remediation mode and threshold
- remediation safety policy
- log rotation settings
- orchestrator stale-node timeout (`node_stale_after`)
- TLS field types
- firewall plugin settings
- expected service allowlist entries
- auth token field types and default development token warnings

Integer-like values produced by environment substitution, such as `"${PORT:9000}"`, are accepted for numeric fields.

Legacy keys such as `mode`, `worker_id`, `listen_ip`, and `listen_port` are accepted with warnings so older examples can still be understood. New configs should prefer `node_role`, `node_id`, `master_ip`, and `port`.

Validation returns exit code `0` when there are no errors and `1` when any file has errors. Warnings do not fail validation.

Runtime services also validate after loading defaults, profiles, environment substitutions, and shared settings:

- `portmap-orchestrator` requires an orchestrator config.
- `portmap-master` requires a master config.
- `portmap-worker` requires a worker config.
- `portmap stack` validates all three node configs before launching subprocesses.

Invalid configs fail before network listeners start. Worker `--watch-config` hot reload also validates new config contents; invalid reloads are skipped and logged while the current runtime settings continue.
