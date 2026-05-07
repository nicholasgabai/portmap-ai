# API Reference (Draft)

## Orchestrator HTTP API

| Endpoint | Method | Description | Auth |
|----------|--------|-------------|------|
| `/healthz` | GET | Health check; returns `{status: ok}` | Optional: `Authorization: Bearer <token>` when auth enabled |
| `/register` | POST | Register node with payload `{node_id, role, address, meta?}` | Yes |
| `/heartbeat` | POST | Worker heartbeat `{node_id, status, meta?}`; returns pending commands | Yes |
| `/commands` | POST | Queue command for node `{node_id, command}` | Yes |
| `/metrics` | GET | Returns counters `{registers, heartbeats, commands_queued}` | Yes |
| `/nodes` | GET | List registered nodes | Yes |

Authentication uses `Authorization: Bearer <token>` when `auth_token` or `orchestrator_token` is configured. Token comparison is constant-time. See `docs/security_authentication.md`.

## Commands

Example payload for `scan_now`:
```json
{
  "node_id": "worker-001",
  "command": {"type": "scan_now"}
}
```

Remediation command (issued by master automatically):
```json
{
  "type": "apply_remediation",
  "decision": "block",
  "connection": {"program": "svc", "port": 8080},
  "reason": "policy",
  "dry_run": true
}
```

## Configuration keys
- `firewall.plugin`: `noop`, `linux_iptables`, etc.
- `tls.enabled`: enable TLS on master/worker; see `docs/configuration.md` for details.
- `orchestrator_token`: shared bearer token for client authentication.
- `auth_token`: orchestrator API bearer token; use `${secret:PORTMAP_ORCHESTRATOR_TOKEN}` for shared deployments.
- `export_dir`: default directory for log/audit zip exports when `--output-dir` is not provided. Defaults to `~/Downloads/portmap-ai-exports`.

## Metrics
Delivered via `/metrics` and visible in the dashboard metrics panel:
- `registers`: total node registrations
- `heartbeats`: total heartbeats received
- `commands_queued`: commands delivered to workers
