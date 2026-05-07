# Stack Stability

Phase 5 hardens the local distributed stack around predictable startup, shutdown, and recovery behavior.

Implemented baseline:

- `portmap stack` validates all orchestrator, master, and worker configs before launching subprocesses.
- `portmap stack` checks orchestrator/master port conflicts before startup.
- Core stack services are supervised with bounded restarts. By default each core service can restart up to three times after an unexpected exit.
- Use `--restart-limit N` to change the restart limit.
- Use `--no-restart` to disable restart supervision.
- Dashboard exit no longer forces the core stack down; orchestrator, master, and worker continue running.
- Shutdown terminates dashboard and core services through the shared platform process helpers.
- Workers retry master connections naturally on each scan cycle, so a restarted master is picked up on the next cycle.
- Workers and the background agent re-register with the orchestrator if a heartbeat returns an unknown-node response, which covers orchestrator restarts or state loss.
- The orchestrator marks stale nodes offline after `node_stale_after` seconds without a heartbeat. Set `node_stale_after` to `0` to disable stale detection.

Example:

```bash
portmap stack --verbose --restart-limit 5
portmap stack --no-dashboard --no-restart
```

Relevant config:

```json
{
  "node_role": "orchestrator",
  "bind_ip": "127.0.0.1",
  "port": 9100,
  "auth_token": "test-token",
  "node_stale_after": 60
}
```
