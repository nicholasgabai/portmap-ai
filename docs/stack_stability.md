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
- Liveness is evaluated on node and metrics reads, not by a background timer. Heartbeat receipt time is the orchestrator's clock, independent of worker event timestamps.
- Registry updates use flushed same-directory temporary files and atomic replacement, so interrupted writes preserve the last complete registry. Persistence errors are logged, not durable-delivery acknowledgements.
- Worker identity prefers `node_id`, accepts the validated legacy `worker_id` alias, and otherwise falls back to the hostname. Use unique explicit IDs for multi-worker operation.

See [TEST 9 Distributed Runtime And Recovery](distributed_runtime_recovery.md) for the implementation audit, regression boundaries, remaining delivery/security limitations, and Raspberry Pi revalidation procedure. No physical TEST 9 acceptance is implied by local tests.

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
