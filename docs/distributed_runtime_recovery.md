# TEST 9: Distributed Runtime And Recovery

This unnumbered validation milestone follows the operator-validated TEST 8R
baseline `4312e5d`. It preserves UTC, canonical evidence references, listener
semantics, socket counter provenance, and read-only/preview defaults. The
development environment has no access to the Raspberry Pi. Local tests are
not distributed physical acceptance.

## Architecture Audit

| Area | Active implementation and contract |
| --- | --- |
| Startup | `core_engine/stack_launcher.py`, packaged `portmap stack`, and `scripts/run_stack.py` validate configs, check master/orchestrator port conflicts, and launch separate Python modules. Direct module startup is also supported. |
| Recovery | The stack polls child processes and restarts each core role up to the configured limit (default three). It does not detect hung but still-running children. Workers attempt a fresh master connection each cycle. |
| Registry | `core_engine/orchestrator.py` serves registration, heartbeat, nodes, health, metrics, and command queues through `OrchestratorState`. Workers register; master/API health is not implied by the worker count. |
| Liveness | Workers heartbeat each cycle. The receiver records epoch seconds using its own clock; this unambiguous instant is independent of source event time. Reads expire stale nodes using the configured TTL. A heartbeat restores online status. |
| Identity | `worker_node.run_worker` prefers `node_id`, then legacy `worker_id`, then hostname. The configured value survives reconnect/restart. It is a logical identity, not proof of machine identity. Duplicate configured IDs still refer to one registry entry. |
| Transport | Worker/master telemetry uses newline JSON frames (2 MiB limit), partial-read handling, and legacy raw-JSON compatibility. TCP connection/read timeouts and optional TLS are supported. The master handles accepted connections serially. |
| Authentication | The orchestrator uses the existing bearer check; empty-token development mode remains possible. Master telemetry has no separate bearer authentication. Optional TLS supports verification and configured client certificates, but certificate identity is not bound to claimed `node_id`. |
| Ingestion | `dispatcher.dispatch_alert` normalizes worker snapshots and invokes the runtime bridge, session/flow reconstruction, correlation, and deterministic attribution. The master appends enriched metadata to JSONL. |
| Persistence | Registry nodes and pending commands persist in local JSON. Evidence logs are append-only. SQLite/API/export helpers preserve canonical fields when explicitly invoked; there is no automatic worker-to-SQLite background writer. |
| Replay | Raw audit deliveries can repeat. Derived socket flow counts deduplicate scoped sample ID plus event time. SQLite's unique event ID rejects duplicates with `StorageError` rather than overwriting stored evidence. This is not transactional exactly-once delivery. |
| Time and display | Worker event time remains separate from receiver ingestion time. Canonical instants use aware UTC/ISO-8601 `Z`. Ambiguous legacy strings stay ambiguous. Risk/AI/Packet details retain the established UTC labels and references. |

Existing tests already cover TEST 8R worker/bridge/SQLite/API/TUI propagation,
IPv4/IPv6 endpoint separation, listener exclusion from Packet conversations,
counter provenance, UTC rollover, wrapping, and viewport persistence. Stack
supervision and platform process helpers have unit coverage. Windows adapters
and platform detection tests do not establish native Windows distributed
acceptance; ARM/multi-host operation still needs operator validation.

## Confirmed Defects Corrected

1. Worker TLS setup failures left the raw TCP socket unclosed. Socket ownership
   is now established before TLS wrapping, so errors close it without falling
   back to plaintext.
2. Master TLS acceptance had no handshake timeout; connection resets/timeouts
   outside `SSLError` could exit the accept loop. TLS handshakes now use the
   existing five-second frame timeout and reject transport failures before
   accepting the next worker. Verification/authentication settings are unchanged.
3. Registry updates truncated the live state file before writing. Updates now
   write a same-directory temporary file, flush/fsync it, close it, and replace
   the target atomically. Handled failures preserve the old file and clean up
   the temporary file. Existing JSON schema and historical evidence are unchanged.
4. Stale transitions occurred only when `/nodes` was read. Metrics polling
   (including TUI health refresh) and individual node reads now also expire stale
   nodes. Node totals include offline entries; online totals count live statuses.
5. Config validation accepted `worker_id`, but runtime ignored it. The worker
   now honors that legacy alias after `node_id`. Old hostname-keyed history is
   not renamed or rewritten; operators should identify any historical alias
   explicitly before comparing old and new records.

No score, AI classification, capture, scanner, enforcement, blocking,
remediation-execution, or authorization algorithm changes are included.

## Regression Coverage And Boundaries

- `tests/test_worker_master_telemetry_framing.py`: existing partial-frame tests
  plus disconnect/refusal/timeout recovery, TLS failure cleanup, no plaintext
  fallback, and master rejection followed by another worker's successful ingest.
- `tests/test_worker_resilience.py`: real worker-loop/control-helper calls with
  in-process transport stubs exercise unavailable orchestrator, unknown-node
  re-registration, restart, explicit ID precedence, and legacy ID compatibility.
- `tests/test_orchestrator_state.py`: two-worker liveness transitions, metrics-only
  expiration, persisted reload, heartbeat recovery, and interrupted writes or
  failed replacements preserving the last complete registry and queued metadata.
- `tests/test_runtime_evidence_integrity.py`: existing two-worker sampling/replay
  tests plus reordered delivery, a deliberately fast worker clock, UTC rollover,
  SQLite rejection without overwrite, API reload, Risk/AI identity consistency,
  and tuple reuse with and without explicit source lifetime references.
- `tests/integration/test_orchestrator_integration.py`: real loopback subprocess
  tests cover two registrations, unauthenticated rejection, orchestrator restart
  with persisted nodes/queued metadata, and master restart with two logical worker
  clients and replay. Synthetic metadata is sent over real local sockets; no
  worker collector, capture, or external scanning is started. Temporary homes
  isolate all child runtime state. These tests skip explicitly if binding is denied.

Two samples of an identical socket tuple are not proof of two TCP connection
lifetimes. Without source lifetime references, canonical session/flow IDs describe
the same endpoint relationship; separate sample IDs are retained. Packet's
60-second inactivity window can create distinct aggregation windows carrying
the same canonical source session/flow references. A window is not evidence of
a new connection. Explicit source session/flow references keep known lifetimes
separate even inside one window. No heuristic lifetime ID is invented.

Out-of-order delivery preserves source time and receiver time. Current TUI
snapshots use receipt order, so an old source observation arriving last can be
the current snapshot. Historical flow ordering uses known event instants; it
does not correct clock skew. Future worker timestamps are not relabeled or
silently moved to the receiver's time.

## Remaining Reliability And Security Limits

- There is no durable worker outbox, retransmission/commit protocol, or guaranteed
  recovery of samples lost while the master is down. The next cycle samples again.
- An ACK indicates handled telemetry, not fsync-confirmed evidence durability.
  Dispatcher log-write errors are currently logged rather than propagated to the
  sender. Raw delivery/risk audit entries can repeat; no new global dedup store
  or command exactly-once protocol is introduced.
- Atomic replacement prevents torn registry JSON; it does not provide power-loss
  guarantees for directory metadata, command acknowledgements, cross-process
  registry locking, or multi-orchestrator writes. Metrics counters reset on restart.
- The master remains IPv4-listening and serial. Frame timeout is an inactivity
  limit, not a total slow-client deadline or multi-client fairness guarantee.
- Shared bearer tokens do not establish per-worker identity. The orchestrator's
  HTTP listener is not TLS-wrapped here. Non-loopback deployment needs an approved
  protected transport and properly verified worker/master TLS, not disabled
  certificate verification. Do not expose development defaults publicly.
- Receiver clock changes and host clock skew still need operational time sync.
  Offline status is refreshed on reads, not by a new daemon. A responding
  `/healthz` is API responsiveness, not proof that master ingestion is healthy.
- Actual multi-machine outages, SD-card/power failures, native Windows recovery,
  real certificate rotation, and physical Pi TEST 9 remain unverified locally.

## Raspberry Pi Multi-Process Procedure

Development-host validation: the complete sandbox suite passed 1,994 tests with
zero failures and two port-binding skips. Both skipped subprocess/socket tests
were then run outside the sandbox and passed on Mac loopback. This verifies
local recovery, not physical multi-host or Raspberry Pi recovery.

Use the existing Python environment from the repository. Stop the old stack
normally first; do not run this alongside its supervised children. Preserve
private validation notes. Pull with `git pull --ff-only origin main`, record
`git rev-parse HEAD`, and record `date -u '+%Y-%m-%dT%H:%M:%SZ'` on every host.

Prepare private copies of the already-validated configuration as
`$HOME/.portmap-ai/test9/orchestrator.json`, `master.json`, `worker-a.json`, and
`worker-b.json`. Give the workers distinct explicit `node_id` values. Keep the
same configured bearer token, verified TLS settings where used, and read-only/
preview defaults; do not copy public example tokens into a remote deployment.
Use loopback for a one-Pi multi-process test. A second physical host requires
separately approved addresses, transport protection, and firewall configuration;
do not disable verification to make it connect. These commands assume prepared
configs; they do not generate or overwrite runtime settings.

Run automated tests before starting the live processes:

```bash
python -m pytest tests/test_worker_resilience.py tests/test_worker_master_telemetry_framing.py tests/test_orchestrator_state.py tests/test_runtime_evidence_integrity.py
python -m pytest tests/integration/test_orchestrator_integration.py -v -rs
```

Run each command in a separate Pi terminal, in this order:

```bash
python -m core_engine.orchestrator --config "$HOME/.portmap-ai/test9/orchestrator.json"
python -m core_engine.master_node --config "$HOME/.portmap-ai/test9/master.json"
python -m core_engine.worker_node --config "$HOME/.portmap-ai/test9/worker-a.json" --continuous
python -m core_engine.worker_node --config "$HOME/.portmap-ai/test9/worker-b.json" --continuous
```

In another terminal, using the validated orchestrator environment:

```bash
python -m cli.main health
python -m cli.main nodes
python -m cli.main metrics
ss -ltn '( sport = :9000 or sport = :9100 )'
ss -tn state established '( sport = :22 or dport = :22 )'
python -m cli.main tui
```

Keep an ordinary authorized SSH session open. Compare Dashboard, Risk, AI, and
Packet node/endpoint/sample references, UTC event/ingestion times, and socket-only
event counters. Do not expect different worker perspectives to share canonical
IDs. Listeners must retain listener provenance and not-applicable flow/session IDs.

1. Ctrl-C worker A only. Leave worker B running. Wait longer than configured
   `node_stale_after`, run `nodes` and `metrics`, and confirm A offline/B online.
2. Restart A with the same command/config. Confirm the same node returns online
   without an additional registry entry; new samples may have new observation IDs.
3. Ctrl-C the master only. Confirm bounded worker send errors while orchestrator
   heartbeats remain healthy. Restart the master with its original command.
   New evidence must resume; do not claim samples during downtime were recovered.
4. Ctrl-C the orchestrator only. Observe failed health/heartbeat checks, not a
   fabricated master crash. Restart it with the same configuration. Confirm the
   two registrations persist and heartbeats resume without duplicate nodes.
5. Restart the TUI and re-check historical references and UTC labels. Inspect
   wrapped details through refresh. Do not delete state files to force recovery.
6. Stop workers, master, and orchestrator normally. Record outcomes privately;
   no physical PASS is implied by these instructions.

## Recommended Next Steps

First specify and test authenticated worker identity binding, durable delivery
and negative acknowledgements, bounded backpressure, and clock-skew diagnostics.
Then validate two physical nodes and supported operating systems. Before any
external scanning, require explicit target authorization, scope/rate limits,
cancellation, and auditable preview. Before authorized capture, validate privilege
boundaries, explicit opt-in, bounded metadata retention, and independently
measured counter provenance. None of those capabilities is activated by TEST 9.
