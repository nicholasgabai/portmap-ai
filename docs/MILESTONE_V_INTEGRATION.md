# Milestone V Integration

Milestone V adds the deep network flow intelligence layer for PortMap-AI. It connects socket observations, reconstructed sessions, metadata-only packet correlation, DNS and destination behavior, process and service attribution, cross-node topology, probabilistic application attribution, behavioral drift, trust-zone inference, and service dependency mapping into one advisory topology-intelligence path.

This milestone remains local-first, metadata-only, advisory-first, source-mode aware, resource-bounded, Raspberry Pi/Linux ARM compatible, macOS/Linux/Windows aware, and export-safe. It does not inspect packet payloads, generate PCAP files, store raw DNS browsing history, create hardcoded live dummy labels, produce threat verdicts, require a graph database, or perform enforcement actions.

The pre-Milestone W live runtime bridge is documented in `docs/milestone_v_live_runtime_integration.md`. It invokes Milestone V summaries from bounded current worker socket snapshots and exposes runtime counters, Traffic Flows, Topology Edges, attribution, drift, and topology intelligence summaries through master telemetry events and operator-safe TUI/dashboard/API/export dictionaries.

## Phase Summary

### Phase 129 - Bidirectional Flow Reconstruction

Bidirectional flow reconstruction adds normalized session tracking records for inbound, outbound, local-loopback, and unknown-direction observations. It models session IDs, endpoint classes, ports, protocol, transport state, process/service attribution, source mode, observed timestamps, confidence, flow pairs, inferred sessions, transient sessions, recurring sessions, relationship strength, recurrence, and drift hints.

The phase turns repeated socket observations into current metadata-only flow relationships without packet payload inspection, raw packet storage, PCAP generation, DPI, credential handling, or enforcement.

### Phase 130 - Packet Metadata Correlation

Packet metadata correlation links packet metadata, socket observations, reconstructed sessions, redacted DNS/destination behavior, protocol hints, process/service attribution, and topology relationships. It preserves source mode and keeps unresolved live attribution as Unknown or Unattributed.

The phase also preserves the fixture/simulated-only boundary for demo labels such as `dummy_app` and `dummy_db`, preventing those labels from leaking into live/default runtime views.

### Phase 131 - Cross-Node Relationship Mapping

Cross-node relationship mapping adds normalized node relationship graph records for orchestrator, master, worker, edge, external, and unknown node classes. It models shared service state, recurring peer interaction score, topology distance, relationship strength, relationship confidence, drift hints, and source mode.

Advisory lateral analysis summarizes expected, unusual, suspicious, isolated, and unknown relationship states without creating threat verdicts, storing packets, requiring a graph database, or enforcing policy.

### Phase 132 - Dynamic Application Attribution

Dynamic application attribution adds generic probable application and service candidate records from process hints, service hints, protocol hints, destination behavior, flow behavior, and recurrence evidence. It also adds metadata-only behavioral signatures and deterministic confidence models.

Unresolved live/default attribution remains Unknown or Unattributed. Hardcoded fake app labels are restricted to explicit fixture or simulated source modes.

### Phase 133 - Behavioral Drift Detection

Behavioral drift detection compares current application, service, destination, flow, topology, and protocol observations against local historical baselines. It reports drift score, drift severity, recurrence state, confidence score, source mode, and advisory notes.

Environment drift aggregation rolls drift records into affected categories, stability score, drift trend, recurring change detection, unusual change detection, confidence, and operator summaries. Drift is not a threat verdict and does not trigger enforcement.

### Phase 134 - Network Topology Intelligence

Network topology intelligence infers internal, management, service, external, and unknown trust zones from normalized relationship records. It also maps service dependencies, recurring communication chains, node dependencies, topology adjacency, management dependencies, external dependencies, and unknown dependencies.

The phase provides bounded relationship strength, recurrence score, confidence score, topology distance, source mode, drift flags, dashboard/API dictionaries, and export-safe summaries without active probing, graph database dependency, traffic injection, or enforcement.

## Integration Points

### Socket Observations

Socket observations provide the metadata foundation for Milestone V. Phase 129 normalizes repeated socket rows into sessions and flow relationships while preserving source mode and current-snapshot boundaries.

### Reconstructed Sessions

Reconstructed sessions connect endpoint classes, ports, protocol, transport state, process/service attribution, timing, and confidence into session-aware flow records. Later phases use session references as stable evidence links.

### Metadata-Only Packet Correlation

Packet metadata correlation links packet summaries to sockets, sessions, DNS/destination behavior, protocol hints, process/service attribution, and topology relationships. It remains metadata-only and does not store packet bodies.

### DNS And Destination Behavior

Redacted or hashed DNS and destination summaries help correlate sessions and dependencies to recurring destinations, resolver behavior, novelty, and destination drift without retaining raw browsing history.

### Process And Service Attribution

Process and service attribution adds minimized local hints when available. Milestone V preserves Unknown and Unattributed live fallbacks when attribution is unavailable or unsupported.

### Cross-Node Topology

Cross-node relationship graphs connect orchestrator, master, worker, edge, external, and unknown node classes with shared service state, recurrence, topology distance, and relationship confidence.

### Probabilistic Application Attribution

Dynamic attribution combines process, service, protocol, destination, flow, and recurrence confidence into ranked generic application/service candidates. It avoids hardcoded live labels and keeps demo labels fixture/simulated-only.

### Behavioral Drift

Behavioral drift compares current metadata to local historical baselines, producing bounded advisory drift scores and environment summaries. Drift records can inform operator review, but they do not create threat verdicts.

### Trust-Zone Inference

Trust-zone inference groups relationship metadata into internal, management, service, external, and unknown zones. These records prepare future graph views and enterprise topology summaries while staying local and advisory.

### Service Dependency Mapping

Dependency mapping infers service dependencies, recurring communication chains, node dependencies, topology adjacency, management dependencies, and external dependencies from normalized relationship records. Outputs are dashboard/API/export-safe and graph-ready without a graph database.

### Live Runtime Bridge

The Milestone V live runtime bridge connects current worker telemetry to the Milestone V modules:

- Worker socket snapshots remain current, bounded, and deduplicated.
- The master dispatcher normalizes each `worker_telemetry` payload and builds Milestone V runtime counters.
- Reconstructed sessions, flow summaries, metadata correlations, process/service correlations, relationship edges, attribution candidates, drift records, trust-zone records, and dependency records are generated from metadata only.
- Nested flow rows are added to master telemetry events so the existing TUI Traffic Flows and Topology Edges panels can render current flow and topology summaries.
- ICMP ping absence is expected under socket-only mode, and very short-lived TCP or UDP activity may require scan timing alignment until a future passive capture path is explicitly enabled.
- Live/default unresolved attribution remains Unknown or Unattributed, while `dummy_app` and `dummy_db` remain restricted to explicit fixture or simulated source modes.

## Safety Guarantees

Milestone V explicitly guarantees:

- No packet payload inspection.
- No packet payload storage.
- No PCAP generation.
- No raw DNS browsing-history storage.
- No hardcoded live dummy labels.
- No enforcement actions.
- No threat verdicts yet.
- No graph database dependency.
- No active probing or traffic injection.
- No credential storage.
- No firewall, router, service, or host configuration changes.
- Metadata-only and advisory-first output.
- Source-mode preservation for live, simulated, fixture, replay, and unknown records.

## Data Flow

```text
socket observations
  -> reconstructed sessions and flow relationships
  -> metadata-only packet/socket/session correlation
  -> DNS, destination, protocol, process, and service context
  -> cross-node relationship graphs
  -> probabilistic application attribution
  -> behavioral drift summaries
  -> trust-zone inference and service dependency mapping
  -> dashboard/API/export-safe topology intelligence
  -> live runtime bridge counters and TUI flow/topology rows
```

## Mac Source-Of-Truth Runtime Checklist

Use sanitized records and local operator-approved runtime only.

- Run the full test suite from the Mac source-of-truth repository.
- Confirm `git diff --check` passes.
- Confirm sensitive-data scan passes for staged public files.
- Confirm artifact/private-file checks pass.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
- Build session, packet correlation, relationship graph, attribution, drift, trust-zone, and dependency summaries from sanitized fixtures.
- Confirm TUI and dashboard/API dictionaries preserve source mode.

## Raspberry Pi/Linux ARM Runtime Checklist

Pull only after the Mac push succeeds.

- Run focused Milestone V tests if full-suite runtime constraints require it.
- Validate current live snapshot deduplication remains bounded.
- Build recurring flow and relationship summaries from small fixture or live-like metadata.
- Confirm relationship graph boundedness with modest node and edge counts.
- Confirm drift summary boundedness and no unbounded historical growth in live views.
- Confirm CPU and RAM remain stable during repeated runtime cycles.
- Confirm no payloads, PCAPs, logs, screenshots, runtime databases, private paths, credentials, certs, or keys are staged.

## Windows Compatibility Fixtures Checklist

Use fixture records only.

- Validate Windows-style socket and process/service attribution fallback records.
- Confirm unresolved live-like attribution remains Unknown or Unattributed.
- Confirm source-mode fields serialize safely.
- Confirm relationship, attribution, drift, trust-zone, and dependency dictionaries remain deterministic.
- Confirm no driver, packet capture, firewall, service, registry, installer, credential, certificate, or key action is modeled as completed.

## Live Snapshot Deduplication Checklist

- Confirm repeated identical live scan snapshots do not grow result counts.
- Confirm stale/transient observations are pruned from latest live views.
- Confirm historical retention remains separate from current snapshot display.
- Confirm remediation scoring remains stable across repeated identical snapshots.

## Recurring Flow Stability Checklist

- Confirm repeated socket observations normalize into stable session and flow relationship records.
- Confirm recurring session classification is deterministic.
- Confirm recurrence scores are bounded from `0.0` to `1.0`.
- Confirm service dependency summaries do not duplicate unchanged relationships.

## Relationship Graph Boundedness Checklist

- Confirm duplicate relationship records collapse by stable relationship identifiers.
- Confirm topology distance and relationship confidence remain bounded.
- Confirm cross-node relationship summaries do not require a graph database.
- Confirm advisory lateral analysis does not produce threat verdicts.

## Drift Summary Boundedness Checklist

- Confirm drift scores and confidence scores remain bounded from `0.0` to `1.0`.
- Confirm malformed baseline/current inputs are isolated with structured errors.
- Confirm environment drift aggregation reports affected categories without enforcement.
- Confirm drift records are export-safe and metadata-only.

## TUI And Source-Mode Correctness Checklist

- Confirm live/default unresolved attribution displays as Unknown or Unattributed.
- Confirm `dummy_app` and `dummy_db` only appear in fixture or simulated records.
- Confirm TUI, dashboard, API, and export dictionaries preserve `source_mode`.
- Confirm replay records remain labeled as replay.

## CPU/RAM Stability Checklist

- Run repeated summary generation over bounded fixture sizes.
- Confirm no unbounded graph growth.
- Confirm no raw payload buffers or PCAP outputs are created.
- Confirm Raspberry Pi/edge defaults remain resource-conscious.

## Sensitive-Data Scan Checklist

- Scan staged docs, tests, and package metadata for private hostnames, IP addresses, usernames, MAC addresses, credentials, certs, keys, local paths, logs, screenshots, archives, runtime outputs, and databases.
- Confirm docs use sanitized placeholders and no private validation notes.

## Artifact And Private-File Check

- Confirm `docs/real_device_validation.md` is not staged.
- Confirm no `artifacts/`, logs, screenshots, archives, cache files, temp files, local runtime outputs, local databases, private credentials, certificates, or keys are staged.
- Confirm package metadata includes only public docs and sanitized fixtures.
