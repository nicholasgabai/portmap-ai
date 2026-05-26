# Phase 93-98 Gateway and Telemetry Enrichment Plan

Milestone P defines the next implementation milestone after the completed Milestone O live telemetry foundation. Recent sanitized real-device validation showed PortMap-AI can run as a stable long-duration local telemetry platform with orchestrator, master, worker, TUI, runtime status, runtime export, remote administration, node heartbeats, scoring, advisory remediation, and live dashboard updates functioning together.

The architectural conclusion from that validation is that PortMap-AI should enrich telemetry quality before moving into full gateway/router-adjacent deployment. Gateway and router-adjacent workflows need stronger flow, process, service, DNS, log-ingestion, and readiness records before inline or bridge-style operation is considered.

This is a planning document only. It does not implement gateway behavior, start services, change host networking, modify router settings, start packet capture loops, transmit telemetry externally, or perform automatic enforcement.

## Milestone P: Gateway and Telemetry Enrichment

Goal:
Strengthen PortMap-AI's live telemetry intelligence before full gateway/router-adjacent deployment by adding richer flow telemetry, process/service attribution, DNS visibility, gateway/router log ingestion, SPAN/mirror-port readiness, and gateway validation workflows.

Milestone P must remain:

- local-first
- passive-first
- operator-controlled
- advisory by default
- dry-run safe by default
- metadata-only by default
- resource-conscious
- Raspberry Pi compatible
- macOS testable
- safe for public GitHub documentation
- testable with sanitized fixtures

## Sanitized Milestone O Validation Evidence

Recent real-device validation, sanitized for public documentation, confirmed:

- Full test suite passed after Milestone O.
- Runtime status returned a healthy dry-run state.
- Runtime export produced deterministic digest output.
- Stack launch brought up orchestrator, master, and worker components successfully.
- The Textual TUI remained responsive during extended runtime.
- Worker heartbeat behavior remained stable over an extended run.
- Scoring and advisory remediation stayed active.
- Dry-run safety remained intact.
- Remote administration workflow was validated through an approved secure shell workflow.
- Duplicate stack startup was correctly blocked when required local ports were already in use.
- Dashboard showed multi-node online status.
- Dashboard showed live score changes, open/listening service observations, service-category observations, and heuristic signal labels.
- No automatic blocking or enforcement occurred.

No real IP addresses, hostnames, usernames, MAC addresses, screenshots, private paths, connection details, runtime logs, tokens, or raw validation artifacts should be committed.

## Phase 93 - Real Flow Telemetry Enrichment

Status: Complete Baseline

Goal:
Add richer metadata-only flow observation records and rolling summaries for higher-quality topology, scoring, dashboard, and gateway-readiness workflows.

Build:

- `core_engine/telemetry/flow_enrichment.py`
- `core_engine/telemetry/flow_observations.py`
- `tests/test_flow_telemetry_enrichment.py`
- `docs/flow_telemetry_enrichment.md`

Features:

- Enriched flow observation records.
- Rolling flow statistics.
- Bytes and packet counters.
- First-seen and last-seen timestamps.
- Direction inference.
- Local versus remote endpoint classification.
- Service-port hint correlation.
- State transition summaries.
- Flow confidence scoring.
- Telemetry quality flags.
- Dashboard/API-ready enriched flow dictionaries.

Acceptance:

- Deterministic enriched flow summaries from sanitized fixtures.
- No raw payload storage.
- Malformed and incomplete flow inputs are handled safely.
- Bounded memory behavior.
- Existing flow reconstruction tests still pass.

## Phase 94 - Process and Service Attribution

Status: Complete Baseline

Goal:
Correlate available local OS process, socket, and service metadata with telemetry records while minimizing sensitive process details.

Build:

- `core_engine/telemetry/process_attribution.py`
- `core_engine/telemetry/service_attribution.py`
- `tests/test_process_service_attribution.py`
- `docs/process_service_attribution.md`

Features:

- Process-to-port attribution summaries where OS data is available.
- Service-name correlation.
- Listening socket ownership summaries.
- Confidence levels for attribution.
- Unsupported-platform fallback behavior.
- Permission-denied safe handling.
- Process metadata minimization.
- Sanitized operator display records.
- Dashboard/API-ready attribution dictionaries.

Acceptance:

- Attribution works with sanitized fixture data.
- Permission failures produce safe degraded status.
- No sensitive command-line secrets are exposed.
- Platform-specific behavior is documented safely.
- No privilege escalation attempts.

## Phase 95 - DNS Visibility Mode

Status: Complete Baseline

Goal:
Build metadata-only DNS visibility and DNS-to-flow correlation summaries for local telemetry and gateway-readiness workflows.

Build:

- `core_engine/telemetry/dns_visibility.py`
- `core_engine/telemetry/dns_correlation.py`
- `tests/test_dns_visibility_mode.py`
- `docs/dns_visibility_mode.md`

Features:

- DNS query and response metadata records.
- Domain-to-flow correlation.
- DNS timing summaries.
- Resolver classification.
- NXDOMAIN and error summaries.
- Encrypted DNS visibility limitations.
- DNS anomaly hints.
- Safe domain truncation and redaction options.
- Dashboard/API-ready DNS visibility dictionaries.

Acceptance:

- Metadata-only DNS summaries.
- No payload or content retention beyond safe DNS metadata.
- Deterministic fixture tests.
- Graceful handling of encrypted or unknown DNS.
- No credential extraction.

## Phase 96 - Gateway and Router Log Ingestion

Status: Complete Baseline

Goal:
Add local, operator-provided gateway/router log parsing helpers that normalize sanitized records for events, topology, exports, and future gateway workflows.

Build:

- `core_engine/gateway/router_logs.py`
- `core_engine/gateway/log_parsers.py`
- `core_engine/gateway/__init__.py`
- `tests/test_gateway_router_log_ingestion.py`
- `docs/gateway_router_log_ingestion.md`

Features:

- Sanitized router log record models.
- Common router/firewall log parser helpers.
- Syslog-style fixture parsing.
- NAT and event summary records.
- Allow/deny event summaries.
- Source/destination metadata normalization.
- Timestamp normalization.
- Gateway event severity summaries.
- Integration hooks for runtime events, topology, and exports.

Acceptance:

- Parser tests use sanitized sample logs only.
- No real router logs are committed.
- Malformed logs are handled safely.
- No router configuration changes.
- No external syslog listener is started unless explicitly dry-run modeled.

## Phase 97 - SPAN / Mirror-Port Readiness

Status: Complete Baseline

Goal:
Add dry-run readiness models for future passive SPAN and mirror-port telemetry without changing interface modes or starting capture loops.

Build:

- `core_engine/gateway/span_readiness.py`
- `core_engine/gateway/mirror_profiles.py`
- `tests/test_span_mirror_port_readiness.py`
- `docs/span_mirror_port_readiness.md`

Features:

- SPAN/mirror-port readiness profile records.
- Passive capture mode requirements.
- Interface capability summaries.
- Expected traffic volume warnings.
- Resource budget checks.
- Privilege requirement documentation.
- Packet-loss risk summaries.
- Operator checklist output.
- Dashboard/API-ready readiness dictionaries.

Acceptance:

- Readiness checks are dry-run only.
- No interface mode changes are performed.
- No promiscuous capture loop is started.
- Resource warnings are deterministic.
- Raspberry Pi limitations are documented safely.

## Phase 98 - Gateway Mode Validation

Status: Complete Baseline

Goal:
Validate gateway-readiness using sanitized local dry-run records from telemetry enrichment, DNS visibility, router logs, SPAN readiness, and topology correlation.

Build:

- `core_engine/gateway/validation.py`
- `core_engine/gateway/operator_views.py`
- `tests/test_gateway_mode_validation.py`
- `docs/gateway_mode_validation.md`

Features:

- Gateway validation summary records.
- Telemetry enrichment validation.
- DNS visibility validation.
- Router log ingestion validation.
- SPAN readiness validation.
- Topology correlation validation.
- Operator safety checklist.
- Export-ready validation summaries.
- Dashboard/API-ready gateway validation dictionaries.

Acceptance:

- Validation uses sanitized fixtures and local dry-run records.
- No router settings are changed.
- No bridge mode is enabled.
- No automatic service installation.
- No automatic blocking.
- Output clearly separates supported, degraded, unavailable, and unsafe states.

## Cross-Phase Data Flow

```text
enriched flow observations
  -> process and service attribution
  -> DNS visibility and correlation
  -> gateway/router log ingestion
  -> SPAN and mirror-port readiness
  -> gateway mode validation
  -> dashboard/API-ready gateway telemetry summaries
```

The flow is local, explicit, and advisory. No phase enables inline gateway enforcement.

## Milestone P Validation Checklist

- Run `python -m pytest`.
- Run `git diff --check`.
- Review staged diffs before commit.
- Run sensitive-data scans.
- Run artifact/private-file checks.
- Confirm `docs/real_device_validation.md` remains unstaged.
- Confirm no screenshots, log archives, cache files, database files, runtime artifacts, or environment files are staged.
- Confirm all public docs use sanitized placeholders only.
- Confirm dry-run remains default.
- Confirm existing CLI/TUI behavior is preserved.

## macOS Validation Checklist

Use sanitized records and temporary local test paths only.

- Build enriched flow summaries from sanitized packet and flow fixtures.
- Build process and service attribution summaries from sanitized socket/process fixtures.
- Build DNS visibility records from sanitized DNS metadata fixtures.
- Parse sanitized gateway/router log examples from local test strings.
- Build SPAN/mirror-port readiness profiles without changing interface state.
- Build gateway validation summaries from dry-run records.
- Confirm no packet payloads, credentials, private paths, screenshots, runtime logs, or raw validation artifacts are staged.

## Raspberry Pi Validation Checklist

Use sanitized low-volume records and temporary local test paths only.

- Run focused Milestone P tests on the target device.
- Build small rolling flow summaries with bounded record counts.
- Build degraded process attribution summaries for permission-limited environments.
- Build DNS visibility summaries with low record counts.
- Parse a small sanitized router log fixture.
- Build SPAN readiness with Raspberry Pi resource warnings.
- Build gateway validation summaries without bridge mode or service installation.
- Confirm CPU and memory use remain modest.
- Confirm no raw payload bytes are stored or rendered.
- Confirm no private validation notes or runtime artifacts are staged.

## Documentation Notes

Milestone P is not full inline gateway enforcement. It prepares the data-quality layer and readiness checks for future gateway deployment. Full bridge/router intermediary operation should remain a later milestone after telemetry enrichment and readiness validation are stable.

## Do Not Build In This Milestone

- Inline packet modification.
- MITM behavior.
- Traffic injection.
- Automatic blocking or enforcement.
- Router configuration modification.
- Bridge mode enablement.
- Credential capture.
- Traffic decryption.
- Hidden monitoring.
- Automatic service installation or startup.
- External telemetry transmission.
- Public docs containing real validation artifacts.
