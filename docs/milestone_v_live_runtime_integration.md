# Milestone V Live Runtime Integration

This document describes the pre-Milestone W runtime bridge that connects current worker socket snapshots to Milestone V flow, correlation, attribution, drift, and topology intelligence summaries.

The bridge is metadata-only and advisory-first. It does not inspect packet payloads, store raw packets, generate PCAP files, enable privileged packet capture, modify firewall rules, create enforcement actions, or create threat verdicts.

## Runtime Path

The live runtime path is:

```text
scanner basic_scan
  -> bounded worker scan snapshot
  -> master worker_telemetry normalization
  -> Milestone V runtime bridge
  -> reconstructed sessions and flow summaries
  -> metadata and process/service correlations
  -> cross-node relationships
  -> application attribution candidates
  -> drift and topology intelligence summaries
  -> TUI, dashboard/API, and export-safe operator summaries
```

The bridge runs on the current worker payload already received by the master. It keeps live scan snapshots bounded and does not turn current observations into historical storage. Historical behavior remains the responsibility of the baseline, history, and retention modules.

## What Socket Scanning Can See

Socket-only runtime scanning can summarize current observable TCP and UDP socket metadata when the operating system exposes it. Useful rows can include:

- established SSH or SCP-related TCP sessions
- established HTTPS-related TCP sessions
- DNS-related UDP socket observations
- listening services when socket ownership is available
- local, remote, protocol, port, state, process, service, and source-mode metadata

When remote endpoint metadata is available, the TUI Traffic Flows and Topology Edges panels can show bounded flow and edge rows derived from the latest master telemetry events.

## What It Cannot See Yet

Socket-only mode is not packet capture. Expected limitations:

- ICMP ping may not appear because ping is not represented as a normal TCP or UDP socket row on many platforms.
- Very short-lived curl, dig, or nslookup activity may disappear between scan intervals.
- DNS visibility depends on whether the OS exposes a UDP socket observation at scan time.
- Packet payloads, request bodies, DNS payload contents, credentials, and PCAPs are never captured or stored by this bridge.

Future packet capture work must remain separately operator-approved and passive-first.

## Runtime Counters

The master `worker_telemetry` event now includes Milestone V counters:

- `observations_seen`
- `sessions_reconstructed`
- `flows_reconstructed`
- `metadata_correlations`
- `process_correlations`
- `relationship_edges`
- `attribution_candidates`
- `drift_records`
- `topology_records`

Verbose master logs include the same counter names so operators can confirm that live socket rows are moving into the Milestone V bridge.

## TUI Expectations

The TUI reads the master event log and extracts nested `flows` rows from `worker_telemetry` events. Those rows feed the existing flow visualization helper, which builds Traffic Flows and Topology Edges.

Expected behavior:

- Live TCP or UDP observations with remote endpoint metadata can produce Traffic Flows rows.
- Those flow rows can produce Topology Edges rows.
- Repeated identical current observations are deduplicated and should not create duplicate graph edges.
- Unresolved live process/service attribution remains `Unknown` or `Unattributed`.
- `dummy_app` and `dummy_db` remain restricted to explicit fixture or simulated source modes.

## Operator Validation

Use operator-approved local test activity only.

- Start the stack in dry-run/default mode.
- Generate an SSH or SCP session between trusted local nodes.
- Generate an HTTPS request to an operator-approved target.
- Generate a DNS query with a local operator-approved resolver path.
- Open the TUI and check Traffic Flows and Topology Edges.
- Check verbose master output for Milestone V runtime counters.
- Confirm ICMP ping absence is not treated as a failure under socket-only mode.
- Confirm no packet payloads, PCAPs, credentials, firewall changes, or enforcement actions are produced.

Public validation notes must use sanitized placeholders only and must not include real hostnames, IP addresses, usernames, MAC addresses, logs, screenshots, private paths, tokens, certificates, keys, runtime databases, or raw artifacts.
