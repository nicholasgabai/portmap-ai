# Milestone Q Integration

Milestone Q covers Phases 99-104: Cross-Platform Runtime Hardening. It makes PortMap-AI reliably testable and operable across macOS, Linux, Raspberry Pi/Linux ARM, Windows, and unknown platforms before deeper behavioral intelligence, installer work, and commercial packaging.

This milestone remains local-first, operator-controlled, dry-run by default, advisory by default, metadata-only by default, and safe for public documentation. It does not install services, modify firewall rules, enable packet capture, change interface modes, request elevation, store raw payloads, or write outside operator-controlled locations.

## Completed Phases

| Phase | Area | Implemented Baseline |
| --- | --- | --- |
| 99 | Cross-platform runtime detection | OS/runtime detection helpers, platform family records for macOS, Linux, Raspberry Pi/Linux ARM, Windows, and unknown systems, architecture and Python summaries, permission detection, capability placeholders, and dashboard/API-ready compatibility dictionaries. |
| 100 | Windows runtime compatibility | Windows-safe path normalization, log/export/cache path summaries, process/socket visibility capability records, elevation summaries, service-mode readiness preview records, runtime profile defaults, degraded fallback records, and dashboard/API-ready dictionaries. |
| 101 | Cross-platform packet capture readiness | macOS BPF/libpcap, Linux libpcap/AF_PACKET/scapy, Raspberry Pi, and Windows Npcap/WinPcap readiness summaries, permission requirement records, backend state models, passive capture safety warnings, raw-payload prohibition fields, and dashboard/API-ready dictionaries. |
| 102 | Cross-platform firewall provider readiness | Windows Defender Firewall, macOS pf, Linux nftables/ufw/iptables, and Raspberry Pi firewall preview provider summaries, dry-run rule preview records, permission requirements, provider state records, safety warnings, review flags, and dashboard/API-ready dictionaries. |
| 103 | Cross-platform filesystem and export safety | Safe log, export, and cache path summaries, OS-specific path normalization, artifact exclusion validators, private-file warnings, runtime artifact classification, public-doc safety checks, and dashboard/API-ready dictionaries. |
| 104 | Cross-platform validation summary | Unified macOS, Linux, Raspberry Pi/Linux ARM, and Windows validation summaries with capture readiness, firewall readiness, filesystem/export safety, aggregate states, operator recommendations, and CLI/table/JSON/dashboard/API-ready output. |

## Module Map

| Layer | Modules | Role |
| --- | --- | --- |
| Runtime detection | `core_engine.platform.runtime_detection`, `core_engine.platform.capabilities` | Normalize platform family, architecture, Python version, permission state, and capability placeholders for runtime, capture, firewall, service, path, and export layers. |
| Windows compatibility | `core_engine.platform.windows_runtime`, `core_engine.platform.windows_paths` | Provide Windows-safe path, process/socket visibility, permission, service-preview, runtime profile, fallback, and dashboard/API summaries without changing host state. |
| Capture readiness | `core_engine.platform.capture_readiness`, `core_engine.platform.capture_backends` | Summarize passive capture backend availability, permission needs, platform-specific degraded states, and raw-payload safety boundaries without starting capture loops. |
| Firewall readiness | `core_engine.platform.firewall_readiness`, `core_engine.platform.firewall_providers` | Build dry-run firewall provider previews and operator review records for Windows, macOS, Linux, and Raspberry Pi without applying rules. |
| Filesystem and export safety | `core_engine.platform.filesystem_safety`, `core_engine.platform.export_paths` | Classify safe paths, private files, runtime artifacts, export targets, and public documentation safety for cross-platform workflows. |
| Validation summaries | `core_engine.platform.validation_summary`, `core_engine.platform.operator_views` | Aggregate platform, capture, firewall, filesystem, export, gateway, service, and runtime health records into CLI/table/JSON and dashboard/API-ready compatibility summaries. |

## Integrated Data Flow

```text
runtime and platform detection records
  -> Windows, macOS, Linux, Raspberry Pi, and unknown compatibility summaries
  -> packet capture and firewall provider readiness previews
  -> filesystem and export safety checks
  -> unified cross-platform validation summary
  -> CLI/table/JSON, dashboard, and API-ready operator records
```

The flow is read-only and dry-run by default. It reports platform capability, degraded state, unavailable state, safety warnings, and operator recommendations without changing the host.

## Connections To Platform Layers

Runtime health:
Milestone Q feeds runtime health with platform capability, permission, filesystem, capture, firewall, service-preview, and aggregate validation states so operators can distinguish supported, degraded, unavailable, and unknown environments.

Telemetry readiness:
Packet capture readiness connects to passive interface discovery, live packet ingestion planning, SPAN/mirror-port readiness, and gateway validation. It reports backend availability and permission needs without enabling capture or changing interface modes.

Gateway readiness:
Firewall preview records, packet capture readiness, filesystem safety, and validation summaries provide platform context for gateway mode validation. They keep gateway readiness dry-run and advisory.

Service mode readiness:
Runtime detection and Windows compatibility records extend service-mode previews across supported platforms. The summaries do not install, enable, start, stop, or modify services.

Export safety:
Filesystem safety and export path helpers validate path shape, artifact exclusions, private-file warnings, and runtime artifact classifications before operator-controlled export workflows.

Windows, macOS, Linux, and Raspberry Pi compatibility:
Milestone Q normalizes per-platform capability checks into a single validation surface. Platform-specific limitations are surfaced as degraded, unavailable, unsafe, or unknown states instead of being hidden or treated as hard failures.

## Safety Boundaries

Milestone Q does not add:

- service installation or service control
- firewall rule changes
- packet capture loops
- promiscuous mode changes
- interface mode changes
- admin, root, or elevation requests
- registry writes
- packet payload storage
- automatic blocking or enforcement
- external telemetry transmission
- committed runtime logs, screenshots, private paths, database files, cache files, or private validation notes

## macOS Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Run the full test suite in the repo-local environment.
- Build a macOS runtime detection summary from fixture inputs.
- Build BPF/libpcap capture readiness summaries without starting capture.
- Build macOS pf firewall preview summaries without applying rules.
- Build safe log, cache, and export path summaries with placeholder paths.
- Build a unified validation summary with supported, degraded, unavailable, and unknown states.
- Confirm no service install, firewall modification, capture loop, interface mode change, elevation request, or external transmission occurs.
- Confirm no real hostnames, usernames, local paths, logs, screenshots, archives, database files, cache files, runtime artifacts, tokens, credentials, or private validation notes are staged.

## Raspberry Pi/Linux ARM Validation Checklist

Use sanitized records and temporary local test locations only.

- Run focused cross-platform runtime tests on the target device.
- Build Raspberry Pi/Linux ARM runtime and architecture summaries.
- Build passive capture readiness summaries with Raspberry Pi resource warnings.
- Build Linux firewall provider previews for nftables, ufw, and iptables without rule changes.
- Build filesystem/export safety summaries using temporary paths only.
- Build a unified validation summary with Raspberry Pi resource recommendations.
- Confirm CPU and memory use remain modest.
- Confirm no service install, firewall modification, capture loop, promiscuous mode change, elevation request, or external network call is required.
- Confirm no raw payload bytes, private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime artifacts, credentials, tokens, or private validation notes are staged.

## Linux Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Build Linux runtime detection and capability summaries.
- Build libpcap, AF_PACKET, and scapy readiness records without starting capture.
- Build nftables, ufw, and iptables dry-run firewall provider previews.
- Build service-mode compatibility summaries without installing or starting services.
- Build safe filesystem/export path summaries and artifact exclusion records.
- Build CLI/table/JSON-ready validation output from fixture records.
- Confirm no root escalation, firewall rule change, service modification, packet capture loop, payload storage, or external telemetry transmission occurs.
- Confirm no real hostnames, usernames, IP addresses, MAC addresses, local paths, logs, screenshots, archives, database files, cache files, runtime artifacts, tokens, credentials, or private validation notes are staged.

## Windows Validation Checklist

Use sanitized fixtures and placeholder paths only.

- Build Windows runtime compatibility records from fixture inputs.
- Build Windows-safe log, cache, and export path summaries with placeholder drive paths.
- Build process/socket visibility degraded and unsupported fallback records.
- Build Npcap/WinPcap readiness summaries without assuming installation.
- Build Windows Defender Firewall dry-run preview summaries without applying rules.
- Build service-mode readiness preview records without installing or controlling services.
- Build unified validation output with supported, degraded, unavailable, and unknown states.
- Confirm no service install, service control, firewall modification, registry write, elevation request, packet capture loop, payload storage, or external transmission occurs.
- Confirm no real hostnames, usernames, IP addresses, MAC addresses, local paths, logs, screenshots, archives, database files, cache files, runtime artifacts, tokens, credentials, or private validation notes are staged.

## Next Direction

Recommended next direction: move from cross-platform runtime hardening into installer, service, and release packaging work.

Suggested areas:

- Operator-approved Linux service installation and rollback records.
- macOS launch agent template support.
- Windows service template support and install previews.
- Repeatable release build pipelines with checksums and dependency manifests.
- Upgrade, rollback, backup, and uninstall validation across supported platforms.
