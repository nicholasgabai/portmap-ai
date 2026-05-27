# Phase 99-104 Cross-Platform Runtime Hardening Plan

Milestone Q defines the next implementation milestone for making PortMap-AI reliably testable and operable across macOS, Linux/Raspberry Pi, and Windows before deeper behavioral intelligence and commercial packaging. The focus is platform detection, Windows compatibility, packet-capture readiness, firewall-provider previews, filesystem/export safety, and unified cross-platform validation summaries.

This is a planning document only. It does not implement runtime behavior, start services, install components, change firewall rules, enable packet capture, elevate privileges, modify host networking, contact external systems, or transmit data outside the local operator environment.

## Milestone Q: Cross-Platform Runtime Hardening

Goal:
Make PortMap-AI reliably testable and operable across macOS, Linux/Raspberry Pi, and Windows while preserving the current local-first, dry-run-first, operator-controlled, advisory-by-default posture.

Milestone Q should connect existing runtime profiles, runtime health, service-mode readiness, packet-capture planning, process/service attribution, gateway readiness, export safety, CLI output, dashboard providers, and local API-compatible dictionaries into cross-platform compatibility records.

All work should remain:

- local-first
- dry-run by default
- operator-controlled
- advisory by default
- metadata-only by default
- resource-conscious
- macOS testable
- Linux/Raspberry Pi compatible
- Windows compatibility-oriented
- safe for public GitHub documentation
- testable with sanitized fixtures

## Current Starting Point

Implemented foundation available before Phase 99:

- Runtime session, profile, recovery, CLI, health, and service-mode readiness records.
- Passive interface discovery and dry-run capture planning.
- Packet metadata windows, flow reconstruction, protocol metadata, live topology, and telemetry dashboard/API summaries.
- Flow enrichment, process/service attribution, DNS visibility, gateway/router log ingestion, SPAN readiness, and gateway mode validation.
- Local storage, operational export bundles, dashboard providers, local API dictionaries, and federation-safe summaries.
- Platform utility helpers and packaging tests.

Milestone Q should harden cross-platform readiness without enabling automatic firewall changes, service installation, packet capture escalation, packet payload retention, or privileged background behavior.

## Phase 99 - Cross-Platform Runtime Detection

Status: Complete Baseline

Goal:
Create deterministic platform detection and capability summaries for macOS, Linux/Raspberry Pi, and Windows runtime workflows.

Build:

- `core_engine/platform/runtime_detection.py`
- `core_engine/platform/capabilities.py`
- `tests/test_cross_platform_runtime_detection.py`
- `docs/cross_platform_runtime_detection.md`

Features:

- Platform detection helpers.
- OS family and version summary records.
- Architecture and Python runtime summaries.
- Admin/root permission detection.
- Container and virtualized environment hints.
- Supported/degraded/unavailable state records.
- Runtime profile compatibility hints.
- Dashboard/API-ready platform capability dictionaries.

Acceptance:

- Detection can run from sanitized fixtures and local platform data.
- Permission state is summarized without attempting elevation.
- Unsupported or unknown platforms produce degraded or unavailable records.
- Outputs include safety fields and no private host identifiers.
- Tests are deterministic across fixture inputs.

## Phase 100 - Windows Runtime Compatibility

Status: Complete Baseline

Goal:
Add Windows compatibility helpers for paths, process/socket visibility fallbacks, runtime profile defaults, and service-mode preview behavior.

Build:

- `core_engine/platform/windows_runtime.py`
- `core_engine/platform/windows_paths.py`
- `tests/test_windows_runtime_compatibility.py`
- `docs/windows_runtime_compatibility.md`

Features:

- Windows path handling.
- Windows-safe runtime profile defaults.
- Windows process/socket visibility fallback summaries.
- Permission-denied and unsupported-feature degraded states.
- Windows service-mode readiness preview only.
- PowerShell and service command preview records with placeholders.
- Export path and cache path compatibility hints.
- Dashboard/API-ready Windows compatibility dictionaries.

Acceptance:

- Windows compatibility records build from sanitized fixtures on non-Windows hosts.
- Path summaries do not expose real usernames or local paths.
- Process/socket fallbacks do not attempt privilege escalation.
- Service-mode support remains preview-only and does not install or start services.
- Existing macOS/Linux behavior is not regressed.

## Phase 101 - Cross-Platform Packet Capture Readiness

Status: Complete Baseline

Goal:
Summarize packet-capture readiness across macOS, Linux/Raspberry Pi, and Windows without changing interface modes or escalating privileges.

Build:

- `core_engine/platform/capture_readiness.py`
- `core_engine/platform/capture_backends.py`
- `tests/test_cross_platform_packet_capture_readiness.py`
- `docs/cross_platform_packet_capture_readiness.md`

Features:

- macOS capture capability summaries.
- Linux and Raspberry Pi capture capability summaries.
- Windows capture capability summaries.
- Npcap/WinPcap readiness detection for Windows.
- BPF/libpcap/scapy readiness summaries.
- Interface permission requirement summaries.
- Capture degraded/unavailable state records.
- Integration with passive capture and SPAN readiness records.
- Dashboard/API-ready capture readiness dictionaries.

Acceptance:

- Readiness checks are dry-run only.
- No capture mode changes are performed.
- No privileged capture loop or escalation attempt is started.
- Missing providers produce clear degraded or unavailable states.
- Raspberry Pi resource limits are documented safely.

## Phase 102 - Cross-Platform Firewall Provider Readiness

Status: Complete Baseline

Goal:
Add dry-run firewall provider readiness previews for Windows, macOS, and Linux without applying rules or enabling enforcement.

Build:

- `core_engine/platform/firewall_readiness.py`
- `core_engine/platform/firewall_providers.py`
- `tests/test_cross_platform_firewall_provider_readiness.py`
- `docs/cross_platform_firewall_provider_readiness.md`

Features:

- Windows Defender Firewall preview provider.
- macOS `pf` preview provider.
- Linux `nftables`, `ufw`, and `iptables` preview providers.
- Provider availability summaries.
- Dry-run rule preview records.
- Unsupported/degraded/unavailable provider states.
- Operator safety checklist records.
- Integration hooks for remediation safety and gateway validation.
- Dashboard/API-ready firewall readiness dictionaries.

Acceptance:

- Providers generate previews only.
- No firewall rules are created, modified, enabled, or deleted.
- Missing commands or unsupported platforms are reported safely.
- Preview examples use sanitized placeholders only.
- Automatic blocking remains disabled.

## Phase 103 - Cross-Platform Filesystem and Export Safety

Status: Complete Baseline

Goal:
Add filesystem and export safety helpers for platform-specific path normalization, safe output locations, and artifact exclusion checks.

Build:

- `core_engine/platform/filesystem_safety.py`
- `core_engine/platform/export_paths.py`
- `tests/test_cross_platform_filesystem_export_safety.py`
- `docs/cross_platform_filesystem_export_safety.md`

Features:

- Safe log path summaries.
- Safe export path summaries.
- OS-specific path normalization.
- Placeholder path rendering for public docs.
- Artifact exclusion validation.
- Runtime log, screenshot, archive, cache, database, and environment-file detection.
- Export bundle path compatibility hints.
- Dashboard/API-ready filesystem safety dictionaries.

Acceptance:

- Path records are deterministic for sanitized fixtures.
- Public outputs do not include real usernames, hostnames, private local paths, tokens, or secrets.
- Artifact exclusion detects unsafe staged or export candidate files.
- Export paths remain operator-provided and local-only.
- No files are deleted, moved, or transmitted by safety checks.

## Phase 104 - Cross-Platform Validation Summary

Goal:
Build a unified cross-platform validation report for macOS, Linux/Raspberry Pi, and Windows compatibility.

Build:

- `core_engine/platform/validation.py`
- `cli/platform.py`
- Updates to `cli/main.py`
- `tests/test_cross_platform_validation_summary.py`
- `docs/cross_platform_validation_summary.md`

Features:

- Unified validation report for macOS, Linux/Raspberry Pi, and Windows.
- Aggregated supported/degraded/unavailable state summaries.
- Runtime profile validation rollups.
- Packet capture readiness rollups.
- Firewall provider readiness rollups.
- Filesystem/export safety rollups.
- CLI table and JSON output.
- Dashboard/API-ready compatibility summaries.
- Operator-readable recommendation records.

Acceptance:

- Validation reports are deterministic for sanitized fixtures.
- CLI output supports table and JSON modes.
- Dashboard/API dictionaries remain local and read-only.
- No services are installed or started.
- No firewall changes, packet capture escalation, or raw payload storage is added.
- Existing CLI/TUI behavior remains compatible.

## Cross-Phase Data Flow

```text
local platform metadata and sanitized fixtures
  -> runtime detection and capability summaries
  -> Windows compatibility and fallback records
  -> packet capture readiness summaries
  -> firewall provider preview summaries
  -> filesystem and export safety summaries
  -> unified cross-platform validation report
  -> CLI, dashboard, API, and export-ready compatibility records
```

No step should add automatic firewall changes, service installation, packet capture escalation, bridge mode, raw payload storage, hidden monitoring, router/switch changes, public internet exposure, or external telemetry transmission.

## Validation Checklist

For each implementation phase:

- Run the full test suite.
- Run whitespace and patch validation.
- Run sensitive-data checks against staged public files.
- Run artifact/private-file checks.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and explicitly approved.
- Confirm no real IP addresses, MAC addresses, hostnames, usernames, tokens, local paths, runtime logs, screenshots, archives, database files, cache files, environment files, or private validation notes are staged.
- Confirm dry-run remains default.
- Confirm existing CLI/TUI behavior is preserved.
- Confirm public examples use sanitized placeholders only.

## macOS Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Build local platform detection summaries.
- Build admin/root permission summaries without attempting elevation.
- Build packet capture readiness summaries for available local providers.
- Build macOS firewall preview records without changing `pf`.
- Build filesystem/export safety summaries from temporary paths.
- Run cross-platform validation CLI in table and JSON modes.
- Confirm no service installation, firewall change, packet capture loop, or external network call is required.
- Confirm no private hostnames, usernames, local paths, logs, screenshots, database files, cache files, archives, tokens, or private validation notes are staged.

## Linux / Raspberry Pi Validation Checklist

Use sanitized records and temporary local test locations only.

- Build Linux and Raspberry Pi capability summaries.
- Build root/admin permission summaries without attempting privilege escalation.
- Build packet capture readiness summaries with edge-device resource thresholds.
- Build Linux firewall preview records for available provider fixtures.
- Build filesystem/export safety summaries with Linux-style placeholder paths.
- Run cross-platform validation summary with Raspberry Pi resource settings.
- Confirm CPU and memory use remain modest.
- Confirm no firewall rules are changed and no services are installed or started.
- Confirm no raw payload bytes are stored or rendered.
- Confirm no private identifiers, logs, screenshots, database files, cache files, environment files, archives, runtime artifacts, credentials, tokens, or private validation notes are staged.

## Windows Validation Checklist

Use sanitized fixtures and temporary local paths only.

- Build Windows runtime compatibility summaries from fixture data.
- Build Windows path normalization summaries using placeholder paths.
- Build Windows process/socket visibility fallback records.
- Build Windows service-mode preview records only.
- Build Npcap/WinPcap readiness summaries from fixture availability records.
- Build Windows Defender Firewall preview records without applying rules.
- Run cross-platform validation summary in JSON mode from sanitized fixtures.
- Confirm no services are installed or started.
- Confirm no firewall rules are changed.
- Confirm no packet capture escalation is attempted.
- Confirm no private usernames, hostnames, local paths, logs, screenshots, registry exports, tokens, credentials, or private validation notes are staged.

## Documentation Requirements

Each phase should add focused documentation:

- `docs/cross_platform_runtime_detection.md`
- `docs/windows_runtime_compatibility.md`
- `docs/cross_platform_packet_capture_readiness.md`
- `docs/cross_platform_firewall_provider_readiness.md`
- `docs/cross_platform_filesystem_export_safety.md`
- `docs/cross_platform_validation_summary.md`

Docs must use sanitized placeholders only.

## Do Not Build In This Milestone

- Automatic firewall changes.
- Service installation or startup.
- Packet capture privilege escalation.
- Packet capture mode changes.
- Bridge mode.
- Raw payload storage.
- Credential capture.
- Router or switch modification.
- Hosted SaaS.
- Public internet exposure.
- External telemetry transmission.
- Replacement of the existing Textual terminal dashboard.
