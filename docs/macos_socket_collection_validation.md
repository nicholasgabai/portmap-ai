# macOS Socket Collection Validation

This document records the Milestone V runtime validation blocker found on macOS and the platform-specific scanner behavior added to resolve it.

The issue was upstream of Milestone V: the runtime bridge worked when socket observations were present, but the macOS worker sometimes reported no connections and sent heartbeat-only payloads. Raspberry Pi/Linux ARM returned live socket observations in the same Milestone V bridge path.

## Root Cause

On macOS, the primary psutil socket inventory call can fail with an operating-system permission error when the process is not allowed to enumerate system-wide sockets. The error can appear as `AccessDenied`, `PermissionError`, `Operation not permitted`, or a wrapped exception whose class name or message indicates access denial. The previous scanner path caught that exception and returned an empty live list, which made the worker log:

```text
No connections found - sending heartbeat only.
```

That empty result prevented live TCP, UDP, SSH, SCP, HTTPS, and DNS-like socket observations from reaching worker payloads, master normalization, Milestone V flow reconstruction, topology edges, attribution summaries, and TUI flow panels.

## Runtime Fix

The scanner now exposes `basic_scan_with_diagnostics()`.

The live/default macOS path is:

```text
psutil socket inventory
  -> if AccessDenied, PermissionError, Operation not permitted, or empty on macOS
  -> non-privileged lsof socket inventory fallback
  -> scanner normalization
  -> bounded worker payload
  -> Milestone V runtime bridge
```

The fallback is live-only. Fixture and simulated modes still use deterministic fixture behavior, including the existing demo labels only when explicitly requested.

## Diagnostics

Worker logs now include safe scanner diagnostics when socket collection returns no observations. Diagnostic fields include:

- platform family
- primary backend
- primary raw count
- primary error type
- permission-blocked flag
- fallback backend
- fallback attempted/available/used flags
- fallback raw count
- candidate count
- normalized count
- result state

Diagnostics do not log raw endpoints, packet payloads, credentials, hostnames, usernames, MAC addresses, private paths, certificates, keys, screenshots, or runtime artifacts.

## Validation Expectations

Use operator-approved local traffic only.

- Confirm macOS can expose socket metadata without sudo using `lsof -nP -iTCP`.
- A macOS system with active SSH or SCP sessions should produce TCP socket observations when visible to the OS.
- A macOS system with active HTTPS sessions should produce TCP socket observations when visible to the OS.
- DNS-like UDP socket observations can appear when visible at scan time.
- Very short-lived traffic may still be missed between scan intervals.
- ICMP ping is not expected to appear in socket-only mode.
- No sudo/admin request is made.
- No packet capture is started.
- No firewall, router, service, or host configuration is changed.

## Safety Guarantees

- No packet payload inspection.
- No raw packet storage.
- No PCAP generation.
- No credential collection.
- No automatic enforcement.
- No privilege escalation.
- No service installation.
- No firewall modification.
- Metadata-only and advisory-first.
