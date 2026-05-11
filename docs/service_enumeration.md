# Service Enumeration

Phase 22 adds safe service and version detection for authorized targets. The module is intentionally isolated from packet capture, remediation, SaaS logic, and the worker scan loop.

## Scope

The implementation lives in `core_engine.modules.service_detection` and supports:

- TCP banner grabbing
- HTTP and HTTPS `HEAD /` probes
- SMTP `EHLO` probe fallback
- fingerprint matching with confidence scores
- unknown-service handling
- IPv4, IPv6, hostname, and CIDR targets through the Phase 20 IP utilities
- JSON-serializable rows for CLI output and future orchestrator telemetry

Initial common-service support covers:

- SSH
- HTTP
- HTTPS
- FTP
- SMTP
- DNS
- SMB
- RDP

## Fingerprints

The packaged fingerprint database lives at:

```text
core_engine/service_fingerprints.json
```

The loader also checks this roadmap path first when it exists:

```text
data/service_fingerprints.json
```

The local `data/` directory can be runtime-owned or ignored in development, so the packaged file is the reproducible baseline.

## CLI Usage

Enumerate a single authorized target:

```bash
portmap services --target 127.0.0.1 --ports 22,80,443 --output json
```

Enumerate an authorized CIDR range:

```bash
portmap services --target <LAN_CIDR> --ports 22,80,443 --output json
```

Restrict IP version:

```bash
portmap services --target ::1 --ports 80,443 --ip-version 6 --output json
```

## Result Shape

Each row is JSON serializable:

```json
{
  "target": "127.0.0.1",
  "port": 80,
  "remote": "127.0.0.1:80",
  "ip_version": 4,
  "state": "open",
  "service": "HTTP",
  "version": "nginx/1.25",
  "confidence": 0.92,
  "banner": "HTTP/1.1 200 OK",
  "probe": "http_head",
  "evidence": ["banner:HTTP/"],
  "reason": "probe_completed"
}
```

Closed or filtered common-service ports retain lower-confidence port hints so operators can still see useful context without claiming certainty.

## Safety

This phase follows the global PortMap-AI safety guarantees. Aggressive target or port counts require an explicit `--aggressive` flag.
