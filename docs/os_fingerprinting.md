# OS Fingerprinting

Phase 23 adds conservative OS-family inference for authorized targets. It is probabilistic by design and avoids claiming certainty when evidence is weak.

## Scope

The implementation lives in `core_engine.modules.os_fingerprint` and supports:

- passive TTL observations
- passive TCP window-size observations
- passive TCP option markers
- service and banner evidence from Phase 22 service enumeration
- confidence scoring
- candidate explanations
- low-confidence `unknown` results

Initial OS families:

- Windows
- Linux
- macOS
- BSD
- network appliance

## Fingerprints

The packaged fingerprint database lives at:

```text
core_engine/os_fingerprints.json
```

The loader also checks this roadmap path first when it exists:

```text
data/os_fingerprints.json
```

The local `data/` directory can be runtime-owned or ignored in development, so the packaged file is the reproducible baseline.

## CLI Usage

Use safe service evidence from an authorized target:

```bash
portmap os --target 127.0.0.1 --ports 22,80,443 --output json
```

Add passive observations when available:

```bash
portmap os \
  --target <LAN_IP> \
  --ports 22,445,3389 \
  --ttl 127 \
  --tcp-window 64240 \
  --tcp-options mss,sack,wscale \
  --output json
```

Fingerprint a passive observation without active probing:

```bash
portmap os \
  --observation-json '{"target":"host1","ttl":64,"tcp_window":29200,"services":["SSH"],"banners":["OpenSSH Ubuntu"]}' \
  --output json
```

## Result Shape

```json
{
  "target": "<LAN_IP>",
  "probable_os": "Windows",
  "confidence": 0.88,
  "certainty": "high",
  "evidence": [
    "ttl:127 in 65-128",
    "services:RDP,SMB"
  ],
  "candidates": [
    {
      "os_family": "Windows",
      "confidence": 0.88,
      "evidence": ["ttl:127 in 65-128"]
    }
  ],
  "notes": [
    "OS fingerprinting is probabilistic.",
    "Low-confidence results are reported as unknown.",
    "No exploit or credential behavior is performed."
  ]
}
```

## Safety

This phase follows the global PortMap-AI safety guarantees. Active mode reuses Phase 22 service enumeration and keeps target/port limits unless `--aggressive` is explicitly selected.
