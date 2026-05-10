# UDP Scanning

Phase 19 adds an isolated UDP scanner in `core_engine.modules.udp_scanner`.

The UDP scanner is intentionally conservative. UDP does not have a TCP-style handshake, so many ports cannot be proven open without a protocol response or privileged ICMP inspection. PortMap-AI classifies results as:

- `open`: the target returned UDP payload data.
- `closed`: the OS surfaced an ICMP-style unreachable or connection-refused error.
- `filtered`: the probe timed out after the configured retry count.
- `unknown`: the scan could not classify the result, usually because of permissions or an unexpected socket error.

## Safe Defaults

Default behavior is scoped and rate-limited:

- common UDP service ports only unless ports are supplied;
- one retry;
- one second timeout;
- small delay between probes;
- maximum port count unless `aggressive=True` is explicitly used through the Python API.

This phase follows the global PortMap-AI safety guarantees.

## Common Probes

Built-in probes cover:

- DNS `53`
- DHCP `67` and `68`
- NTP `123`
- SNMP `161`
- NetBIOS `137` and `138`
- mDNS `5353`

## Python Usage

```python
from core_engine.modules.udp_scanner import scan_udp_target

rows = scan_udp_target("127.0.0.1", ports=[53, 123, 161])
```

Rows follow the existing scanner output style and remain JSON serializable:

```json
{
  "program": "-",
  "pid": 0,
  "port": 53,
  "service_name": "DNS",
  "protocol": "UDP",
  "status": "FILTERED",
  "udp_state": "filtered",
  "direction": "outgoing",
  "local": "-",
  "remote": "127.0.0.1:53",
  "target": "127.0.0.1",
  "probe": "DNS",
  "attempts": 2,
  "reason": "timeout",
  "response_bytes": 0
}
```

## CLI Usage

The unified CLI can run UDP probes without changing the existing TCP/local socket scan:

```bash
portmap scan --udp-target 127.0.0.1 --udp-ports 53,123,161 --output json
```

Without `--udp-target`, `portmap scan` keeps the existing local socket inventory behavior.
