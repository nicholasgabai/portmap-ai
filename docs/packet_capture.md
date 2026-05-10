# Packet Capture Core

Phase 25 adds a safe packet-capture foundation for local operator visibility. It is designed for authorized managed environments and keeps payload handling conservative: metadata is extracted for display and analysis, while full packet bytes are only written when the operator explicitly requests a PCAP file.

## Scope

The capture core provides:

- Interface discovery and default interface selection.
- Live packet capture where the platform exposes a supported backend.
- Packet metadata extraction for Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, and ARP labels.
- Simple capture filters for protocol, host, and port selection.
- Classic PCAP file writing with a stdlib-only writer.
- Graceful results for missing permissions or unsupported live-capture backends.

This phase follows the global PortMap-AI safety guarantees.

## CLI Usage

Capture metadata from the default detected interface:

```bash
portmap capture --duration 5 --max-packets 100 --output json
```

Capture only TCP packet metadata on a specific interface:

```bash
portmap capture --interface en0 --filter tcp --duration 10 --max-packets 200 --output json
```

Save filtered packets to a PCAP file:

```bash
portmap capture --interface en0 --filter "port 443" --pcap ./artifacts/https.pcap --output json
```

On macOS and Windows, the stdlib live-capture backend reports `unsupported_capture_backend` unless a future backend is added. On Linux, AF_PACKET capture usually requires elevated privileges or packet-capture capabilities; missing permission is reported as `permission_denied` with exit code `0` so automation can treat it as an expected runtime capability result.

## Filters

Supported filters are intentionally small and predictable:

- `tcp`, `udp`, `icmp`, `arp`
- `ip`, `ipv6`
- `host <ip>`
- `src host <ip>` and `dst host <ip>`
- `port <number>`
- `src port <number>` and `dst port <number>`

Unsupported filter syntax returns a validation error instead of being passed to a shell command or platform tool.

## Metadata Fields

Packet metadata rows are JSON serializable and may include:

- `timestamp`
- `interface`
- `captured_len` and `original_len`
- `src_mac` and `dst_mac`
- `ethertype`
- `ip_version`
- `src_ip` and `dst_ip`
- `protocol` and `protocol_number`
- `ttl` or `hop_limit`
- `src_port` and `dst_port`
- `tcp_flags`, `tcp_window`, `udp_length`, `icmp_type`, or `icmp_code`
- `payload_bytes`

Payload bytes are not included in metadata rows. When `--pcap` is supplied, matching packet bytes are written to the requested PCAP path for operator-controlled offline analysis.

## Developer Notes

The main module is `core_engine.modules.packet_capture`. Tests inject packet sources so permission-sensitive behavior remains deterministic. The PCAP writer lives in `core_engine.modules.pcap_writer` and writes classic Ethernet-linktype PCAP files without external dependencies.

Future protocol dissection and DPI phases should consume metadata from this layer and keep payload retention explicit and redacted by default.
