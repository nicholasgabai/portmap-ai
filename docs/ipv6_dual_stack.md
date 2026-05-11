# IPv6 And Dual-Stack Scanning

Phase 20 adds target parsing and dual-stack TCP probe support without changing the default local socket inventory behavior.

## Modules

- `core_engine.modules.ip_utils` validates IPv4, IPv6, hostname, and CIDR targets.
- `core_engine.modules.ipv6_scanner` runs conservative TCP `connect_ex` probes against IPv4 and IPv6 targets.

## Target Handling

Supported target forms:

- IPv4 literal: `127.0.0.1`
- IPv6 literal: `::1`
- Bracketed IPv6 literal: `[::1]`
- CIDR: `<LAN_CIDR>` or `fd00::/126`
- Hostname: resolved through the OS resolver when enabled by the scanner

Malformed targets are rejected before scanning. CIDR expansion is capped by a safe target limit.

## Safe Defaults

The active TCP scanner uses:

- one second timeout;
- maximum target count;
- maximum port count;
- small rate delay between probes;
- explicit `--aggressive` opt-in for larger scans.

This phase does not add SYN scanning, raw packets, packet capture, or remediation.

## CLI Usage

Default local socket inventory remains unchanged:

```bash
portmap scan --output json
```

Active dual-stack scan:

```bash
portmap scan --target ::1 --ports 80,443 --ip-version 6 --output json
```

Active IPv4 scan:

```bash
portmap scan --target 127.0.0.1 --ports 22,80,443 --ip-version 4 --output json
```

CIDR scans are supported but capped:

```bash
portmap scan --target <LAN_CIDR> --ports 80 --output json
```

## Result Shape

Rows follow the scanner output style and remain JSON serializable:

```json
{
  "program": "-",
  "pid": 0,
  "port": 443,
  "service_name": "HTTPS",
  "protocol": "TCP",
  "status": "OPEN",
  "tcp_state": "open",
  "direction": "outgoing",
  "local": "-",
  "remote": "[::1]:443",
  "target": "::1",
  "ip_version": 6,
  "target_source": "literal",
  "reason": "connect_success"
}
```
