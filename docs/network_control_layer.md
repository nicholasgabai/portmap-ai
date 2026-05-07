# Network Control Layer

Phase 14 adds advisory router/gateway awareness and local exposure assessment. It does not change router settings, firewall rules, NAT, port forwards, or host network configuration.

## Command

```bash
portmap network
portmap network --output json
```

The command reports:

- default gateway/router IP when detectable;
- gateway interface;
- local IPv4 networks;
- non-loopback listening services from the local scanner;
- exposed-service recommendations;
- advisory-only safety notes.

## Safety Boundary

The network control layer is intentionally read-only:

- no router login attempts;
- no UPnP/NAT-PMP changes;
- no firewall modifications;
- no port-forward changes;
- no LAN-wide scanning by default.

Future LAN scanning must be explicit, scoped, rate-limited, and documented before it is enabled.

## Exposure Model

Listening services are categorized by bind address:

- `loopback_only`: ignored for exposure recommendations.
- `lan_interface`: bound to a private LAN IP.
- `all_interfaces`: bound to `0.0.0.0`, `::`, or equivalent.
- `public_interface`: bound to a public address.
- `unknown`: address could not be classified.

Risky-port metadata is reused from `core_engine.risky_ports` so exposed services on known sensitive ports receive stronger review recommendations.

## Platform Support

Gateway detection uses platform-native read-only commands when present:

- Linux: `ip route show default`
- macOS: `route -n get default`
- Windows: `route print 0.0.0.0`

If gateway detection is unavailable, posture assessment still reports local interfaces, exposed services, and recommendations.

## Output Contract

JSON output includes:

```json
{
  "advisory_only": true,
  "automatic_changes": false,
  "gateway": {},
  "local_networks": [],
  "exposed_services": [],
  "recommendations": [],
  "safety_notes": []
}
```

Operators should treat recommendations as review guidance. Active remediation remains governed by the remediation safety layer and explicit confirmation policy.
