# Network Asset Inventory

Phase 21 adds a conservative inventory layer for authorized networks. It is designed to improve visibility into managed infrastructure. This phase follows the global PortMap-AI safety guarantees.

## Scope

The inventory engine lives in `core_engine.modules.discovery` and focuses on:

- administrator-defined IPs, hostnames, and CIDR ranges
- detected local private networks when explicitly requested or when no range is supplied to the CLI
- ARP/neighbor table evidence from the local host
- optional platform `ping` reachability checks
- TCP transport availability checks using normal socket connects
- local topology context such as gateway, local networks, and broadcast candidates
- orchestrator-ready telemetry events

## CLI Usage

Inventory an authorized CIDR range:

```bash
portmap discover --range 192.168.1.0/24 --output json
```

Inventory the detected local networks with default safe limits:

```bash
portmap discover --output json
```

Combine methods and customize transport checks:

```bash
portmap discover \
  --range 192.168.1.0/24 \
  --method arp \
  --method tcp \
  --tcp-ports 22,80,443,8080 \
  --output json
```

Include topology context:

```bash
portmap discover --range 192.168.1.0/24 --topology --output json
```

## Safety Defaults

The default target expansion limit is 256 assets. Larger inventory jobs require `--aggressive`, and should only be used on networks where the operator has explicit authorization.

Default methods are ARP inventory plus TCP availability checks. `ping` is available as an opt-in method:

```bash
portmap discover --range 10.0.0.0/24 --method ping --method tcp
```

This phase follows the global PortMap-AI safety guarantees.

## Result Shape

Each asset row is JSON serializable:

```json
{
  "asset_type": "network_asset",
  "host": "192.168.1.10",
  "ip_version": 4,
  "status": "reachable",
  "target_source": "cidr",
  "private": true,
  "loopback": false,
  "methods": ["arp", "tcp"],
  "evidence": [
    {
      "method": "arp",
      "reachable": true,
      "mac": "aa:bb:cc:dd:ee:ff",
      "interface": "en0",
      "reason": "arp_table_entry"
    }
  ],
  "mac": "aa:bb:cc:dd:ee:ff",
  "interface": "en0",
  "open_ports": [443],
  "closed_ports": [22, 80]
}
```

Statuses are:

- `reachable`: ARP, ping, or TCP evidence indicates the device is present.
- `unreachable`: active reachability checks completed with negative evidence.
- `unknown`: no positive or negative evidence was available.

## Orchestrator Telemetry

`asset_telemetry_events()` converts inventory rows into telemetry payloads:

```json
{
  "type": "asset_inventory",
  "source": "portmap.asset_inventory",
  "target": "192.168.1.10",
  "node_id": "worker-001",
  "asset": {
    "asset_type": "network_asset",
    "host": "192.168.1.10"
  }
}
```

This keeps the result format ready for a future orchestrator ingestion endpoint without coupling Phase 21 to SaaS, GUI, or remediation behavior.
