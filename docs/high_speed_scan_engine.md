# High-Speed Scan Engine

Phase 24 adds a bounded asynchronous TCP scanning engine for authorized targets. It improves throughput with `asyncio` concurrency and scheduler limits. This phase follows the global PortMap-AI safety guarantees.

## Modules

- `core_engine.modules.scan_scheduler`
  - expands authorized targets and ports
  - validates safe limits
  - builds scan plans
  - tracks concurrency, rate limits, batches, and warnings
  - provides adaptive delay helpers under timeout/error pressure

- `core_engine.modules.async_scanner`
  - runs `asyncio` TCP connect probes
  - classifies ports as `open`, `closed`, `filtered`, or `unknown`
  - emits scanner rows compatible with existing active TCP scan output
  - provides a synchronous wrapper for CLI/service usage

## CLI Usage

Scan an authorized host:

```bash
portmap fast-scan --target 127.0.0.1 --ports 80,443 --output json
```

Scan an authorized CIDR range with explicit safe limits:

```bash
portmap fast-scan \
  --target 192.168.1.0/24 \
  --ports 22,80,443 \
  --concurrency 64 \
  --rate 128 \
  --output json
```

Use aggressive mode only on networks where you have explicit authorization:

```bash
portmap fast-scan --target 10.0.0.0/20 --ports 1-1024 --aggressive --output json
```

## Safe Defaults

Default limits:

- max targets: 256
- max ports: 1024
- max concurrency: 64
- max probe rate: 128 per second

Aggressive mode raises the ceilings but adds an explicit warning to result rows.

## Result Shape

```json
{
  "target": "127.0.0.1",
  "port": 443,
  "remote": "127.0.0.1:443",
  "ip_version": 4,
  "status": "CLOSED",
  "tcp_state": "closed",
  "reason": "connection_refused",
  "duration_ms": 1.234,
  "scanner": "async_connect"
}
```

## Safety

This feature uses normal TCP connect attempts and follows the global PortMap-AI safety guarantees.
