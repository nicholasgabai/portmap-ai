# Scanner and Risk Engine

Phase 8 improves scan output and risk explanations while preserving the existing worker payload shape.

Scanner additions:

- `basic_scan()` still returns normalized connection dictionaries.
- Each scanned row now includes `service_name` when the local port maps to a known service hint.
- The scanner still falls back to deterministic demo rows when socket enumeration is unavailable.

Risk engine additions:

- Known risky ports are centralized in `core_engine.risky_ports`.
- Risk metadata includes service name, severity, and a short reason.
- Heuristic scoring now considers:
  - known risky port severity
  - sensitive ports
  - high-risk protocols
  - listening sockets
  - sockets bound to all interfaces
  - public remote endpoints
  - suspicious process-name markers
  - payload presence
  - high ephemeral listeners
  - unusual socket states
  - expected service allowlist matches

Every heuristic score includes:

- `score`
- `score_factors`
- `risk_explanation`

Example factors:

```json
[
  "risky_port:3389:RDP:critical",
  "sensitive_port:3389",
  "listening_socket",
  "binds_all_interfaces"
]
```

Example explanation:

```text
Risk score 0.980: RDP on port 3389 is classified as critical risk; port 3389 is sensitive; open listening socket; listening on all interfaces.
```

Expected services still reduce score and explain why:

```json
{
  "port": 3306,
  "protocol": "MySQL",
  "program": "mysqld",
  "reason": "local development database"
}
```
