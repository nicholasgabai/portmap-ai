# Protocol Dissector Framework

Phase 26 adds a lightweight protocol-dissector framework under `core_engine.protocols`. The framework consumes packet bytes and capture metadata from the Phase 25 packet-capture layer and returns structured summaries without modifying traffic or retaining raw payloads in JSON output.

## Supported Protocols

Initial dissectors cover:

- HTTP
- DNS
- ICMP and ICMPv6
- TLS record headers
- SSH banners
- SMB1 and SMB2/3 markers
- DHCP messages
- FTP commands/responses
- SMTP commands/responses

Unknown or malformed payloads are labeled with `status: "unknown"` or `status: "error"` instead of raising through the capture workflow.

## Capture Integration

Dissection is opt-in during capture:

```bash
portmap capture --duration 5 --max-packets 50 --filter tcp --dissect --output json
```

Captured packet metadata remains available without dissection by default. When `--dissect` is supplied, each packet row may include a `dissection` object with:

- `protocol`
- `status`
- `confidence`
- `summary`
- `fields`
- `evidence`
- `payload_bytes`
- `error`

The dissection object avoids raw payload storage. Sensitive command arguments are redacted for protocols where credentials or addresses commonly appear, such as FTP `PASS`, FTP `USER`, SMTP `AUTH`, `MAIL`, and `RCPT`.

## Direct Developer API

```python
from core_engine.protocols import dissect_packet, dissect_payload

result = dissect_payload("HTTP", b"GET / HTTP/1.1\r\nHost: local\r\n\r\n")
packet_result = dissect_packet(raw_ethernet_frame)
```

`dissect_packet()` performs basic Ethernet/IP/TCP/UDP/ICMP payload extraction, classifies the probable application protocol from ports and payload markers, and delegates to the protocol-specific parser.

## Safety Boundaries

The framework is passive parsing only and follows the global PortMap-AI safety guarantees. It stores no raw payloads in JSON rows by default.

Future DPI work should build on these parsers while keeping payload retention explicit, redacted by default, and operator-controlled.
