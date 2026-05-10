# Traffic Flow Reconstruction

Phase 29 adds passive traffic flow reconstruction on top of packet metadata, protocol dissection, DPI output, and capture rows. It groups packets into bidirectional flow records for future topology, behavior learning, and correlation layers without storing raw payload bytes.

## Scope

The flow tracker lives in `core_engine.modules.flow_tracker` and provides:

- Bidirectional flow keys from source/destination IPs, ports, and transport protocol.
- Time-windowed flow segmentation when an idle gap exceeds the configured window.
- Initiator/responder lineage based on the first observed packet in a flow.
- Directional packet and payload counters.
- Transport and application protocol summaries.
- Finding and evidence aggregation from DPI and dissection results.
- Topology-ready node and edge summaries.
- JSON-serializable output for CLI, dashboard, AI, and future correlation layers.

Flow reconstruction is passive metadata processing. It does not capture traffic by itself, transmit packets, authenticate, exploit services, alter network configuration, or trigger remediation.

## CLI Usage

Reconstruct flows from packet metadata or DPI records:

```bash
portmap flows \
  --events-json '[{"timestamp":1,"protocol":"TCP","src_ip":"10.0.0.5","src_port":51515,"dst_ip":"10.0.0.10","dst_port":443,"payload_bytes":128}]' \
  --output json
```

Use a shorter idle window to split flows:

```bash
portmap flows --events-json '[...]' --window 15 --output json
```

Attach flow summaries to an explicit capture:

```bash
portmap capture --duration 5 --max-packets 50 --filter tcp --flows --output json
```

`--flows` only summarizes packet metadata collected by the capture command. On platforms where live capture is unsupported or lacks privileges, capture still returns structured capability results such as `unsupported_capture_backend` or `permission_denied`.

## Output Fields

`portmap flows` returns:

- `ok`
- `window_seconds`
- `flow_count`
- `flows`
- `topology`
- `raw_payload_stored`

Each flow includes:

- `flow_id`
- `flow_key`
- `initiator` and `responder`
- `first_seen`, `last_seen`, and `duration_seconds`
- `packet_count`
- `payload_bytes`
- `captured_bytes`
- directional counters
- `transports`
- `application_protocols`
- aggregated `findings`
- aggregated `evidence`

Topology output contains:

- `nodes`: per-IP flow, packet, and byte totals
- `edges`: initiator-to-responder relationships with flow, packet, byte, transport, and application protocol summaries

## Developer API

```python
from core_engine.modules.flow_tracker import build_flow_report, reconstruct_flows

flows = reconstruct_flows(packet_rows, window_seconds=60)
report = build_flow_report(packet_rows)
```

Input rows can be packet-capture metadata, DPI result objects, or records with a nested `metadata` object. Raw payloads are not needed and are not retained in flow output.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. Traffic flow reconstruction stores no raw payload bytes in flow reports.

Future AI behavioral and topology phases should consume flow records and topology summaries rather than raw packets wherever possible.
