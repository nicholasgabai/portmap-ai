# Live Packet Ingestion

Phase 88 adds bounded packet metadata ingestion windows for operator-provided records and sanitized fixtures.

This phase does not capture packets from interfaces, store raw payload bytes, modify traffic, inject traffic, block traffic, create hidden monitoring, start network listeners, or transmit telemetry externally. It converts provided packet metadata into local, deterministic summaries.

## Purpose

Live packet ingestion prepares PortMap-AI for later passive telemetry phases by answering these operator questions:

- Which metadata-only packet records were accepted into a bounded window?
- Which interface and node produced each packet metadata record?
- Which records are IPv4, IPv6, mixed-family, malformed, unsupported, stale, or duplicate?
- What TCP, UDP, and ICMP transport counts were observed?
- What packet size and packet rate summaries are safe to show in dashboards?
- Did any input include payload-like fields, and were they discarded?

## Modules

- `core_engine.telemetry.ingestion`
- `core_engine.telemetry.packet_window`

The helpers reuse Phase 87 interface and capture-session planning records. They accept metadata dictionaries from tests or explicit operator workflows and return dashboard/API-ready dictionaries.

## Packet Metadata Records

Packet metadata records include:

- interface attribution
- source node attribution
- source and destination addresses
- optional source and destination ports
- IPv4, IPv6, mixed, or unknown address-family classification
- TCP, UDP, ICMP, unsupported, or unknown transport classification
- packet size in bytes
- deterministic packet digest
- malformed and unsupported reason lists
- payload governance fields

Payload-like input fields are never copied into output records. Output always includes:

- `raw_payload_stored: false`
- `payload_bytes_stored: 0`
- `automatic_changes: false`
- `administrator_controlled: true`
- `external_transmission_enabled: false`

## Ingestion Window Records

Packet ingestion windows provide bounded dry-run summaries:

- maximum packet count
- maximum byte count
- metadata record count
- accepted, duplicate, stale, malformed, unsupported, rejected, and truncated counters
- packet size summaries
- packet rate summaries
- transport summaries
- address-family summaries
- replay-safe counters
- dashboard/API-ready dictionaries

Window records are dry-run summaries. They do not open interfaces or capture packets.

## Sanitized Example

```json
{
  "record_type": "packet_ingestion_window",
  "dry_run": true,
  "metadata_only": true,
  "summary": {
    "metadata_record_count": 3,
    "accepted_count": 3,
    "transport_summary": {
      "icmp": 1,
      "tcp": 1,
      "udp": 1
    },
    "address_family_summary": {
      "ipv4": 2,
      "ipv6": 1
    }
  },
  "raw_payload_stored": false,
  "external_transmission_enabled": false
}
```

## Operator Workflow

1. Build or load a Phase 87 passive capture plan.
2. Provide packet metadata records from sanitized fixtures or an explicit later telemetry source.
3. Build a bounded packet ingestion window.
4. Review malformed, unsupported, stale, duplicate, and truncated counters.
5. Forward only metadata summaries to later flow, protocol, topology, dashboard, or export phases.

## Validation Notes

Phase 88 validation uses sanitized metadata fixtures only.

- Run the full test suite with `python -m pytest`.
- Run `git diff --check`.
- Confirm no payload captures, logs, screenshots, archives, database files, environment files, runtime artifacts, or private validation notes are staged.
- Confirm `docs/real_device_validation.md` remains unstaged unless separately scrubbed and approved.
