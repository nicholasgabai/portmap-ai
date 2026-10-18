# Runtime Evidence Integrity

This unnumbered stabilization milestone continues the existing phase history.
It changes metadata identity and time propagation; it does not collect traffic,
enable capture, change scoring rules, or execute remediation.

## Identity Contract

New socket observations use identity version 2. The shared identity basis includes
the originating node, normalized local and remote addresses, local and remote
ports, address family, transport, direction, listener/conversation scope, source
mode, and telemetry context. IPv6 endpoints with ports use bracket notation;
IPv6 compression is normalized and interface scope identifiers are retained.

- `session_id` identifies an endpoint-supported socket relationship from that
  node's perspective. Listeners do not receive generated session IDs.
- `flow_key` identifies a fully specified conversation in that same context.
- `observation_id` identifies a sample of that relationship at its event time.
- Exact duplicate samples collapse; a later sample has a new observation ID but
  retains the relationship's session and flow identity.
- A listener retains its local endpoint and has no remote endpoint, session ID,
  or flow key. Listener aliases cannot establish conversation correlation.
- Existing supplied IDs remain upstream references. Legacy IDs must be scoped
  by node and endpoint context when matching; they are not rehashed on reload.
  Normalized listener evidence excludes incompatible conversation aliases;
  historical stored records themselves are not rewritten.

Raw socket snapshots do not expose TCP connection creation identifiers. A reused
tuple cannot reliably distinguish successive connection lifetimes without extra
source evidence. Missing endpoints remain missing; incomplete socket identity is
not evidence of a fully reconstructed conversation.

## Timestamp Contract

`event_timestamp` is the source observation time. `ingested_at` is the master
receiver's processing time. New worker samples require aware timestamps and
serialize UTC as ISO-8601 `Z`; aware offsets convert to the same UTC instant.
The compatibility `timestamp` field mirrors event time when available.

Legacy naive strings remain unchanged and carry `timestamp_status` equal to
`ambiguous_legacy`. Missing event times remain null with status `unavailable`.
For old consumers, a master envelope without event time may retain receipt time
in `timestamp`; its explicit null `event_timestamp` prevents treating that value
as an observed event. Receipt time never repairs or substitutes for missing
event evidence. Legacy ambiguity is neither timezone conversion nor clock skew.

Known times compare as UTC instants. Ambiguous values are ordered deterministically
before known instants for bounded retention; this is not a claim about their age.
TUI current snapshots use ingestion order when available, while event details
retain source time. Display strings are not inputs to duration calculations.
The header, event/detail displays, and standard runtime log formatter label UTC.

## Integration And Compatibility

Worker samples pass through the existing JSON framing, master dispatcher, runtime
bridge, session/flow reconstruction, correlation, risk/AI views, learning evidence,
and investigation references. The master JSON log includes bounded enriched
`observations` alongside its compatibility `ports_sample`; the TUI uses the
enriched records when available. Packet Activity only includes conversations
with endpoints, retaining socket-reconstruction provenance.

SQLite event/finding payloads and API collections preserve the additive identity
and time fields. No database columns or historical files are migrated. SQLite
storage remains explicitly invoked by existing repository/runtime callers; this
milestone does not add a background database writer or new API service.
Legacy records without these fields continue to load unchanged.

Session aggregates choose a representative sample deterministically by event
time, receipt time, and a stable record tie-breaker. They do not replace the
identity or event time of individual samples during enrichment or correlation.
Learning history uses explicit event time, including explicit absence, rather
than analysis time. AI does not present session/flow references as observation
IDs. Existing event/packet/record and flow ID aliases remain recognizable.

Risk and AI selection keys include full endpoint context, not abbreviated labels.
Packet aggregation keeps socket, packet-metadata, and fixture provenance separate.
An explicit unknown event time persists as null in JSON/API payloads; the existing
non-null SQLite timestamp index uses an empty string without a schema migration.

## Validation

`tests/test_runtime_evidence_integrity.py` exercises node/endpoint separation,
IPv4/IPv6, listeners, repeated samples, source offsets and UTC rollover, legacy
timestamps, source versus receipt time, transport framing, master JSON logging,
SQLite close/reopen, API collections, risk/AI evidence, and TUI duration/display.
Existing TEST 8R, attribution, and narrow-pane/viewport tests remain regression
checks. These local tests do not establish physical device acceptance.

Manual device validation should use the existing read-only stack configuration:

1. Confirm the installed checkout and record `date -u` on each participating host.
2. Keep a new ordinary SSH session open through several worker sample intervals.
3. Inspect the same observation in master metadata, Risk, AI, and Packet details.
   Compare node, endpoints, observation ID, session ID, and flow key where present.
4. Verify event time remains constant through downstream views and ingestion time
   records receiver processing. Verify all displayed clocks identify UTC.
5. Compare a TCP listener with the established conversation: the listener must
   show flow identity as not applicable and must not create Packet Activity.
6. Repeat with another worker or peer where available; equal ports must not
   combine different nodes or addresses. Check refresh selection and scrolling.

Clock synchronization is an operator responsibility; no skew correction or NTP
service is added. Dedicated legacy federation parsers and independent historical
models still require separate contract review before claiming repository-wide
UTC compliance. Safety defaults and operator-controlled execution stay intact.

## Post-TEST 8R Hardening

Operator-reported Raspberry Pi results at `62c92b4` include 38 passing runtime
evidence tests, consistent UTC presentation, SSH identities matching AI/Packet,
and independently observed established SSH sockets. These are reported physical
results, not physical tests performed by the development environment.

The TUI health check previously used a 0.75-second timeout and described malformed
responses and transport failures alike as unreachable. It now uses a bounded
two-second request timeout, distinguishes timeout, connection failure, HTTP/auth
failure, and invalid responses, and shows check/last-success UTC timestamps.
Metrics failure does not invalidate a successful health response. The endpoint
only checks API responsiveness; node rows come from local persisted state and
can outlive the process. A failed check is not evidence of a crash. The stack
launcher stops its children on exit and has bounded restart supervision; inspect
its output and API results before drawing a lifecycle conclusion. Existing
synchronous refresh work can delay the display of a new check.

Socket-derived flows count metadata observations, not captured packets. New
summaries include `event_count`, `socket_observation_count`,
`captured_packet_count`, and `counter_provenance`. Socket packet/byte counters
remain zero because they are not measured. The TUI labels activity counters
Events and displays unmeasured bytes/packets explicitly, not as zero traffic.
Exact replays with the same scoped sample ID and event timestamp count once.
Aggregates expose contributing observation IDs instead of a fabricated singular
ID. A session count is not an event or packet count.
Packet details show the originating node. Aggregation `flow_key` remains a
grouping key; `source_flow_key`/`source_flow_keys` retain the canonical worker
flow references. Only a single-sample aggregate has a singular observation ID.

Capture-length-bearing metadata is categorized as `captured_packet`; this is
source metadata, not independent authentication of capture. Explicit fixture,
simulation, estimate, and OS-counter metadata remain distinct. No OS packet
totals are inferred from socket presence. Legacy unmarked packet metadata retains
the compatibility `packet_count` with `reported_packet_metadata` provenance;
it is not claimed to be measured capture. Topology exposes separate
`counter_sources` totals even when grouping the same endpoint pair. API/SQLite
JSON preserves these additive fields without a migration or automatic writer.

Explicit UTC display strings parse back to the same UTC instant. Naive legacy
timestamps still remain ambiguous. No capture, crafting, external scanning,
enforcement, blocking, remediation execution, or runtime service was added.
