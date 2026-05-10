# Deep Packet Inspection

Phase 27 adds a passive DPI layer on top of packet capture and protocol dissection. It summarizes headers, payload metadata, suspicious indicators, malformed protocol signals, and basic session groupings without storing raw payload bytes by default.

## Scope

The DPI module lives in `core_engine.modules.dpi` and provides:

- Header extraction from packet metadata and protocol dissection results.
- Payload metadata extraction, including length, SHA-256, entropy, printable ratio, null-byte count, and content category.
- Optional short payload previews with redaction.
- Suspicious pattern detection for credential markers, script injection markers, SQL injection markers, shell command markers, high-entropy payloads, and cleartext login/auth flow indicators.
- Malformed protocol indicators, such as parser errors, unrecognized payloads for known protocols, and truncated TLS records.
- Basic bidirectional session keys and session summaries.
- JSON-serializable results for CLI, future dashboard views, and future AI correlation layers.

DPI remains passive. This phase follows the global PortMap-AI safety guarantees.

## CLI Usage

Analyze a passive observation:

```bash
portmap dpi \
  --observation-json '{"protocol":"HTTP","metadata":{"protocol":"TCP","src_ip":"10.0.0.5","src_port":51515,"dst_ip":"10.0.0.10","dst_port":80},"payload_text":"GET / HTTP/1.1\r\nHost: local\r\n\r\n"}' \
  --output json
```

Include a short redacted preview:

```bash
portmap dpi \
  --observation-json '{"protocol":"HTTP","payload_text":"POST /login HTTP/1.1\r\nHost: local\r\n\r\npassword=secret"}' \
  --include-payload-preview \
  --output json
```

Attach DPI analysis to captured packet metadata:

```bash
portmap capture --duration 5 --max-packets 50 --filter tcp --dpi --output json
```

On platforms where live capture is unsupported or lacks privileges, capture still returns structured capability results such as `unsupported_capture_backend` or `permission_denied`.

## Payload Handling

Raw payload bytes are not emitted in JSON results. By default, DPI output includes metadata only:

- `length`
- `sha256`
- `entropy`
- `printable_ratio`
- `null_bytes`
- `category`

If `--include-payload-preview` is used for observation analysis, the preview is limited and redacted. Authorization tokens, password-like key/value pairs, FTP/SMTP credential command arguments, and email local parts are replaced with `<redacted>`.

## Findings

Findings include:

- `credential_material`
- `script_injection_marker`
- `sql_injection_marker`
- `shell_command_marker`
- `high_entropy_payload`
- `cleartext_credential_protocol`
- `cleartext_mail_auth_or_identity`
- `cleartext_login_flow`
- `malformed_protocol`
- `unrecognized_protocol_payload`
- `truncated_tls_record`

These findings are evidence markers for operator review and future correlation. They do not imply automatic blocking or remediation.

## Developer API

```python
from core_engine.modules.dpi import analyze_observation, analyze_packet, group_sessions

result = analyze_observation({
    "protocol": "HTTP",
    "payload_text": "GET / HTTP/1.1\r\nHost: local\r\n\r\n",
})

packet_result = analyze_packet(raw_ethernet_frame)
sessions = group_sessions([packet_result])
```

Future behavioral learning and threat-correlation phases should consume DPI results rather than raw payloads whenever possible.
