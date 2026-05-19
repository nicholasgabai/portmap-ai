# Runtime CLI

The `portmap runtime` command family exposes the unified local runtime operations path. It is operator-triggered, local-first, and dry-run by default.

This phase does not start services, install service files, run background collection, execute remediation, change host configuration, or transmit data externally.

## Commands

### `portmap runtime status`

Builds an operator-readable summary from a runtime profile and a local runtime session record.

```bash
portmap runtime status --output json
```

### `portmap runtime run`

Runs the explicit local runtime pipeline over operator-provided JSON records.

```bash
portmap runtime run \
  --assets-json '[{"asset_id":"asset-alpha","label":"Asset Alpha"}]' \
  --services-json '[{"service_id":"service-alpha","asset_id":"asset-alpha","service":"https"}]' \
  --output json
```

The command is dry-run by default. Local storage writes require both:

- `--write-local`
- `--db-path <operator-selected-database>`

### `portmap runtime recover`

Builds an advisory recovery summary from runtime checkpoints or pipeline result records.

```bash
portmap runtime recover --checkpoint-json '{"record_type":"runtime_checkpoint"}' --output json
```

### `portmap runtime reviews`

Summarizes local operator review records.

```bash
portmap runtime reviews --reviews-json '[{"review_id":"review-sample","policy_id":"policy-sample","source_ref":"finding:finding-sample","category":"policy_review_required","severity":"high","title":"Sample Review","summary":"Sample review summary."}]' --output json
```

### `portmap runtime export`

Builds an operational export bundle from operator-provided local evidence summaries.

```bash
portmap runtime export \
  --runtime-summary-json '{"status":"ok","session_id":"session-sample"}' \
  --output json
```

Writing a JSON bundle or archive requires an explicit `--output-path`.

## Output Modes

Each runtime command supports:

- `--output json`
- `--output table`

JSON output is intended for local automation, tests, and future dashboard/API integration. Table output is intended for operator review.

## Safety Posture

Runtime CLI commands:

- use dry-run behavior by default
- require explicit local-write flags for storage writes
- do not collect new network data
- do not execute remediation
- do not run plugins
- do not install, enable, start, or stop services
- do not transmit data externally
- do not store raw payload bytes in public output

## Relationship To Existing Commands

The runtime command family is additive. It does not replace:

- `portmap stack`
- `portmap tui`
- `portmap visibility`
- `portmap logs`
