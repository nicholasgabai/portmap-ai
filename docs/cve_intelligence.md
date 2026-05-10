# CVE Intelligence Engine

Phase 34 adds a local CVE intelligence layer for matching observed service evidence against vulnerability records. The feature is advisory by default and follows the global PortMap-AI safety guarantees.

## Scope

The implementation lives under `core_engine.vuln`:

- `cve_client.py` normalizes NVD-style CVE records, optionally fetches from the NVD CVE API, and matches service/version evidence to CVEs.
- `cve_store.py` persists a local JSON cache under `~/.portmap-ai/data/cve_cache.json` unless a custom cache path is supplied.
- `cvss.py` extracts CVSS metadata, normalizes severity, and computes an advisory risk score.

The matching engine considers service names, common aliases, CPE strings, version tokens, CVSS severity, known-exploited flags when provided, and whether the service evidence indicates an open/listening endpoint.

## CLI Usage

Offline analysis from service evidence and inline CVE data:

```bash
portmap cve \
  --service-json '[{"target":"127.0.0.1","port":80,"state":"open","service":"HTTP","version":"Apache/2.4.49"}]' \
  --cve-json '[{"id":"CVE-2021-41773","summary":"Apache HTTP Server 2.4.49 path traversal vulnerability.","severity":"high","cvss_score":7.5,"cpes":["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]}]' \
  --output json
```

List the local cache:

```bash
portmap cve --output table
```

Explicitly update the local cache from NVD:

```bash
portmap cve --update --query "openssh" --limit 50 --output json
```

Use `--api-key` when an operator has an NVD API key. Network access only happens when `--update` is provided.

## Output Fields

Offline matching returns:

- `ok`
- `service_count`
- `cve_count`
- `match_count`
- `matches`
- `raw_payload_stored`
- `automatic_changes`
- `model`

Each match includes:

- `target`
- `port`
- `service`
- `version`
- `cve_id`
- `severity`
- `cvss_score`
- `risk_score`
- `confidence`
- `match_reasons`
- `known_exploited`
- `summary`
- `references`
- `advisory`

Cache updates return fetched/stored counts, cache path, normalized records, and explicit `automatic_changes: false` to clarify that only the local advisory cache was written.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees.

CVE matches are evidence for operator review and future prioritization layers; they are not proof that a target is exploitable.
