# Local Visibility and Operator Tooling

Phase 41 adds a lightweight local visibility summarizer for operator workflows. It combines existing asset, service, and flow evidence into categorized findings and approval-required review drafts without running scans by itself.

## Scope

The implementation lives in `core_engine.visibility` and supports:

- authorized asset inventory summaries
- service and protocol metadata summaries
- passive flow summary review
- categorized findings by asset, service, and flow category
- policy-controlled review thresholds for management ports, data-service ports, unknown services, public endpoints, and high-volume flows
- dry-run response workflow drafts for operator approval
- JSON-serializable output for future dashboard, orchestrator, and distributed-node visibility layers

This layer does not execute remediation, change host configuration, store raw payload bytes, or transmit data. It only summarizes evidence provided by other opt-in commands.

## CLI Usage

Summarize asset and service evidence:

```bash
portmap visibility \
  --assets-json '{"assets":[{"host":"<LAN_IP>","status":"reachable","methods":["arp"]}]}' \
  --services-json '[{"target":"<LAN_IP>","port":10022,"state":"open","service":"SSH","confidence":0.92}]' \
  --output json
```

Summarize flow evidence:

```bash
portmap visibility \
  --flows-json '{"flows":[{"flow_id":"<FLOW_ID>","initiator":{"ip":"<LAN_IP>","port":51515},"responder":{"ip":"<REMOTE_IP>","port":8443},"payload_bytes":2048,"application_protocols":["HTTPS"]}]}' \
  --output table
```

Apply a local review policy:

```bash
portmap visibility \
  --services-json '[{"target":"<LAN_IP>","port":15432,"state":"open","service":"PostgreSQL"}]' \
  --policy-json '{"database_ports":[15432],"high_payload_bytes":1048576,"require_approval":true}' \
  --output json
```

Run the fully sanitized example dataset:

```bash
portmap visibility \
  --assets-json docs/examples/assets_sample.json \
  --services-json docs/examples/services_sample.json \
  --flows-json docs/examples/flows_sample.json \
  --policy-json docs/examples/policy_sample.json \
  --output table
```

The files under `docs/examples/` use RFC5737 TEST-NET addresses and placeholders only. They are intended for command testing, screenshots, and training material without exposing local infrastructure details.

## Result Shape

The JSON report includes:

- `summary`: counts for assets, services, flows, findings, and review drafts
- `categories`: structured per-domain summaries
- `findings`: categorized finding rows with severity, target, evidence, and recommended action
- `response_workflows`: dry-run, approval-required review drafts
- `policy`: the effective local policy
- `automatic_changes: false`
- `administrator_controlled: true`
- `raw_payload_stored: false`

Example finding:

```json
{
  "category": "service",
  "severity": "high",
  "type": "management_service_open",
  "target": "<LAN_IP>",
  "message": "Management service SSH is open on port 10022.",
  "recommended_action": "review_access_policy"
}
```

Example review draft:

```json
{
  "action": "review_access_policy",
  "target": "<LAN_IP>",
  "approval_required": true,
  "dry_run": true,
  "confirmed": false,
  "automatic_execution": false,
  "status": "pending_operator_review"
}
```

## Service Coverage

Service metadata coverage now includes additional common infrastructure services when the operator enumerates those ports:

- MySQL and MariaDB-compatible banners
- PostgreSQL port hints
- Redis banners
- MongoDB port hints
- Elasticsearch HTTP hints
- Microsoft SQL Server and Oracle port hints
- VNC and WinRM
- POP3 and IMAP

These additions are still bounded by existing target, port, timeout, and aggressive-mode limits in `portmap services`.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees:

- all workflows are opt-in
- outputs use placeholders in docs
- response workflows are review drafts only
- destructive actions are not generated or executed
- no raw payload bytes are required or retained
- resource usage remains proportional to already-collected evidence

The sanitized examples preserve these fields so operators can verify safety behavior:

- `automatic_changes: false`
- `administrator_controlled: true`
- `raw_payload_stored: false`
- `dry_run: true`
- `require_approval: true`
