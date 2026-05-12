# Policy Review Engine

Phase 51 adds local advisory policy evaluation and operator review queue primitives for PortMap-AI. The engine converts local events, advisory findings, and baseline deltas into review records that an operator can inspect, approve, defer, dismiss, or mark resolved.

The policy review engine is advisory by default. Approval transitions update review state only; they do not execute actions.

## Policy Model

Policies include:

- `policy_id`
- `name`
- `description`
- `enabled`
- `severity_threshold`
- `categories`
- `required_review`
- `metadata`
- `created_at`
- `updated_at`

Sanitized example:

```json
{
  "policy_id": "policy-sample",
  "name": "Sample Review Policy",
  "description": "Review medium and higher local findings.",
  "enabled": true,
  "severity_threshold": "medium",
  "categories": ["policy_review_required", "service_added"],
  "required_review": true,
  "metadata": {
    "profile": "sample"
  },
  "created_at": "sample-created-at",
  "updated_at": "sample-updated-at"
}
```

## Review Records

Review records include:

- `review_id`
- `policy_id`
- `source_ref`
- `category`
- `severity`
- `title`
- `summary`
- `evidence_refs`
- `recommended_action`
- `status`
- `approval_required`
- `automatic_changes`
- `administrator_controlled`
- `raw_payload_stored`
- `created_at`
- `updated_at`
- optional `reviewed_by`
- optional `review_note`

Supported states:

- `open`
- `approved`
- `deferred`
- `dismissed`
- `resolved`

## Local Workflow

```python
from core_engine.policy import ReviewQueue, create_policy, evaluate_event_against_policies

policy = create_policy(
    policy_id="policy-sample",
    name="Sample Review Policy",
    description="Review high-severity local events.",
    severity_threshold="high",
    categories=["policy_review_required"],
)

reviews = evaluate_event_against_policies(
    {
        "event_id": "event-sample",
        "event_type": "policy_review_required",
        "severity": "high",
        "message": "Sample policy review required.",
    },
    [policy],
)

queue = ReviewQueue(reviews)
queue.update_status(reviews[0].review_id, "approved", reviewed_by="operator-sample")
```

The approval state change does not execute remediation or modify configuration.

## Safety Boundaries

- Local-only and operator-controlled.
- Advisory by default.
- No external network transport.
- No cloud sync.
- No automatic enforcement.
- No router or firewall changes.
- No active background probing.
- No write endpoints.
- No raw payload storage.

Use placeholders in public examples. Do not commit real IP addresses, MAC addresses, hostnames, usernames, secrets, tokens, screenshots, logs, local paths, or environment-specific runtime data.
