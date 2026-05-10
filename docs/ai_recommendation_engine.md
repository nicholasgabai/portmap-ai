# AI Recommendation Engine

Phase 33 adds a local recommendation engine that turns correlated incidents into operator-review recommendations. It suggests investigation, segmentation review, credential rotation, egress review, and dry-run remediation drafts while preserving the existing approval and safety posture.

## Scope

The implementation lives in `ai_agent.recommendation_engine` and supports:

- Recommendations from Phase 32 threat-correlation incidents.
- Investigation and evidence-review recommendations for every incident.
- Scan-source review for suspicious scan behavior.
- Segmentation review for lateral-movement indicators.
- Host evidence collection for chained behavior/payload risk.
- Credential rotation recommendations when credential-like payload markers are present.
- Egress policy review for beaconing or possible exfiltration indicators.
- Dry-run, approval-required remediation command drafts for high-scoring incidents.
- Stable recommendation IDs, confidence, priority, operator prompts, and supporting evidence summaries.

The recommendation engine creates administrator-review guidance. Destructive recommendations are always marked `approval_required: true`, `dry_run: true`, and `confirmed: false`.

## CLI Usage

Generate recommendations from a correlation report:

```bash
portmap recommend \
  --incidents-json '{"incidents":[{"incident_id":"inc-1","type":"chained_behavior_payload_risk","severity":"high","score":0.9,"entity":"worker-1","peers":["10.0.0.10"],"findings":["new_peer","credential_marker"],"event_count":2}]}' \
  --output json
```

Use a different dry-run approval threshold:

```bash
portmap recommend --incidents-json '[...]' --approval-threshold 0.9 --output json
```

## Output Fields

The command returns:

- `ok`
- `incident_count`
- `recommendation_count`
- `recommendations`
- `review_threshold`
- `approval_threshold`
- `raw_payload_stored`
- `automatic_changes`
- `model`

Each recommendation includes:

- `recommendation_id`
- `incident_id`
- `incident_type`
- `action`
- `target`
- `priority`
- `confidence`
- `reason`
- `approval_required`
- `dry_run`
- `destructive`
- `operator_prompt`
- `supporting_evidence`
- optional `remediation_command`

## Developer API

```python
from ai_agent.recommendation_engine import generate_recommendations, recommend_incident

single = recommend_incident(incident)
report = generate_recommendations(incidents)
```

Inputs should be incident rows from `ai_agent.threat_correlation`, but the engine tolerates plain dicts with the same fields.

## Safety Boundaries

This phase follows the global PortMap-AI safety guarantees. Recommendation output stores no raw payload bytes, and future remediation integrations must continue to pass generated drafts through the existing remediation safety gates.
Destructive actions require explicit operator approval.
