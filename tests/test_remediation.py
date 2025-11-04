from ai_agent.remediation import MODE_PROMPT, MODE_SILENT, decide_remediation, handle_remediation


def test_decide_monitor_below_threshold():
    payload = {"node_id": "node-1", "score": 0.3}
    decision = decide_remediation(payload, MODE_PROMPT, threshold=0.75)
    assert decision.action == "monitor"
    assert decision.auto_applied is False


def test_prompt_mode_requests_operator():
    payload = {"node_id": "node-2", "score": 0.85}
    decision = decide_remediation(payload, MODE_PROMPT, threshold=0.75)
    assert decision.action == "prompt_operator"
    assert decision.auto_applied is False


def test_silent_mode_auto_remediates():
    payload = {"node_id": "node-3", "score": 0.9}
    decision = decide_remediation(payload, MODE_SILENT, threshold=0.75)
    assert decision.action == "auto_remediate"
    assert decision.auto_applied is True


def test_handle_remediation_defaults_to_prompt():
    payload = {"node_id": "node-4", "score": 0.9}
    decision = handle_remediation(payload, settings={})
    assert decision.action == "prompt_operator"
