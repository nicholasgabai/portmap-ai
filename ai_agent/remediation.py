# ai_agent/remediation.py

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Dict, Optional

MODE_PROMPT = "prompt"
MODE_SILENT = "silent"


@dataclass
class RemediationDecision:
    action: str
    node_id: str
    score: float
    reason: str
    mode: str
    auto_applied: bool = False

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _normalise_mode(mode: Optional[str]) -> str:
    if not mode:
        return MODE_PROMPT
    mode = mode.strip().lower()
    if mode not in {MODE_PROMPT, MODE_SILENT}:
        return MODE_PROMPT
    return mode


def decide_remediation(payload: Dict[str, object], mode: str, threshold: float) -> RemediationDecision:
    score = float(payload.get("score") or 0.0)
    node_id = payload.get("node_id", "unknown-node")
    mode_norm = _normalise_mode(mode)

    if score < threshold:
        return RemediationDecision(
            action="monitor",
            node_id=node_id,
            score=score,
            reason=f"score<{threshold}",
            mode=mode_norm,
        )

    if mode_norm == MODE_SILENT:
        return RemediationDecision(
            action="auto_remediate",
            node_id=node_id,
            score=score,
            reason="silent_mode",
            mode=mode_norm,
            auto_applied=True,
        )

    return RemediationDecision(
        action="prompt_operator",
        node_id=node_id,
        score=score,
        reason="threshold_exceeded",
        mode=mode_norm,
    )


def handle_remediation(payload: Dict[str, object], settings: Dict[str, object], logger: Optional[logging.Logger] = None) -> RemediationDecision:
    mode = settings.get("remediation_mode", MODE_PROMPT)
    threshold = float(settings.get("remediation_threshold", 0.75))
    decision = decide_remediation(payload, mode, threshold)

    if logger:
        if decision.action == "monitor":
            logger.debug("🛡️ Remediation monitor for %s | score=%.3f", decision.node_id, decision.score)
        elif decision.action == "prompt_operator":
            logger.warning("🛡️ Remediation prompt required for %s | score=%.3f", decision.node_id, decision.score)
        else:
            logger.error("🛡️ Auto-remediation triggered for %s | score=%.3f", decision.node_id, decision.score)

    return decision


__all__ = ["MODE_PROMPT", "MODE_SILENT", "RemediationDecision", "decide_remediation", "handle_remediation"]
