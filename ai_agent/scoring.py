from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np

from ai_agent.interface import AIAnalysisResult, AIProvider, validate_analysis_result
from ai_agent.ml_model_scorer import MLScorer
from core_engine.config_loader import load_settings
from core_engine.risky_ports import SEVERITY_WEIGHTS, port_metadata

ml_scorer = MLScorer()

LOG_FILE = Path.home() / ".portmap-ai" / "data" / "connection_log.jsonl"
LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

SENSITIVE_PORTS = {22, 23, 53, 3306, 3389, 5432, 5900, 6379}
HIGH_RISK_PROTOCOLS = {"TELNET", "RDP", "MYSQL", "EXPLOIT", "BACKDOOR", "MALWARE"}
SUSPICIOUS_PROGRAM_MARKERS = ("unknown", "nc", "ncat", "netcat", "socat", "python", "bash", "sh")


def sanitize_for_logging(obj, seen=None, root=None):
    if seen is None:
        seen = set()
    if root is None:
        root = obj

    obj_id = id(obj)
    if obj_id in seen:
        return "<circular_ref>"
    seen.add(obj_id)

    if isinstance(obj, dict):
        sanitized = {}
        for key, value in obj.items():
            if key == "payload" and isinstance(value, str) and len(value) > 300:
                sanitized[key] = value[:300] + "..."
            elif value is root:
                sanitized[key] = "<circular_ref>"
            else:
                sanitized[key] = sanitize_for_logging(value, seen, root)
        return sanitized
    if isinstance(obj, list):
        return [sanitize_for_logging(item, seen, root) for item in obj]
    if isinstance(obj, tuple):
        return tuple(sanitize_for_logging(item, seen, root) for item in obj)
    if isinstance(obj, np.generic):
        return float(obj)
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


def log_connection(connection, file_path="logs/connection_log.jsonl"):
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        clean_conn = sanitize_for_logging(connection)
        with open(file_path, "a") as handle:
            handle.write(json.dumps(clean_conn, indent=2))
            handle.write("\n")
    except Exception as exc:
        print(f"⚠️ Failed to log connection: {exc}")


def get_autolearn_setting():
    settings_path = Path.home() / ".portmap-ai" / "data" / "settings.json"
    try:
        if settings_path.exists():
            with open(settings_path, "r") as handle:
                config = json.load(handle)
                return config.get("enable_autolearn", False)
    except Exception as exc:
        print(f"⚠️ Failed to read settings.json: {exc}")
    return False


def _extract_host(address: str | None) -> str:
    if not address or address == "-":
        return ""
    value = str(address)
    if value.count(":") == 1:
        return value.split(":", 1)[0]
    if value.startswith("[") and "]:" in value:
        return value[1:].split("]:", 1)[0]
    return value


def _is_public_host(host: str) -> bool:
    if not host:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)


def _is_wildcard_host(host: str) -> bool:
    return host in {"0.0.0.0", "::", "*", ""}


def _clamp_score(value: float) -> float:
    return round(max(0.05, min(0.98, value)), 3)


def _matches_expected_service(connection: Dict[str, Any], service: Dict[str, Any]) -> bool:
    try:
        expected_port = int(service.get("port", 0) or 0)
    except Exception:
        expected_port = 0
    try:
        actual_port = int(connection.get("port", 0) or 0)
    except Exception:
        actual_port = 0

    if expected_port and expected_port != actual_port:
        return False

    expected_protocol = str(service.get("protocol") or "").upper()
    actual_protocol = str(connection.get("protocol") or "").upper()
    if expected_protocol and actual_protocol and expected_protocol != actual_protocol:
        return False

    expected_program = str(service.get("program") or "").lower()
    actual_program = str(connection.get("program") or "").lower()
    if expected_program and actual_program and expected_program not in actual_program:
        return False

    return bool(expected_port or expected_protocol or expected_program)


def _find_expected_service(connection: Dict[str, Any], expected_services: List[Dict[str, Any]]) -> Dict[str, Any] | None:
    for service in expected_services:
        if isinstance(service, dict) and _matches_expected_service(connection, service):
            return service
    return None


def heuristic_score(
    connection: Dict[str, Any],
    expected_services: List[Dict[str, Any]] | None = None,
) -> Tuple[float, List[str]]:
    score = 0.15
    factors: List[str] = []

    port = int(connection.get("port") or 0)
    protocol = str(connection.get("protocol") or "Unknown").upper()
    status = str(connection.get("status") or "").upper()
    direction = str(connection.get("direction") or "").lower()
    program = str(connection.get("program") or "unknown").lower()
    remote_host = _extract_host(connection.get("remote"))
    local_host = _extract_host(connection.get("local"))
    payload = str(connection.get("payload") or "")

    metadata = port_metadata(port)
    if metadata and metadata.get("severity") != "low":
        severity = str(metadata.get("severity") or "medium")
        service = str(metadata.get("service") or "unknown")
        score += SEVERITY_WEIGHTS.get(severity, 0.15)
        factors.append(f"risky_port:{port}:{service}:{severity}")

    if port in SENSITIVE_PORTS:
        score += 0.25
        factors.append(f"sensitive_port:{port}")
    elif port in {80, 443, 8080, 8443}:
        score += 0.08
        factors.append(f"common_service_port:{port}")

    if protocol in HIGH_RISK_PROTOCOLS:
        score += 0.2
        factors.append(f"high_risk_protocol:{protocol}")
    elif protocol in {"HTTP", "HTTPS", "SSH"}:
        score += 0.05
        factors.append(f"known_protocol:{protocol}")

    if status == "LISTEN":
        score += 0.15
        factors.append("listening_socket")
        if _is_wildcard_host(local_host):
            score += 0.1
            factors.append("binds_all_interfaces")
    elif status == "ESTABLISHED":
        score += 0.1
        factors.append("established_connection")

    if direction == "outgoing":
        score += 0.05
        factors.append("outgoing_flow")

    if _is_public_host(remote_host):
        score += 0.18
        factors.append("public_remote_ip")

    if any(marker in program for marker in SUSPICIOUS_PROGRAM_MARKERS):
        score += 0.08
        factors.append(f"suspicious_program:{program}")

    if payload:
        score += min(len(payload) / 500.0, 0.04)
        factors.append("payload_present")

    if status == "LISTEN" and port >= 49152:
        score += 0.08
        factors.append("high_ephemeral_listener")

    if status in {"CLOSE_WAIT", "SYN_SENT", "SYN_RECV"}:
        score += 0.05
        factors.append(f"unusual_socket_state:{status}")

    if remote_host in {"127.0.0.1", "::1", "localhost"}:
        score -= 0.12
        factors.append("loopback_remote")

    if direction == "incoming" and port in {80, 443, 8080, 8443}:
        score -= 0.04
        factors.append("expected_incoming_service")

    expected_service = _find_expected_service(connection, expected_services or [])
    if expected_service:
        reason = str(expected_service.get("reason") or "configured")
        score -= 0.22
        factors.append(f"expected_service:{reason}")

    return _clamp_score(score), factors


FACTOR_EXPLANATIONS = {
    "binds_all_interfaces": "listening on all interfaces",
    "established_connection": "active established connection",
    "expected_incoming_service": "common incoming service pattern",
    "high_ephemeral_listener": "listening on a high ephemeral port",
    "listening_socket": "open listening socket",
    "loopback_remote": "remote endpoint is loopback",
    "outgoing_flow": "outbound connection flow",
    "payload_present": "payload data was observed",
    "public_remote_ip": "remote endpoint is a public IP address",
}


def explain_score(score: float, factors: List[str]) -> str:
    if not factors:
        return f"Risk score {score:.3f}: no specific risk factors identified."
    explanations: list[str] = []
    for factor in factors:
        if factor.startswith("risky_port:"):
            _, port, service, severity = factor.split(":", 3)
            explanations.append(f"{service} on port {port} is classified as {severity} risk")
        elif factor.startswith("sensitive_port:"):
            explanations.append(f"port {factor.split(':', 1)[1]} is sensitive")
        elif factor.startswith("high_risk_protocol:"):
            explanations.append(f"protocol {factor.split(':', 1)[1]} is high risk")
        elif factor.startswith("known_protocol:"):
            explanations.append(f"protocol {factor.split(':', 1)[1]} is recognized")
        elif factor.startswith("suspicious_program:"):
            explanations.append(f"program name matched suspicious marker '{factor.split(':', 1)[1]}'")
        elif factor.startswith("expected_service:"):
            explanations.append(f"matches expected service: {factor.split(':', 1)[1]}")
        elif factor.startswith("unusual_socket_state:"):
            explanations.append(f"socket state {factor.split(':', 1)[1]} needs review")
        else:
            explanations.append(FACTOR_EXPLANATIONS.get(factor, factor.replace("_", " ")))
    return f"Risk score {score:.3f}: " + "; ".join(explanations[:6]) + "."


def heuristic_analysis(
    connection: Dict[str, Any],
    expected_services: List[Dict[str, Any]] | None = None,
    *,
    provider: str = "heuristic",
) -> AIAnalysisResult:
    score, factors = heuristic_score(connection, expected_services=expected_services)
    return AIAnalysisResult(
        score=score,
        factors=factors,
        explanation=explain_score(score, factors),
        provider=provider,
    )


class LocalAIProvider:
    name = "local"

    def analyze(self, connection, context=None):
        context = context or {}
        expected_services = context.get("expected_services") or []
        use_ml = bool(context.get("use_ml"))

        if use_ml and ml_scorer.is_loaded():
            try:
                label, score = ml_scorer.predict(connection)
                label_value = label if isinstance(label, (str, int, float)) else str(label)
                factors = ["ml_model"]
                score = _clamp_score(float(score))
                return AIAnalysisResult(
                    score=score,
                    factors=factors,
                    explanation=explain_score(score, factors),
                    provider="local_ml",
                    label=label_value,
                )
            except Exception as exc:
                print(f"⚠️ ML scoring failed, falling back to heuristic scoring: {exc}")
                result = heuristic_analysis(connection, expected_services=expected_services)
                return AIAnalysisResult(
                    score=result.score,
                    factors=result.factors,
                    explanation=result.explanation,
                    provider=result.provider,
                    metadata={"fallback_reason": str(exc)},
                )

        return heuristic_analysis(connection, expected_services=expected_services)


_ai_provider: AIProvider = LocalAIProvider()


def get_ai_provider() -> AIProvider:
    return _ai_provider


def set_ai_provider(provider: AIProvider | None) -> None:
    global _ai_provider
    _ai_provider = provider or LocalAIProvider()


def reset_ai_provider() -> None:
    set_ai_provider(None)


def get_score(connection, use_ml=None):
    if use_ml is None:
        use_ml = get_autolearn_setting()
    settings = load_settings(defaults={"expected_services": []})
    expected_services = settings.get("expected_services") or []

    provider = get_ai_provider()
    provider_name = getattr(provider, "name", "custom")
    try:
        result = validate_analysis_result(
            provider.analyze(
                connection,
                context={"use_ml": use_ml, "expected_services": expected_services},
            ),
            default_provider=provider_name,
        )
    except Exception as exc:
        print(f"⚠️ AI provider failed, falling back to heuristic scoring: {exc}")
        fallback = heuristic_analysis(connection, expected_services=expected_services, provider="heuristic_fallback")
        factors = [*fallback.factors, "ai_provider_failed"]
        result = AIAnalysisResult(
            score=fallback.score,
            factors=factors,
            explanation=explain_score(fallback.score, factors),
            provider=fallback.provider,
            metadata={"fallback_reason": str(exc), "failed_provider": str(provider_name)},
        )

    connection["score"] = result.score
    connection["score_factors"] = result.factors
    connection["risk_explanation"] = result.explanation
    connection["ai_provider"] = result.provider
    if result.label is not None:
        connection["ml_flag"] = result.label if isinstance(result.label, (str, int, float)) else str(result.label)
    else:
        connection.pop("ml_flag", None)
    if result.metadata:
        connection["ai_metadata"] = result.metadata
    else:
        connection.pop("ai_metadata", None)
    log_connection(connection)
    return result.score
