"""Gateway and router-adjacent metadata helpers.

The gateway package currently parses sanitized local router/firewall log
fixtures only. It does not start listeners, change router settings, or enforce
network policy.
"""

from core_engine.gateway.log_parsers import (
    map_gateway_log_fields,
    parse_gateway_log_line,
    parse_gateway_log_lines,
)
from core_engine.gateway.router_logs import (
    GATEWAY_LOG_RECORD_VERSION,
    GATEWAY_LOG_SAFETY_FLAGS,
    build_gateway_log_api_response,
    build_gateway_log_dashboard_record,
    build_gateway_log_export_summary,
    build_gateway_log_ingestion_report,
    deterministic_gateway_log_json,
    gateway_event_severity,
    gateway_log_to_runtime_event,
    gateway_log_to_topology_edge,
    malformed_gateway_log_record,
    normalize_gateway_action,
    normalize_gateway_endpoint,
    normalize_gateway_log_record,
    normalize_gateway_timestamp,
    summarize_gateway_logs,
)

__all__ = [
    "GATEWAY_LOG_RECORD_VERSION",
    "GATEWAY_LOG_SAFETY_FLAGS",
    "build_gateway_log_api_response",
    "build_gateway_log_dashboard_record",
    "build_gateway_log_export_summary",
    "build_gateway_log_ingestion_report",
    "deterministic_gateway_log_json",
    "gateway_event_severity",
    "gateway_log_to_runtime_event",
    "gateway_log_to_topology_edge",
    "malformed_gateway_log_record",
    "map_gateway_log_fields",
    "normalize_gateway_action",
    "normalize_gateway_endpoint",
    "normalize_gateway_log_record",
    "normalize_gateway_timestamp",
    "parse_gateway_log_line",
    "parse_gateway_log_lines",
    "summarize_gateway_logs",
]
