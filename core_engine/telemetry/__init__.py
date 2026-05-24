"""Passive telemetry planning helpers.

The telemetry package builds local metadata and dry-run planning records only.
Phase 87 does not capture packets, persist raw payloads, escalate privileges,
or start live sniffing loops.
"""

from core_engine.telemetry.capture_sessions import (
    CAPTURE_SESSION_MODES,
    CAPTURE_SESSION_RECORD_VERSION,
    PassiveCaptureSessionError,
    build_capture_plan_api_response,
    build_capture_plan_dashboard_record,
    build_capture_targets,
    build_passive_capture_session_plan,
    deterministic_capture_plan_json,
    summarize_capture_plan,
    validate_capture_session_plan_inputs,
)
from core_engine.telemetry.interfaces import (
    INTERFACE_RECORD_VERSION,
    TELEMETRY_SAFETY_FLAGS,
    TelemetryInterfaceError,
    build_interface_api_response,
    build_interface_dashboard_record,
    build_interface_resource_budget_summary,
    classify_interface_capabilities,
    deterministic_interface_json,
    enumerate_local_interfaces,
    normalize_address_family,
    normalize_interface_address,
    normalize_interface_metadata,
    summarize_interface_address_families,
    summarize_interfaces,
)

__all__ = [
    "CAPTURE_SESSION_MODES",
    "CAPTURE_SESSION_RECORD_VERSION",
    "INTERFACE_RECORD_VERSION",
    "PassiveCaptureSessionError",
    "TELEMETRY_SAFETY_FLAGS",
    "TelemetryInterfaceError",
    "build_capture_plan_api_response",
    "build_capture_plan_dashboard_record",
    "build_capture_targets",
    "build_interface_api_response",
    "build_interface_dashboard_record",
    "build_interface_resource_budget_summary",
    "build_passive_capture_session_plan",
    "classify_interface_capabilities",
    "deterministic_capture_plan_json",
    "deterministic_interface_json",
    "enumerate_local_interfaces",
    "normalize_address_family",
    "normalize_interface_address",
    "normalize_interface_metadata",
    "summarize_capture_plan",
    "summarize_interface_address_families",
    "summarize_interfaces",
    "validate_capture_session_plan_inputs",
]
