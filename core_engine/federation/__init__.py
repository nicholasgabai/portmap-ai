"""Trusted federation record helpers.

Phase 77 introduces local record models only. The package does not open
network listeners, contact peers, or perform cryptographic signing.
"""

from core_engine.federation.transport import (
    DEFAULT_TRANSPORT_MODE,
    TRUSTED_TRANSPORT_MODES,
    TRUSTED_TRANSPORT_STATUSES,
    TrustedTransportError,
    build_handshake_summary,
    build_replay_window_metadata,
    build_transport_session_summary,
    create_trusted_transport_session,
    deterministic_transport_json,
    trusted_transport_session_from_dict,
    trusted_transport_session_to_dict,
    validate_trusted_transport_session,
)
from core_engine.federation.trust import (
    DEFAULT_REPLAY_WINDOW_SECONDS,
    TRUST_SCOPE_LABELS,
    TRUST_STATUSES,
    TrustedNodeTrustError,
    build_approved_peer_record,
    build_local_node_trust_profile,
    deterministic_trust_json,
    is_peer_approved,
    summarize_trust_profile,
    validate_approved_peer_record,
    validate_local_node_trust_profile,
)

__all__ = [
    "DEFAULT_REPLAY_WINDOW_SECONDS",
    "DEFAULT_TRANSPORT_MODE",
    "TRUSTED_TRANSPORT_MODES",
    "TRUSTED_TRANSPORT_STATUSES",
    "TRUST_SCOPE_LABELS",
    "TRUST_STATUSES",
    "TrustedNodeTrustError",
    "TrustedTransportError",
    "build_approved_peer_record",
    "build_handshake_summary",
    "build_local_node_trust_profile",
    "build_replay_window_metadata",
    "build_transport_session_summary",
    "create_trusted_transport_session",
    "deterministic_transport_json",
    "deterministic_trust_json",
    "is_peer_approved",
    "summarize_trust_profile",
    "trusted_transport_session_from_dict",
    "trusted_transport_session_to_dict",
    "validate_approved_peer_record",
    "validate_local_node_trust_profile",
    "validate_trusted_transport_session",
]
