"""Metadata-only packet capture framework foundation."""

from .adapters import BaseCaptureAdapter, MockCaptureAdapter, PcapFileMetadataAdapter
from .filters import CaptureFilter, build_capture_filter, validate_capture_filter
from .manager import CaptureManager
from .models import CaptureSession, PacketMetadata, build_flow_key, packet_from_dict, session_from_dict
from .statistics import summarize_packets, summarize_session

__all__ = [
    "BaseCaptureAdapter",
    "CaptureFilter",
    "CaptureManager",
    "CaptureSession",
    "MockCaptureAdapter",
    "PacketMetadata",
    "PcapFileMetadataAdapter",
    "build_capture_filter",
    "build_flow_key",
    "packet_from_dict",
    "session_from_dict",
    "summarize_packets",
    "summarize_session",
    "validate_capture_filter",
]
