"""Local metadata-only capture manager."""

from __future__ import annotations

from typing import Any, Dict, List

from .adapters import BaseCaptureAdapter, MockCaptureAdapter, PcapFileMetadataAdapter
from .filters import build_capture_filter
from .models import CaptureSession, PacketMetadata
from .statistics import summarize_packets, summarize_session


class CaptureManager:
    def __init__(self, adapters: List[BaseCaptureAdapter] | None = None) -> None:
        self.adapters: Dict[str, BaseCaptureAdapter] = {}
        self.sessions: Dict[str, CaptureSession] = {}
        self.session_packets: Dict[str, List[PacketMetadata]] = {}
        for adapter in adapters or [MockCaptureAdapter(), PcapFileMetadataAdapter()]:
            self.register_adapter(adapter)

    def register_adapter(self, adapter: BaseCaptureAdapter) -> None:
        self.adapters[adapter.adapter_name] = adapter

    def list_adapters(self) -> List[Dict[str, Any]]:
        return [
            {"adapter_name": name, "platform_support": list(self.adapters[name].platform_support)}
            for name in sorted(self.adapters)
        ]

    def _adapter(self, adapter_name: str) -> BaseCaptureAdapter:
        try:
            return self.adapters[adapter_name]
        except KeyError as exc:
            raise ValueError(f"unknown_capture_adapter:{adapter_name}") from exc

    def list_interfaces(self, adapter_name: str = "mock") -> List[Dict[str, Any]]:
        return self._adapter(adapter_name).list_interfaces()

    def create_session(
        self,
        *,
        interface: str = "-",
        adapter_name: str = "mock",
        filter_expression: str = "all",
        filter_mode: str = "preset",
        started_at: Any = "-",
        capture_path: Any = "-",
        metadata: Dict[str, Any] | None = None,
    ) -> CaptureSession:
        capture_filter = build_capture_filter(filter_expression, mode=filter_mode)
        if not capture_filter.valid:
            raise ValueError(capture_filter.reason)
        session = CaptureSession.create(
            interface=interface,
            adapter=adapter_name,
            filter_expression=capture_filter.expression,
            filter_mode=filter_mode,
            started_at=started_at,
            capture_path=capture_path,
            metadata={**(metadata or {}), "filter": capture_filter.to_dict()},
        )
        self.sessions[session.session_id] = session
        self.session_packets[session.session_id] = []
        return session

    def start_session(self, session_id: str) -> CaptureSession:
        session = self.sessions[session_id]
        updated = self._adapter(session.adapter).start_session(session)
        self.sessions[session_id] = updated
        return updated

    def pause_session(self, session_id: str) -> CaptureSession:
        session = self.sessions[session_id]
        updated = self._adapter(session.adapter).pause_session(session)
        self.sessions[session_id] = updated
        return updated

    def resume_session(self, session_id: str) -> CaptureSession:
        session = self.sessions[session_id]
        updated = self._adapter(session.adapter).resume_session(session)
        self.sessions[session_id] = updated
        return updated

    def stop_session(self, session_id: str) -> CaptureSession:
        session = self.sessions[session_id]
        updated = self._adapter(session.adapter).stop_session(session)
        self.sessions[session_id] = updated
        return updated

    def add_packet_metadata(self, session_id: str, packet: Dict[str, Any] | PacketMetadata) -> PacketMetadata:
        session = self.sessions[session_id]
        metadata = PacketMetadata.from_dict({**PacketMetadata.from_dict(packet).to_dict(), "session_id": session_id})
        self.session_packets.setdefault(session_id, []).append(metadata)
        self.sessions[session_id] = session.add_packets([metadata])
        return metadata

    def import_packets(self, *, adapter_name: str = "mock", source: Any = None, interface: str = "imported") -> Dict[str, Any]:
        adapter = self._adapter(adapter_name)
        packets = adapter.import_packets(source)
        session = CaptureSession.create(
            interface=interface,
            adapter=adapter_name,
            filter_expression="all",
            filter_mode="preset",
            capture_path=source or "-",
            metadata={"import_source": str(source or adapter_name)},
        ).transition("imported")
        session = session.add_packets(packets)
        self.sessions[session.session_id] = session
        self.session_packets[session.session_id] = [
            PacketMetadata.from_dict({**packet.to_dict(), "session_id": session.session_id}) for packet in packets
        ]
        return self.session_summary(session.session_id)

    def session_summary(self, session_id: str) -> Dict[str, Any]:
        return summarize_session(self.sessions[session_id], self.session_packets.get(session_id, []))

    def capture_statistics(self, session_id: str | None = None) -> Dict[str, Any]:
        if session_id is not None:
            return summarize_packets(self.session_packets.get(session_id, []))
        packets = [packet for values in self.session_packets.values() for packet in values]
        return summarize_packets(packets)

    def list_sessions(self) -> List[Dict[str, Any]]:
        return [self.session_summary(session_id) for session_id in sorted(self.sessions)]
