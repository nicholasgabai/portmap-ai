"""Deterministic metadata-only capture adapters."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Protocol

from .models import CaptureSession, PacketMetadata, _stable_id


class BaseCaptureAdapter(Protocol):
    adapter_name: str
    platform_support: tuple[str, ...]

    def list_interfaces(self) -> List[Dict[str, Any]]:
        ...

    def start_session(self, session: CaptureSession) -> CaptureSession:
        ...

    def pause_session(self, session: CaptureSession) -> CaptureSession:
        ...

    def resume_session(self, session: CaptureSession) -> CaptureSession:
        ...

    def stop_session(self, session: CaptureSession) -> CaptureSession:
        ...

    def import_packets(self, source: Any) -> List[PacketMetadata]:
        ...


class MockCaptureAdapter:
    adapter_name = "mock"
    platform_support = ("darwin", "linux", "windows", "test")

    def __init__(
        self,
        *,
        interfaces: Iterable[Dict[str, Any]] | None = None,
        packets: Iterable[Dict[str, Any] | PacketMetadata] | None = None,
    ) -> None:
        self._interfaces = list(
            interfaces
            or [
                {"name": "mock0", "description": "Mock interface 0", "status": "available"},
                {"name": "mock1", "description": "Mock interface 1", "status": "available"},
            ]
        )
        self._packets = [PacketMetadata.from_dict(packet) for packet in (packets or _default_mock_packets())]

    def list_interfaces(self) -> List[Dict[str, Any]]:
        return sorted((dict(item) for item in self._interfaces), key=lambda item: item.get("name", ""))

    def start_session(self, session: CaptureSession) -> CaptureSession:
        return session.transition("running", at=session.started_at)

    def pause_session(self, session: CaptureSession) -> CaptureSession:
        return session.transition("paused")

    def resume_session(self, session: CaptureSession) -> CaptureSession:
        return session.transition("running")

    def stop_session(self, session: CaptureSession) -> CaptureSession:
        return session.transition("stopped")

    def import_packets(self, source: Any = None) -> List[PacketMetadata]:
        source_tag = str(source or "mock")
        return [
            PacketMetadata.from_dict(
                {
                    **packet.to_dict(),
                    "tags": [*packet.tags, "mock_import"],
                    "metadata": {**packet.metadata, "source": source_tag},
                }
            )
            for packet in self._packets
        ]


class PcapFileMetadataAdapter:
    adapter_name = "pcap_file_metadata"
    platform_support = ("darwin", "linux", "windows", "test")

    def list_interfaces(self) -> List[Dict[str, Any]]:
        return [{"name": "offline_file", "description": "Offline capture metadata import", "status": "available"}]

    def start_session(self, session: CaptureSession) -> CaptureSession:
        return session.transition("imported", at=session.started_at)

    def pause_session(self, session: CaptureSession) -> CaptureSession:
        return session

    def resume_session(self, session: CaptureSession) -> CaptureSession:
        return session

    def stop_session(self, session: CaptureSession) -> CaptureSession:
        return session.transition("stopped")

    def import_packets(self, source: Any) -> List[PacketMetadata]:
        path = Path(str(source)).expanduser()
        if not path.exists():
            raise FileNotFoundError(str(path))
        stat = path.stat()
        return [
            PacketMetadata.from_dict(
                {
                    "packet_id": _stable_id("packet", {"path": str(path), "size": stat.st_size}),
                    "observed_at": str(int(stat.st_mtime)),
                    "interface": "offline_file",
                    "direction": "imported",
                    "length": stat.st_size,
                    "captured_length": stat.st_size,
                    "link_type": "pcap_file",
                    "protocol": "OFFLINE",
                    "tags": ["offline_import", "metadata_only"],
                    "metadata": {
                        "source_path": str(path),
                        "file_name": path.name,
                        "parser": "metadata_only",
                    },
                }
            )
        ]


def _default_mock_packets() -> List[Dict[str, Any]]:
    return [
        {
            "observed_at": "2026-06-14T12:00:00+00:00",
            "interface": "mock0",
            "direction": "outbound",
            "length": 60,
            "captured_length": 60,
            "eth_src": "aa:bb:cc:dd:ee:ff",
            "eth_dst": "11:22:33:44:55:66",
            "ether_type": "0x0800",
            "ip_version": 4,
            "src_ip": "192.168.1.10",
            "dst_ip": "203.0.113.10",
            "ttl": 64,
            "protocol": "TCP",
            "src_port": 51515,
            "dst_port": 443,
            "tcp_flags": ["SYN"],
            "payload_length": 0,
            "tags": ["fixture"],
        },
        {
            "observed_at": "2026-06-14T12:00:01+00:00",
            "interface": "mock0",
            "direction": "outbound",
            "length": 72,
            "captured_length": 72,
            "eth_src": "aa:bb:cc:dd:ee:ff",
            "eth_dst": "11:22:33:44:55:66",
            "ether_type": "0x0800",
            "ip_version": 4,
            "src_ip": "192.168.1.10",
            "dst_ip": "203.0.113.53",
            "ttl": 64,
            "protocol": "UDP",
            "src_port": 5353,
            "dst_port": 53,
            "payload_length": 0,
            "tags": ["fixture"],
        },
    ]
