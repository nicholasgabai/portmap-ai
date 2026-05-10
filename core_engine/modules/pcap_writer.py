from __future__ import annotations

import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


PCAP_MAGIC_LITTLE_ENDIAN = 0xA1B2C3D4
PCAP_VERSION_MAJOR = 2
PCAP_VERSION_MINOR = 4
DEFAULT_SNAPLEN = 65535
LINKTYPE_ETHERNET = 1


@dataclass(frozen=True)
class PcapPacket:
    data: bytes
    timestamp: float | None = None
    original_length: int | None = None


def _coerce_packet(raw: bytes | bytearray | memoryview | PcapPacket) -> PcapPacket:
    if isinstance(raw, PcapPacket):
        return raw
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return PcapPacket(data=bytes(raw))
    raise TypeError("pcap packets must be bytes-like objects or PcapPacket instances")


def _packet_header(packet: PcapPacket, captured: bytes) -> bytes:
    timestamp = float(packet.timestamp if packet.timestamp is not None else time.time())
    seconds = int(timestamp)
    microseconds = int((timestamp - seconds) * 1_000_000)
    original_length = int(packet.original_length if packet.original_length is not None else len(packet.data))
    return struct.pack("<IIII", seconds, microseconds, len(captured), original_length)


def write_pcap(
    path: str | Path,
    packets: Iterable[bytes | bytearray | memoryview | PcapPacket],
    *,
    linktype: int = LINKTYPE_ETHERNET,
    snaplen: int = DEFAULT_SNAPLEN,
) -> dict[str, Any]:
    """Write a classic PCAP file using a small stdlib-only writer."""
    if snaplen <= 0:
        raise ValueError("pcap snaplen must be greater than 0")
    if linktype <= 0:
        raise ValueError("pcap linktype must be greater than 0")

    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    packet_count = 0
    payload_bytes = 0
    with open(output_path, "wb") as handle:
        handle.write(
            struct.pack(
                "<IHHIIII",
                PCAP_MAGIC_LITTLE_ENDIAN,
                PCAP_VERSION_MAJOR,
                PCAP_VERSION_MINOR,
                0,
                0,
                snaplen,
                linktype,
            )
        )
        for raw_packet in packets:
            packet = _coerce_packet(raw_packet)
            captured = bytes(packet.data[:snaplen])
            handle.write(_packet_header(packet, captured))
            handle.write(captured)
            packet_count += 1
            payload_bytes += len(captured)

    return {
        "path": str(output_path),
        "packets_written": packet_count,
        "payload_bytes": payload_bytes,
        "file_bytes": output_path.stat().st_size,
        "linktype": linktype,
        "snaplen": snaplen,
    }


__all__ = [
    "DEFAULT_SNAPLEN",
    "LINKTYPE_ETHERNET",
    "PcapPacket",
    "write_pcap",
]
