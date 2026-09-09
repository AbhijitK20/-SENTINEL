"""PCAP ingestion and packet-level feature extraction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from trajectory.schemas import UnifiedEvent

try:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Packet
    from scapy.utils import PcapReader
except ImportError:  # pragma: no cover - exercised through the dependency error path
    IP = TCP = UDP = IPv6 = Packet = PcapReader = None  # type: ignore[assignment,misc]


@dataclass(frozen=True)
class PacketCoverage:
    """Feature availability and parser statistics for one PCAP."""

    total_packets: int
    parsed_packets: int
    skipped_packets: int
    packet_features: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class PcapIngestionResult:
    """Normalized packet events and coverage metadata."""

    events: tuple[UnifiedEvent, ...]
    coverage: PacketCoverage


def read_pcap(path: str | Path) -> PcapIngestionResult:
    """Read an IPv4/IPv6 PCAP and extract packet-level features."""
    if PcapReader is None:
        raise RuntimeError("PCAP support requires the optional dependency: uv sync --extra pcap")

    pcap_path = Path(path)
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP does not exist: {pcap_path}")

    events: list[UnifiedEvent] = []
    warnings: list[str] = []
    seen_tcp_sequences: set[tuple[str, str, int, int, int]] = set()
    total_packets = 0
    skipped_packets = 0

    try:
        reader = PcapReader(str(pcap_path))
        for packet in reader:
            total_packets += 1
            event = _packet_to_event(packet, pcap_path, total_packets, seen_tcp_sequences)
            if event is None:
                skipped_packets += 1
                continue
            events.append(event)
        reader.close()
    except Exception as error:
        raise ValueError(f"Unable to parse PCAP '{pcap_path}': {error}") from error

    if total_packets == 0:
        warnings.append("PCAP contains no packets")
    if skipped_packets:
        warnings.append(f"Skipped {skipped_packets} packets without an IP layer")

    return PcapIngestionResult(
        events=tuple(events),
        coverage=PacketCoverage(
            total_packets=total_packets,
            parsed_packets=len(events),
            skipped_packets=skipped_packets,
            packet_features=(
                "ttl",
                "tcp_window_size",
                "fragment_flags",
                "payload_size",
                "retransmission",
                "tcp_flags",
            ),
            warnings=tuple(warnings),
        ),
    )


def _packet_to_event(
    packet: Packet,
    pcap_path: Path,
    packet_number: int,
    seen_tcp_sequences: set[tuple[str, str, int, int, int]],
) -> UnifiedEvent | None:
    if IP is None or IPv6 is None or not (packet.haslayer(IP) or packet.haslayer(IPv6)):
        return None

    ip_layer = packet[IP] if packet.haslayer(IP) else packet[IPv6]
    source = str(ip_layer.src)
    destination = str(ip_layer.dst)
    protocol = int(ip_layer.proto) if hasattr(ip_layer, "proto") else 0
    features: dict[str, float] = {
        "ttl": float(getattr(ip_layer, "ttl", getattr(ip_layer, "hlim", 0))),
        "fragment_flags": float(getattr(getattr(ip_layer, "flags", 0), "value", 0)),
        "payload_size": float(len(bytes(packet.payload))),
        "tcp_window_size": 0.0,
        "tcp_flags": 0.0,
        "retransmission": 0.0,
    }
    source_port = 0
    destination_port = 0

    if TCP is not None and packet.haslayer(TCP):
        tcp = packet[TCP]
        source_port = int(tcp.sport)
        destination_port = int(tcp.dport)
        features["tcp_window_size"] = float(tcp.window)
        features["tcp_flags"] = float(_tcp_flag_mask(str(tcp.flags)))
        sequence_key = (source, destination, source_port, destination_port, int(tcp.seq))
        if sequence_key in seen_tcp_sequences:
            features["retransmission"] = 1.0
        seen_tcp_sequences.add(sequence_key)
    elif UDP is not None and packet.haslayer(UDP):
        udp = packet[UDP]
        source_port = int(udp.sport)
        destination_port = int(udp.dport)

    return UnifiedEvent(
        event_id=f"{pcap_path.name}:packet-{packet_number}",
        timestamp=_packet_timestamp(packet),
        source_entity=source,
        destination_entity=destination,
        event_type="packet",
        features={
            **features,
            "protocol": float(protocol),
            "source_port": float(source_port),
            "destination_port": float(destination_port),
        },
        source_format="pcap",
        provenance=f"{pcap_path}:packet-{packet_number}",
    )


def _packet_timestamp(packet: Packet):
    from datetime import UTC, datetime

    return datetime.fromtimestamp(float(packet.time), tz=UTC)


def _tcp_flag_mask(value: str) -> int:
    bits = {"F": 1, "S": 2, "R": 4, "P": 8, "A": 16, "U": 32}
    return sum(bits[flag] for flag in value if flag in bits)
