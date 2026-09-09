from datetime import UTC, datetime
from pathlib import Path

import pytest

pytest.importorskip("scapy")

from trajectory.pcap_ingestion import read_pcap


def test_pcap_extracts_packet_features(tmp_path: Path) -> None:
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Raw
    from scapy.utils import wrpcap

    path = tmp_path / "sample.pcap"
    packets = [
        IP(src="10.0.0.1", dst="10.0.0.2", ttl=61)
        / TCP(sport=40000, dport=443, flags="SA", window=4096, seq=1)
        / Raw(b"hello"),
        IP(src="10.0.0.1", dst="10.0.0.2", ttl=61)
        / TCP(sport=40000, dport=443, flags="SA", window=4096, seq=1)
        / Raw(b"hello"),
        IP(src="10.0.0.3", dst="10.0.0.4", ttl=64) / UDP(sport=50000, dport=53) / Raw(b"dns"),
    ]
    for packet in packets:
        packet.time = datetime(2026, 1, 1, tzinfo=UTC).timestamp()
    wrpcap(str(path), packets)

    result = read_pcap(path)

    assert result.coverage.total_packets == 3
    assert result.coverage.parsed_packets == 3
    assert result.events[0].features["ttl"] == 61
    assert result.events[0].features["tcp_window_size"] == 4096
    assert result.events[1].features["retransmission"] == 1
    assert result.events[2].features["source_port"] == 50000


def test_nonexistent_pcap_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="PCAP does not exist"):
        read_pcap(tmp_path / "missing.pcap")
