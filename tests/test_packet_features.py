"""Packet-level telemetry must actually reach the model.

The problem statement lists TTL spread, TCP window size, IP fragment flags,
payload distribution, and retransmission counts as required inputs. Two of those
had no live path at all: the fragment features read a key the PCAP adapter never
emits, and the retransmission and fragment-offset helpers were implemented but
never called. These tests pin the wiring so they cannot silently go dead again.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel.feature_computes.packets import (
    frag_df_share,
    frag_mf_share,
    frag_offset_nunique,
    retransmission_count,
    retransmission_rate,
)
from sentinel.schemas import UnifiedEvent
from sentinel.state_builder import (
    FEATURE_VERSION,
    RAW_ONLY_FEATURES,
    build_network_states,
)

START = datetime(2026, 1, 1, tzinfo=UTC)
DF = 0x4000
MF = 0x2000


def _packet(index: int, seconds: int, features: dict[str, float]) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=f"p{index}",
        timestamp=START + timedelta(seconds=seconds),
        source_entity="10.0.0.1",
        destination_entity="10.0.0.2",
        event_type="packet",
        features=features,
        source_format="pcap",
        provenance="test",
    )


def _window(events: list[UnifiedEvent]):
    states = build_network_states(events, window_seconds=60, stride_seconds=30)
    return states[0]


def test_fragment_features_read_the_pcap_key() -> None:
    """Regression: the state builder read `ip_flags`; the PCAP adapter writes
    `fragment_flags`, so real captures silently produced 0.0 for both shares."""
    events = [
        _packet(0, 0, {"fragment_flags": float(DF)}),
        _packet(1, 1, {"fragment_flags": float(DF | MF)}),
        _packet(2, 2, {"fragment_flags": 0.0}),
    ]
    features = _window(events).features

    assert features["frag_df_share"] == pytest.approx(2 / 3)
    assert features["frag_mf_share"] == pytest.approx(1 / 3)


def test_fragment_features_still_accept_the_legacy_key() -> None:
    features = _window([_packet(0, 0, {"ip_flags": float(DF)})]).features
    assert features["frag_df_share"] == pytest.approx(1.0)


def test_retransmissions_are_counted_and_rated() -> None:
    events = [
        _packet(index, index, {"retransmission": 1.0 if index % 2 == 0 else 0.0})
        for index in range(4)
    ]
    features = _window(events).features

    assert features["retransmission_count"] == 2.0
    assert features["retransmission_rate"] == pytest.approx(0.5)
    assert features["retransmission_sum"] == 2.0
    assert features["retransmission_mean"] == pytest.approx(0.5)


def test_fragment_offsets_are_counted() -> None:
    events = [
        _packet(0, 0, {"frag_offset": 0.0}),
        _packet(1, 1, {"frag_offset": 1480.0}),
        _packet(2, 2, {"frag_offset": 1480.0}),
    ]
    assert _window(events).features["frag_offset_nunique"] == 2.0


def test_raw_header_values_never_reach_the_generic_sum() -> None:
    """Summing an IP flags word or a fragment offset would be meaningless."""
    assert {"fragment_flags", "ip_flags", "frag_offset"} <= RAW_ONLY_FEATURES
    features = _window(
        [
            _packet(index, index, {"fragment_flags": float(DF), "frag_offset": 1480.0})
            for index in range(3)
        ]
    ).features

    assert "fragment_flags" not in features
    assert "frag_offset" not in features
    assert features["frag_df_share"] == pytest.approx(1.0)


def test_absent_packet_features_are_explicit_zeros_not_missing_keys() -> None:
    features = _window([_packet(0, 0, {"payload_size": 100.0})]).features

    for name in ("frag_df_share", "frag_mf_share", "frag_offset_nunique"):
        assert features[name] == 0.0
    assert features["retransmission_count"] == 0.0
    assert features["retransmission_rate"] == 0.0


def test_feature_version_moved_with_the_new_features() -> None:
    assert FEATURE_VERSION == "state-features-v4"


def test_helpers_handle_empty_input_without_inventing_evidence() -> None:
    assert frag_df_share([]) is None
    assert frag_mf_share([]) is None
    assert frag_offset_nunique([]) is None
    assert retransmission_count([]) == 0
    assert retransmission_rate([]) is None


def test_ip_flags_word_is_the_wire_bitmask_not_the_enum_ordinal() -> None:
    """Regression: scapy's FlagValue int() is 1 for MF and 2 for DF, while the
    fragmentation features test 0x2000 / 0x4000. Reading the ordinal made every
    real capture report a fragment bit that was never set."""
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP

    from sentinel.pcap_ingestion import _ip_flags_word

    assert _ip_flags_word(IP(src="1.1.1.1", dst="2.2.2.2", flags="MF")) == float(MF)
    assert _ip_flags_word(IP(src="1.1.1.1", dst="2.2.2.2", flags="DF")) == float(DF)
    assert _ip_flags_word(IP(src="1.1.1.1", dst="2.2.2.2", flags="MF+DF")) == float(MF | DF)
    assert _ip_flags_word(IP(src="1.1.1.1", dst="2.2.2.2")) == 0.0


def test_pcap_adapter_maps_every_packet_header_field() -> None:
    """Header → feature mapping, tested without the file round-trip.

    Scapy's writer is unreliable without a libpcap provider (packets carrying a
    fragment offset come back truncated), so this pins the mapping directly;
    ``test_pcap_ingestion`` covers the file round-trip.
    """
    pytest.importorskip("scapy")
    from scapy.layers.inet import IP, TCP
    from scapy.packet import Raw

    from sentinel.pcap_ingestion import _packet_to_event

    packet = (
        IP(src="10.0.0.1", dst="10.0.0.2", ttl=57, flags="MF", frag=1480)
        / TCP(sport=40000, dport=445, flags="SA", window=1024, seq=1)
        / Raw(b"x")
    )
    packet.time = START.timestamp()

    event = _packet_to_event(packet, Path("capture.pcap"), 1, set())
    assert event is not None
    assert event.event_type == "packet"
    assert event.features["ttl"] == 57
    assert event.features["tcp_window_size"] == 1024
    assert event.features["fragment_flags"] == float(MF)
    assert event.features["frag_offset"] == 1480.0
    assert event.features["destination_port"] == 445.0
    assert "retransmission" in event.features


def test_pcap_coverage_advertises_the_computed_packet_features() -> None:
    from sentinel.pcap_ingestion import PacketCoverage

    coverage = PacketCoverage(
        total_packets=1,
        parsed_packets=1,
        skipped_packets=0,
        packet_features=("ttl", "frag_offset", "retransmission"),
        warnings=(),
    )
    assert set(coverage.packet_features) >= {"ttl", "frag_offset", "retransmission"}
