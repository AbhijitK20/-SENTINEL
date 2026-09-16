from datetime import UTC, datetime, timedelta

import pytest

from trajectory.schemas import UnifiedEvent
from trajectory.state_builder import build_network_states

START = datetime(2026, 1, 1, tzinfo=UTC)


def event(offset: int, event_type: str, event_id: str) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=event_id,
        timestamp=START + timedelta(seconds=offset),
        source_entity="host-a",
        destination_entity="server-a",
        event_type=event_type,
        features={"bytes": 100.0, "ttl": 60.0},
        source_format="replay",
        provenance=f"replay:{event_id}",
    )


def test_states_sort_events_and_aggregate_coverage() -> None:
    states = build_network_states(
        [event(40, "packet", "packet-1"), event(0, "flow", "flow-1")],
        window_seconds=60,
        stride_seconds=60,
    )

    assert len(states) == 1
    assert states[0].source_ids == ["flow-1", "packet-1"]
    assert states[0].features["bytes_sum"] == 200
    assert states[0].features["event_count"] == 2
    assert states[0].coverage == {"flow": True, "packet": True}
    assert states[0].edge_summary[0]["count"] == 2


def test_rich_aggregations_produced() -> None:
    """S2-T1 AC1: ttl_var, iat_mean_mean, payload_size_p90 present when events carry those features."""
    base = datetime(2026, 1, 1, tzinfo=UTC)
    events = [
        UnifiedEvent(
            event_id=f"e{i}",
            timestamp=base + timedelta(seconds=i * 10),
            source_entity="a",
            destination_entity="b",
            event_type="flow",
            features={"bytes": 100.0, "ttl": float(64 + i), "iat_mean": float(i), "payload_size": float(50 + i)},
            source_format="replay",
            provenance=f"r:e{i}",
        )
        for i in range(5)
    ]
    states = build_network_states(events, window_seconds=60, stride_seconds=60)
    assert len(states) == 1
    f = states[0].features
    assert "bytes_sum" in f
    assert "bytes_mean" in f
    assert "bytes_std" in f
    assert "ttl_var" in f
    assert "iat_mean_mean" in f
    assert "payload_size_p90" in f
    assert "payload_size_entropy" in f


def test_absent_features_produce_no_key() -> None:
    """S2-T1 AC2: absent inputs produce absent keys, never 0.0."""
    states = build_network_states(
        [event(0, "flow", "f1")],
        window_seconds=60,
        stride_seconds=60,
    )
    assert len(states) == 1
    f = states[0].features
    assert "ttl_var" not in f
    assert "iat_mean_mean" not in f
    assert "payload_size_p90" not in f


def test_single_event_undefined_aggregations_absent() -> None:
    """S2-T1 AC3: single-event windows produce std/var as absent, not 0.0."""
    states = build_network_states(
        [event(0, "flow", "f1")],
        window_seconds=60,
        stride_seconds=60,
    )
    f = states[0].features
    assert "bytes_std" not in f
    assert "bytes_var" not in f
    assert "bytes_sum" in f
    assert "bytes_mean" in f


def test_overlapping_windows_include_event_in_each_matching_window() -> None:
    states = build_network_states(
        [event(40, "flow", "flow-1"), event(75, "packet", "packet-1")],
        window_seconds=60,
        stride_seconds=30,
    )

    assert len(states) == 2
    assert states[0].source_ids == ["flow-1", "packet-1"]
    assert states[1].source_ids == ["packet-1"]


def test_empty_windows_can_be_retained() -> None:
    states = build_network_states(
        [event(0, "flow", "flow-1"), event(120, "flow", "flow-2")],
        window_seconds=30,
        stride_seconds=30,
        include_empty=True,
    )

    assert len(states) == 5
    assert states[1].features["event_count"] == 0
    assert states[1].source_ids == []
    assert states[1].coverage == {"flow": False, "packet": False}


def test_invalid_window_configuration_is_rejected() -> None:
    with pytest.raises(ValueError, match="must be positive"):
        build_network_states([], window_seconds=0, stride_seconds=30)
