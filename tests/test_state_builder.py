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
    assert states[0].features["bytes"] == 200
    assert states[0].features["event_count"] == 2
    assert states[0].coverage == {"flow": True, "packet": True}
    assert states[0].edge_summary[0]["count"] == 2


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
