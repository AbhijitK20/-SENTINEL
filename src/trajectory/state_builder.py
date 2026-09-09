"""Build ordered network states from normalized telemetry events."""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from trajectory.schemas import NetworkState, UnifiedEvent

SUM_FEATURES = {
    "bytes",
    "packets",
    "payload_size",
    "retransmission",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
}


def build_network_states(
    events: tuple[UnifiedEvent, ...] | list[UnifiedEvent],
    *,
    window_seconds: int,
    stride_seconds: int,
    include_empty: bool = False,
) -> tuple[NetworkState, ...]:
    """Aggregate events into ordered, possibly overlapping time windows.

    Windows are half-open intervals ``[start, end)`` anchored to the earliest
    event. An event belongs to every window that contains its timestamp, which
    supports a stride shorter than the window duration without losing events.
    """
    if window_seconds <= 0 or stride_seconds <= 0:
        raise ValueError("window_seconds and stride_seconds must be positive")
    if not events:
        return ()

    ordered_events = sorted(events, key=lambda event: event.timestamp)
    origin = ordered_events[0].timestamp
    latest = ordered_events[-1].timestamp
    window_delta = timedelta(seconds=window_seconds)
    stride_delta = timedelta(seconds=stride_seconds)

    states: list[NetworkState] = []
    start = origin
    while start <= latest:
        end = start + window_delta
        window_events = [event for event in ordered_events if start <= event.timestamp < end]
        if window_events or include_empty:
            states.append(_build_state(start, end, window_events))
        start += stride_delta
    return tuple(states)


def _build_state(
    start: datetime,
    end: datetime,
    events: list[UnifiedEvent],
) -> NetworkState:
    feature_values: dict[str, list[float]] = defaultdict(list)
    entities: set[str] = set()
    edges: dict[tuple[str, str], dict[str, float]] = defaultdict(
        lambda: {"count": 0.0, "bytes": 0.0}
    )
    source_ids: list[str] = []
    flow_count = 0
    packet_count = 0

    for event in events:
        source_ids.append(event.event_id)
        entities.update((event.source_entity, event.destination_entity))
        if event.event_type == "flow":
            flow_count += 1
        elif event.event_type == "packet":
            packet_count += 1
        for name, value in event.features.items():
            feature_values[name].append(value)
        edge = edges[(event.source_entity, event.destination_entity)]
        edge["count"] += 1
        edge["bytes"] += event.features.get("bytes", event.features.get("payload_size", 0.0))

    features = {
        "event_count": float(len(events)),
        "flow_event_count": float(flow_count),
        "packet_event_count": float(packet_count),
    }
    for name, values in feature_values.items():
        features[name] = sum(values) if name in SUM_FEATURES else sum(values) / len(values)

    edge_summary = [
        {
            "source": source,
            "destination": destination,
            "count": values["count"],
            "bytes": values["bytes"],
        }
        for (source, destination), values in sorted(edges.items())
    ]
    return NetworkState(
        window_start=start,
        window_end=end,
        features=features,
        entities=sorted(entities),
        edge_summary=edge_summary,
        coverage={"flow": flow_count > 0, "packet": packet_count > 0},
        source_ids=source_ids,
    )
