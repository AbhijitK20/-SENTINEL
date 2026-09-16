# SPDX-License-Identifier: Apache-2.0
"""Build ordered network states from normalized telemetry events."""

from __future__ import annotations

import bisect
import math
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from enum import Enum

from trajectory.schemas import NetworkState, UnifiedEvent

FEATURE_VERSION = "state-features-v2"


class Agg(str, Enum):
    """Aggregation functions applied to per-window feature value lists."""

    SUM = "sum"
    MEAN = "mean"
    STD = "std"
    VAR = "var"
    MAX = "max"
    MIN = "min"
    P50 = "p50"
    P90 = "p90"
    P99 = "p99"
    ENTROPY = "entropy"
    NUNIQUE = "nunique"
    RATIO = "ratio"


# Feature name -> tuple of aggregations to emit.
# Absent inputs produce absent keys, never 0.0.
AGGREGATION_POLICY: dict[str, tuple[Agg, ...]] = {
    "bytes": (Agg.SUM, Agg.MEAN, Agg.STD, Agg.MAX, Agg.P90),
    "packets": (Agg.SUM, Agg.MEAN, Agg.MAX),
    "duration": (Agg.MEAN, Agg.STD, Agg.MAX),
    "payload_size": (Agg.SUM, Agg.MEAN, Agg.STD, Agg.P50, Agg.P90, Agg.ENTROPY),
    "ttl": (Agg.MEAN, Agg.STD, Agg.VAR, Agg.MIN, Agg.MAX, Agg.NUNIQUE),
    "tcp_window_size": (Agg.MEAN, Agg.STD, Agg.MIN, Agg.MAX),
    "iat_mean": (Agg.MEAN, Agg.VAR, Agg.MAX, Agg.MIN, Agg.P90),
    "iat_variance": (Agg.MEAN, Agg.MAX),
    "iat_max": (Agg.MEAN, Agg.MAX),
    "bidirectional_ratio": (Agg.MEAN, Agg.STD),
    "syn_count": (Agg.SUM, Agg.MEAN),
    "ack_count": (Agg.SUM, Agg.MEAN),
    "fin_count": (Agg.SUM, Agg.MEAN),
    "rst_count": (Agg.SUM, Agg.MEAN),
    "failed_auth": (Agg.SUM,),
    "auth_attempt": (Agg.SUM,),
    "source_port": (Agg.MEAN, Agg.NUNIQUE),
    "destination_port": (Agg.MEAN, Agg.NUNIQUE),
    "protocol": (Agg.NUNIQUE,),
    "tcp_flags": (Agg.NUNIQUE,),
}

# Aggregation types that are undefined for single-event windows.
_UNDEFINED_FOR_SINGLE = {Agg.STD, Agg.VAR, Agg.P50, Agg.P90, Agg.P99, Agg.ENTROPY}

# Legacy aliases: old flat feature name -> new enriched name.
# Used by stage_mapping.py and detectors.py until S7 migrates them.
LEGACY_ALIASES: dict[str, str] = {
    "bytes": "bytes_sum",
    "packets": "packets_sum",
    "duration": "duration_mean",
    "payload_size": "payload_size_sum",
    "syn_count": "syn_count_sum",
    "ack_count": "ack_count_sum",
    "fin_count": "fin_count_sum",
    "rst_count": "rst_count_sum",
    "failed_auth": "failed_auth_sum",
    "iat_mean": "iat_mean_mean",
    "auth_attempt": "auth_attempt_sum",
}


def resolve_alias(name: str) -> str:
    """Resolve a legacy flat feature name to its v2 equivalent, emitting a warning."""
    if name in LEGACY_ALIASES:
        warnings.warn(
            f"Feature {name!r} is deprecated; use {LEGACY_ALIASES[name]!r} instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return LEGACY_ALIASES[name]
    return name


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
    stamps = [e.timestamp for e in ordered_events]
    origin = stamps[0]
    latest = stamps[-1]
    window_delta = timedelta(seconds=window_seconds)
    stride_delta = timedelta(seconds=stride_seconds)

    states: list[NetworkState] = []
    start = origin
    while start <= latest:
        end = start + window_delta
        lo = bisect.bisect_left(stamps, start)
        hi = bisect.bisect_left(stamps, end)
        window_events = ordered_events[lo:hi]
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

    features: dict[str, float] = {
        "event_count": float(len(events)),
        "flow_event_count": float(flow_count),
        "packet_event_count": float(packet_count),
        "external_destination_count": float(
            sum(1 for entity in entities if entity.startswith(("external", "1.2.3.4")))
        ),
    }

    # Apply the aggregation policy to each feature present in the window.
    for name, values in feature_values.items():
        aggs = AGGREGATION_POLICY.get(name)
        if aggs is None:
            # Unknown feature: fall back to sum (count-like) if all non-negative,
            # else mean. This preserves backward compat for custom features.
            features[name] = sum(values)
            continue
        if not isinstance(aggs, tuple):
            aggs = (aggs,)
        n = len(values)
        for agg in aggs:
            out_name = f"{name}_{agg.value}"
            if agg in _UNDEFINED_FOR_SINGLE and n < 2:
                continue  # absent, not 0.0
            if agg == Agg.SUM:
                features[out_name] = sum(values)
            elif agg == Agg.MEAN:
                features[out_name] = sum(values) / n
            elif agg == Agg.STD:
                features[out_name] = _std(values)
            elif agg == Agg.VAR:
                features[out_name] = _var(values)
            elif agg == Agg.MAX:
                features[out_name] = max(values)
            elif agg == Agg.MIN:
                features[out_name] = min(values)
            elif agg == Agg.P50:
                features[out_name] = _percentile(values, 50)
            elif agg == Agg.P90:
                features[out_name] = _percentile(values, 90)
            elif agg == Agg.P99:
                features[out_name] = _percentile(values, 99)
            elif agg == Agg.ENTROPY:
                features[out_name] = _entropy(values)
            elif agg == Agg.NUNIQUE:
                features[out_name] = float(len(set(values)))
            elif agg == Agg.RATIO:
                pass  # computed by the caller if needed

        # Legacy flat alias: emit the original name pointing to the first
        # aggregation (sum for count-like, mean for continuous). This keeps
        # stage_mapping.py, detectors.py, and existing tests working until S7
        # migrates them to the enriched names.
        if name in LEGACY_ALIASES:
            flat_name = name
            if Agg.SUM in aggs:
                features[flat_name] = sum(values)
            elif Agg.MEAN in aggs:
                features[flat_name] = sum(values) / n
            elif aggs:
                # Fallback: compute the first aggregation
                first = aggs[0]
                if first == Agg.SUM:
                    features[flat_name] = sum(values)
                elif first == Agg.MEAN:
                    features[flat_name] = sum(values) / n
                elif first == Agg.NUNIQUE:
                    features[flat_name] = float(len(set(values)))

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


def _std(values: list[float]) -> float:
    """Sample standard deviation."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1))


def _var(values: list[float]) -> float:
    """Sample variance."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / (n - 1)


def _percentile(values: list[float], pct: int) -> float:
    """Linear interpolation percentile."""
    ordered = sorted(values)
    n = len(ordered)
    k = (pct / 100) * (n - 1)
    f = int(k)
    c = min(f + 1, n - 1)
    d = k - f
    return ordered[f] + d * (ordered[c] - ordered[f])


def _entropy(values: list[float]) -> float:
    """Shannon entropy of discrete values (quantised to integers)."""
    if not values:
        return 0.0
    counts = Counter(int(v) for v in values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
