# SPDX-License-Identifier: Apache-2.0
"""Timeline visualization for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np


def lttb_downsample(
    data: np.ndarray,
    target_points: int,
) -> np.ndarray:
    """Largest Triangle Three Buckets downsampling.

    Preserves visual shape better than naive decimation.
    """
    if len(data) <= target_points:
        return data

    sampled = np.zeros(target_points)
    sampled[0] = data[0]
    sampled[-1] = data[-1]

    bucket_size = (len(data) - 2) / (target_points - 2)

    prev_index = 0
    for i in range(1, target_points - 1):
        bucket_start = int((i - 1) * bucket_size) + 1
        bucket_end = int(i * bucket_size) + 1
        bucket_end = min(bucket_end, len(data))

        next_bucket_start = int(i * bucket_size) + 1
        next_bucket_end = int((i + 1) * bucket_size) + 1
        next_bucket_end = min(next_bucket_end, len(data))

        avg_x = np.mean(np.arange(bucket_start, bucket_end))
        avg_y = np.mean(data[bucket_start:bucket_end])

        next_avg_x = np.mean(np.arange(next_bucket_start, next_bucket_end))
        next_avg_y = np.mean(data[next_bucket_start:next_bucket_end])

        max_area = -1
        max_index = bucket_start

        for j in range(bucket_start, bucket_end):
            area = abs(
                (avg_x - prev_index) * (data[j] - data[prev_index])
                - (prev_index - j) * (avg_y - data[prev_index])
            )
            if area > max_area:
                max_area = area
                max_index = j

        sampled[i] = data[max_index]
        prev_index = max_index

    return sampled


@dataclass
class TimelineTrack:
    """Timeline track data."""

    name: str
    timestamps: np.ndarray
    values: np.ndarray
    color: str = "#3b82f6"
    visible: bool = True


def create_timeline_tracks(
    risk_scores: np.ndarray,
    timestamps: np.ndarray,
    stage_probs: np.ndarray | None = None,
    detector_firings: np.ndarray | None = None,
    flow_volume: np.ndarray | None = None,
) -> list[TimelineTrack]:
    """Create timeline tracks for visualization.

    Args:
        risk_scores: Risk score values.
        timestamps: Timestamp values.
        stage_probs: Stage probability values.
        detector_firings: Detector firing values.
        flow_volume: Flow volume values.

    Returns:
        List of timeline tracks.
    """
    tracks = [
        TimelineTrack(
            name="Risk Score",
            timestamps=timestamps,
            values=risk_scores,
            color="#ef4444",
        )
    ]

    if stage_probs is not None:
        tracks.append(
            TimelineTrack(
                name="Stage Probability",
                timestamps=timestamps,
                values=stage_probs,
                color="#f59e0b",
            )
        )

    if detector_firings is not None:
        tracks.append(
            TimelineTrack(
                name="Detector Firings",
                timestamps=timestamps,
                values=detector_firings,
                color="#22c55e",
            )
        )

    if flow_volume is not None:
        tracks.append(
            TimelineTrack(
                name="Flow Volume",
                timestamps=timestamps,
                values=flow_volume,
                color="#3b82f6",
            )
        )

    return tracks
