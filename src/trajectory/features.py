"""Turn network states into fixed-width, leakage-safe feature vectors."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from trajectory.schemas import NetworkState

FEATURE_VERSION = "state-features-v1"

# Names that can never be model inputs regardless of configuration.
FORBIDDEN_FEATURE_NAMES = frozenset(
    {"infiltration", "attack_stage", "scenario_id", "target_infiltration", "target_stage"}
)


class FeatureSchema(BaseModel):
    """Ordered feature names plus training-only normalization statistics."""

    model_config = ConfigDict(extra="forbid")

    version: str = FEATURE_VERSION
    names: list[str] = Field(min_length=1)
    excluded: list[str] = Field(default_factory=list)
    means: list[float]
    scales: list[float]
    missing_value: float = 0.0

    @property
    def width(self) -> int:
        return len(self.names)


def fit_feature_schema(
    training_states: Sequence[NetworkState],
    *,
    excluded_features: Iterable[str] = (),
) -> FeatureSchema:
    """Derive the eligible feature list and z-score statistics from training states only."""
    if not training_states:
        raise ValueError("cannot fit a feature schema without training states")

    excluded = set(excluded_features) | FORBIDDEN_FEATURE_NAMES
    names: set[str] = set()
    for state in training_states:
        names.update(state.features)
    eligible = sorted(names - excluded)
    if not eligible:
        raise ValueError("no eligible features remain after exclusions")

    raw = _raw_matrix(training_states, eligible, missing_value=0.0)
    means = raw.mean(axis=0)
    scales = raw.std(axis=0)
    scales[scales == 0.0] = 1.0  # constant columns stay constant instead of dividing by zero
    return FeatureSchema(
        names=eligible,
        excluded=sorted(excluded & names),
        means=means.tolist(),
        scales=scales.tolist(),
    )


def vectorize_states(states: Sequence[NetworkState], schema: FeatureSchema) -> np.ndarray:
    """Vectorize states using a fitted schema; unseen feature names are ignored."""
    if not states:
        return np.empty((0, schema.width), dtype=float)
    raw = _raw_matrix(states, schema.names, missing_value=schema.missing_value)
    return (raw - np.asarray(schema.means)) / np.asarray(schema.scales)


def _raw_matrix(
    states: Sequence[NetworkState], names: Sequence[str], *, missing_value: float
) -> np.ndarray:
    matrix = np.full((len(states), len(names)), missing_value, dtype=float)
    for row, state in enumerate(states):
        for column, name in enumerate(names):
            value = state.features.get(name)
            if value is not None:
                matrix[row, column] = value
    return matrix
