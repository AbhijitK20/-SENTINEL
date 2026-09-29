# SPDX-License-Identifier: Apache-2.0
"""Turn network states into fixed-width, leakage-safe feature vectors.

**Missing telemetry is imputed in z-space, at zero.** This is a load-bearing
detail and it was wrong until 2026-09-29.

The previous implementation filled an absent feature with ``0.0`` in *raw*
space and then standardized it, so a missing feature landed at
``(0 - mean) / scale``. Because network features are large and tightly
concentrated, that is not a small offset. Measured against the committed
release bundle's own schema:

    payload_size_p90    train mean 1459.0, sd 14.0  ->  z = -104.47
    ttl_max             train mean   64.0, sd  1.0  ->  z =  -64.00
    tcp_window_size_max train mean 65354.9          ->  z =  -33.81

Sixteen of the 98 features exceeded 5 sigma when missing and three exceeded 50.
This is reachable, not hypothetical: ``file_forecast.py`` and ``POST /v1/forecast``
both accept a flow CSV or a PCAP, and a flow-only capture omits 24 of the 98
schema features. The vector that reaches the model then contains a z of -104,
which a linear model turns into an arbitrary probability the caller has no way
to interpret.

Absent telemetry is not a measurement of zero, so it must not be encoded as one.
The fix is to fill the *standardized* value with 0.0, which is the training mean
by construction. Two properties matter:

- **Leakage safety is preserved.** The mean is the imputation value, and means
  are fitted on training states only. Validation and test rows never contribute
  to it.
- **Feature ordering and width are unchanged**, so an existing artifact still
  loads and only the values for absent features move.

``fit_feature_schema`` also computes its statistics over *present* values only.
Filling with 0.0 before averaging meant a training window that lacked a feature
dragged the fitted mean toward zero, which is the same mistake one step earlier
in the pipeline.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from sentinel.schemas import NetworkState

#: v2: missing values are imputed in z-space rather than in raw space. Bumped
#: because the change alters model inputs for any state with incomplete
#: telemetry, which is every flow-only capture.
FEATURE_VERSION = "state-features-v2"

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

    # NaN marks "this training window did not carry this feature". Statistics are
    # taken over the windows that did, so a partially-telemetryd training set
    # does not bias its own normalization.
    raw = _raw_matrix(training_states, eligible, missing_value=np.nan)
    present = np.isfinite(raw)
    counts = present.sum(axis=0)
    if not (counts > 0).all():
        never = [eligible[i] for i in np.flatnonzero(counts == 0)]
        raise ValueError(f"no training window carries these features: {never}")
    sums = np.where(present, raw, 0.0).sum(axis=0)
    means = sums / counts
    deviations = np.where(present, raw - means, 0.0) ** 2
    scales = np.sqrt(deviations.sum(axis=0) / counts)
    scales[scales == 0.0] = 1.0  # constant columns stay constant instead of dividing by zero
    return FeatureSchema(
        names=eligible,
        excluded=sorted(excluded & names),
        means=means.tolist(),
        scales=scales.tolist(),
    )


def vectorize_states(states: Sequence[NetworkState], schema: FeatureSchema) -> np.ndarray:
    """Vectorize states using a fitted schema; unseen feature names are ignored.

    A feature the state does not carry is imputed at ``0.0`` in z-space, which is
    the training mean. Filling with ``missing_value`` in raw space and
    standardizing afterwards would place it at ``-mean/scale``, up to 104 sigma
    on the committed bundle; see the module docstring.
    """
    if not states:
        return np.empty((0, schema.width), dtype=float)
    means = np.asarray(schema.means)
    scales = np.asarray(schema.scales)
    raw = _raw_matrix(states, schema.names, missing_value=np.nan)
    # Standardize what is present; leave absent entries at 0.0 rather than
    # carrying NaN into the model.
    present = np.isfinite(raw)
    standardized = np.zeros_like(raw)
    np.subtract(raw, means, out=standardized, where=present)
    np.divide(standardized, scales, out=standardized, where=present)
    return standardized


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
