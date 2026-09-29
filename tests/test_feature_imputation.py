# SPDX-License-Identifier: Apache-2.0
"""Absent telemetry must not be encoded as an extreme measurement.

The bug this file pins: `vectorize_states` filled a missing feature with 0.0 in
raw space and then standardized, placing it at `(0 - mean) / scale`. Network
features are large and tightly concentrated, so that is a huge offset rather
than a neutral fill — against the committed bundle `payload_size_p90` landed at
z = -104.47 and sixteen of ninety-eight features exceeded 5 sigma.

It is reachable: `file_forecast.py` and `POST /v1/forecast` both accept a
flow-only capture, which omits 24 of the 98 schema features.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import numpy as np
import pytest

from sentinel.features import (
    FEATURE_VERSION,
    FeatureSchema,
    fit_feature_schema,
    vectorize_states,
)
from sentinel.ingestion import read_flow_csv
from sentinel.schemas import NetworkState
from sentinel.state_builder import build_network_states

REPO = Path(__file__).resolve().parents[1]
BUNDLE = REPO / "models" / "release" / "v1" / "baseline_result.json"
START = datetime(2026, 1, 1, tzinfo=UTC)


def state(index: int, **features: float) -> NetworkState:
    return NetworkState(
        window_start=START + timedelta(minutes=index),
        window_end=START + timedelta(minutes=index + 1),
        features=features,
    )


def test_missing_values_impute_at_the_training_mean_not_at_minus_mean_over_scale() -> None:
    """The core regression.

    A training set where the feature is large and tight is the condition that
    makes the old fill pathological, so that is what this builds.
    """
    training = [state(i, payload_size_p90=1400.0 + i) for i in range(4)]
    schema = fit_feature_schema(training)
    index = schema.names.index("payload_size_p90")

    # This state has no packet telemetry at all.
    matrix = vectorize_states([state(99, other=1.0)], schema)

    assert matrix[0, index] == 0.0, (
        f"missing feature imputed at z={matrix[0, index]}, expected 0.0 (the training "
        f"mean). Raw-space 0.0 then z-scoring would give "
        f"{(0.0 - schema.means[index]) / schema.scales[index]:.2f}"
    )


def test_schema_statistics_ignore_windows_that_lack_the_feature() -> None:
    """A training window without a feature must not drag the fitted mean to zero.

    This is the same mistake one step earlier in the pipeline: filling with 0.0
    before averaging made a partially-covered training set bias its own
    normalization.
    """
    training = [
        state(0, bytes=100.0),
        state(1, bytes=200.0),
        state(2, bytes=300.0),
        state(3, bytes=400.0, duration=999.0),  # the only window carrying `duration`
    ]
    schema = fit_feature_schema(training)
    index = schema.names.index("duration")

    assert schema.means[index] == pytest.approx(999.0), (
        f"duration mean fitted as {schema.means[index]}, expected 999.0 from the only "
        "window that carries it; a raw-space 0.0 fill would have given 249.75"
    )
    assert schema.scales[index] == pytest.approx(1.0)


def test_imputed_vectors_stay_finite_and_bounded() -> None:
    """No coordinate may blow up when a state is missing most of its features."""
    training = [state(i, bytes=1400.0 + i, ttl=64.0, tcp_window_size=65000.0 + i) for i in range(5)]
    schema = fit_feature_schema(training)
    matrix = vectorize_states([state(42, bytes=1402.0)], schema)

    assert np.isfinite(matrix).all()
    assert np.abs(matrix).max() <= 10.0, (
        f"max |z| = {np.abs(matrix).max():.2f} for a near-empty state; the old raw-space "
        "fill produced values over 100 sigma on the committed bundle"
    )


def test_present_values_are_standardized_exactly_as_before() -> None:
    """The fix must not perturb rows that carry every feature."""
    training = [state(0, bytes=100.0), state(1, bytes=300.0)]
    schema = fit_feature_schema(training)
    matrix = vectorize_states([state(2, bytes=200.0), state(3, bytes=900.0)], schema)

    assert schema.means == [200.0]
    assert schema.scales == [100.0]
    assert matrix.tolist() == [[0.0], [7.0]]


def test_feature_order_and_width_are_unchanged() -> None:
    """An existing artifact must still line up with the schema."""
    training = [state(i, b=1.0, a=2.0, c=3.0) for i in range(3)]
    schema = fit_feature_schema(training)

    assert schema.names == sorted(schema.names)
    assert schema.width == 3
    matrix = vectorize_states([state(9, a=1.0)], schema)
    assert matrix.shape == (1, 3)


@pytest.mark.skipif(not BUNDLE.is_file(), reason="release bundle not present")
def test_flow_only_capture_no_longer_injects_a_hundred_sigma_coordinate() -> None:
    """The end-to-end case: score a flow CSV against a bundle trained with packets.

    This is the path `file_forecast.py` and `POST /v1/forecast` take, and the one
    that produced `max |z| = 104.47` before the fix.
    """
    fixture = REPO / "data" / "fixtures" / "flow_sample.csv"
    if not fixture.is_file():
        pytest.skip("flow fixture not present")

    payload = json.loads(BUNDLE.read_text(encoding="utf-8"))["feature_schema"]
    schema = FeatureSchema(**payload)
    result = read_flow_csv(fixture)
    states = build_network_states(list(result.events), window_seconds=60, stride_seconds=30)
    if not states:
        pytest.skip("fixture produced no windows")

    matrix = vectorize_states(states, schema)
    absent = [n for n in schema.names if n not in states[0].features]

    assert absent, "expected the flow-only fixture to omit some schema features"
    assert np.isfinite(matrix).all()
    assert np.abs(matrix).max() < 25.0, (
        f"max |z| = {np.abs(matrix).max():.2f} with {len(absent)} features absent; "
        "the raw-space fill put this at 104.47"
    )


def test_feature_version_records_the_imputation_change() -> None:
    """Behaviour changed, so the version moved (AGENTS.md rule 7)."""
    assert FEATURE_VERSION == "state-features-v2"
