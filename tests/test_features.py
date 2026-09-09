from datetime import UTC, datetime, timedelta

import numpy as np
import pytest

from trajectory.features import fit_feature_schema, vectorize_states
from trajectory.schemas import NetworkState

START = datetime(2026, 1, 1, tzinfo=UTC)


def state(index: int, **features: float) -> NetworkState:
    return NetworkState(
        window_start=START + timedelta(minutes=index),
        window_end=START + timedelta(minutes=index + 1),
        features=features,
    )


def test_schema_uses_training_names_and_excludes_configured_features() -> None:
    training = [state(0, bytes=100.0, source_port=4000.0), state(1, bytes=300.0, duration=2.0)]

    schema = fit_feature_schema(training, excluded_features=["source_port"])

    assert schema.names == ["bytes", "duration"]
    assert schema.excluded == ["source_port"]


def test_forbidden_label_names_are_never_features() -> None:
    training = [state(0, bytes=1.0, infiltration=1.0, scenario_id=3.0)]

    schema = fit_feature_schema(training)

    assert schema.names == ["bytes"]


def test_normalization_is_fitted_on_training_data_only() -> None:
    training = [state(0, bytes=100.0), state(1, bytes=300.0)]
    schema = fit_feature_schema(training)

    matrix = vectorize_states([state(2, bytes=200.0), state(3, bytes=900.0)], schema)

    assert schema.means == [200.0]
    assert schema.scales == [100.0]
    assert matrix.tolist() == [[0.0], [7.0]]


def test_missing_and_unseen_features_are_handled() -> None:
    schema = fit_feature_schema([state(0, bytes=10.0, duration=1.0), state(1, bytes=30.0)])

    matrix = vectorize_states([state(2, bytes=20.0, unseen=99.0)], schema)

    assert matrix.shape == (1, 2)
    # duration missing -> fill 0.0 then standardize with training mean/scale
    assert matrix[0, schema.names.index("bytes")] == 0.0
    assert np.isfinite(matrix).all()


def test_empty_training_set_is_rejected() -> None:
    with pytest.raises(ValueError, match="without training states"):
        fit_feature_schema([])
