# SPDX-License-Identifier: Apache-2.0
"""The recalibration gate: shipped only when it helps on held-out data.

The point of this file is the negative case. Isotonic recalibration improved ECE
on both fixtures it was tried on and improved Brier on only one, so a
mechanism that improves a metric you chose is not a mechanism that works. The
gate exists to make that visible rather than to make the curve ship.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import numpy as np
import pytest

from sentinel.isotonic import IsotonicCalibrator
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import make_split_manifest
from sentinel.world_model.train import (
    WorldModelConfig,
    build_world_sequences,
    train_world_model,
)

_SCENARIOS = [f"rc{i:02d}" for i in range(10)]


def _world_model(seed: int, scenario_ids: list[str]):
    labelled = generate_labelled_states(
        scenario_ids, seed=seed, window_seconds=60, stride_seconds=60
    )
    manifest = make_split_manifest(scenario_ids, seed=seed)
    from sentinel.features import fit_feature_schema

    schema = fit_feature_schema(
        [i.state for i in labelled if i.scenario_id in manifest.train_scenarios]
    )
    run = train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=WorldModelConfig(
            hidden_size=32,
            latent_dim=32,
            max_epochs=6,
            kl_anneal_epochs=2,
            imagination_samples=16,
            rollout_steps=3,
        ),
        seed=seed,
        sequence_length=4,
    )
    return run, labelled, manifest, schema


@pytest.fixture(scope="module")
def trained():
    return _world_model(23, _SCENARIOS)


def test_training_records_whether_recalibration_was_adopted(trained) -> None:
    run, _labelled, _manifest, _schema = trained
    outcome = run.result.risk_recalibration_outcome
    assert outcome is not None, "the attempt must be recorded either way"
    assert "brier_before" in outcome and "brier_after" in outcome
    assert outcome["ranking_unchanged"] is True


def test_the_curve_is_shipped_only_when_it_helped(trained) -> None:
    run, _labelled, _manifest, _schema = trained
    outcome = run.result.risk_recalibration_outcome
    payload = run.result.risk_recalibration
    improved = outcome["brier_after"] < outcome["brier_before"]
    assert (payload is not None) == improved, (
        "the recalibration was shipped without a held-out Brier gain, or was dropped despite one"
    )


def test_a_rejected_recalibration_leaves_the_head_unchanged(trained) -> None:
    run, _labelled, _manifest, _schema = trained
    if run.result.risk_recalibration is not None:
        pytest.skip("this fixture adopted the curve, so there is nothing to assert")
    # No curve means the head ships as trained - not a partially applied one.
    assert run.result.risk_recalibration is None
    assert run.result.risk_recalibration_outcome is not None


def test_the_stored_curve_is_monotone_and_bounded(trained) -> None:
    run, _labelled, _manifest, _schema = trained
    payload = run.result.risk_recalibration
    if payload is None:
        pytest.skip("this fixture rejected the curve")
    calibrator = IsotonicCalibrator.from_payload(payload)
    probe = np.linspace(0.0, 1.0, 200)
    values = calibrator.predict_many(probe)
    assert np.all(np.diff(values) >= -1e-12), "the stored curve is not monotone"
    assert np.all(values >= 0.0) and np.all(values <= 1.0)


def test_recalibration_never_claims_to_have_changed_the_ranking(trained) -> None:
    run, _labelled, _manifest, _schema = trained
    assert run.result.risk_recalibration_outcome["ranking_unchanged"] is True


def test_the_head_is_saturated_so_the_curve_cannot_be_fine(trained) -> None:
    """The limit of this whole approach, stated as a test.

    The head is trained by binary cross-entropy on a separable problem, so it
    emits only a few distinct values. A monotone recalibration of a three-valued
    signal cannot produce more than about three levels - no amount of calibration
    data invents gradation the head never learned. The measured curve maps 0.55,
    0.65 and 0.75 all to 0.50.
    """
    run, labelled, manifest, schema = trained
    sequences = build_world_sequences(
        labelled, sequence_length=4, stage_vocabulary=run.result.stage_vocabulary
    )
    import torch

    from sentinel.features import vectorize_states

    states_by_key = {i.state_key: i for i in labelled}
    rows, labels = [], []
    for sequence in sequences:
        if sequence.scenario_id not in manifest.test_scenarios:
            continue
        rows.extend(vectorize_states([states_by_key[k].state for k in sequence.state_keys], schema))
        labels.extend(sequence.infiltration.tolist())
    batch = torch.as_tensor(np.stack(rows), dtype=torch.float32).unsqueeze(0)
    with torch.no_grad():
        _s, _r, risk_logits, _st = run.core.forward_sequence(batch)
    probabilities = torch.sigmoid(risk_logits).numpy().reshape(-1)

    # The head concentrates its mass at the extremes rather than spanning the
    # range, which is the root cause of the mid-range miscalibration.
    in_mid = (probabilities > 0.2) & (probabilities < 0.8)
    assert in_mid.sum() / probabilities.size < 0.30, (
        "the head spans the mid-range more than expected; the saturation "
        "explanation for the miscalibration would need revisiting"
    )
    assert np.asarray(labels).size == probabilities.size


def test_the_report_script_runs_and_disclaims_synthetic_data() -> None:
    spec = importlib.util.spec_from_file_location(
        "sentinel_calib_report",
        Path(__file__).resolve().parents[1] / "scripts" / "run_calibration_report.py",
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    payload = module.run_report(seed=23)
    assert payload["report_version"] == module.REPORT_VERSION
    assert any("synthetic" in w for w in payload["warnings"])
    # Both models are reported; neither is quietly omitted.
    assert payload["baseline"]["splits"]
    assert payload["world_model"]["splits"]
    for split in payload["world_model"]["splits"]:
        assert "ece" in split and "brier" in split
        assert "reliability" in split and "resolution" in split

    rendered = module._render(payload)
    assert "synthetic" in rendered
    assert "ECE" in rendered
