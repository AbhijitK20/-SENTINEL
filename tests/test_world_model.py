"""Tests for the RSSM world model: dynamics, imagination, and artifacts.

The world model is the only component that claims to *simulate* network states,
so the tests that matter most are the ones that would catch it pretending:
shapes that cannot exist, an imagination path that never runs, an objective that
does not reach the parameters, and a training run that can see the test split.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path

import numpy as np
import pytest
import torch

from sentinel.features import fit_feature_schema, vectorize_states
from sentinel.schemas import Forecast
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import make_split_manifest
from sentinel.world_model.imagine import (
    IMAGINATION_VERSION,
    aggregate_open_loop,
    imagination_forecast,
    imagine,
    open_loop_error,
    risk_saliency,
)
from sentinel.world_model.model import (
    CORE_TYPES,
    WORLD_MODEL_VERSION,
    RSSMCore,
    dream_consistency,
    dream_trajectory,
    kl_divergence,
    kl_weight,
    rssm_loss,
)
from sentinel.world_model.train import (
    WorldModelConfig,
    build_world_sequences,
    load_world_model,
    render_report,
    save_world_model_artifacts,
    stage_vocabulary,
    train_world_model,
)

SCENARIOS = [f"wm{i}" for i in range(6)]
SEQ_LEN = 6
HORIZON = 3


@pytest.fixture(scope="module")
def corpus():
    labelled = generate_labelled_states(SCENARIOS, seed=7, window_seconds=60, stride_seconds=60)
    manifest = make_split_manifest(SCENARIOS, seed=7)
    schema = fit_feature_schema(
        [i.state for i in labelled if i.scenario_id in manifest.train_scenarios]
    )
    return labelled, manifest, schema


@pytest.fixture(scope="module")
def trained(corpus):
    labelled, manifest, schema = corpus
    config = WorldModelConfig(
        hidden_size=16,
        latent_dim=4,
        max_epochs=3,
        kl_anneal_epochs=1,
        batch_size=64,
        rollout_steps=2,
    )
    return train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=config,
        seed=7,
        sequence_length=SEQ_LEN,
    )


def _core(**kwargs) -> RSSMCore:
    defaults = {"obs_dim": 5, "hidden_dim": 8, "latent_dim": 4, "num_stages": 3}
    return RSSMCore(**{**defaults, **kwargs})


# ── core dynamics ───────────────────────────────────────────────────────


@pytest.mark.parametrize("core_type", CORE_TYPES)
def test_every_core_runs_teacher_forced_and_backward(core_type: str) -> None:
    """Regression: the LSTM core used to crash because the cell state was the latent."""
    torch.manual_seed(0)
    core = _core(core_type=core_type, num_heads=2)
    observations = torch.randn(3, SEQ_LEN, 5)
    states, recon, risks, stages = core.forward_sequence(observations)

    assert len(states) == SEQ_LEN
    assert recon.shape == observations.shape
    assert risks.shape == (3, SEQ_LEN, 1)
    assert stages.shape == (3, SEQ_LEN, 3)

    loss, parts = rssm_loss(
        observations,
        recon,
        risks,
        stages,
        states,
        risk_labels=torch.randint(0, 2, (3, SEQ_LEN)).float(),
        stage_labels=torch.randint(0, 3, (3, SEQ_LEN)),
    )
    loss.backward()
    assert np.isfinite(parts["total"])
    assert any(p.grad is not None and p.grad.abs().sum() > 0 for p in core.parameters())


def test_heads_emit_logits_not_probabilities() -> None:
    """Sigmoid/softmax live in the loss, so a head returning 0..1 means double softmax."""
    torch.manual_seed(0)
    core = _core()
    observations = torch.randn(2, SEQ_LEN, 5)
    _states, _recon, risks, stages = core.forward_sequence(observations)

    assert risks.min() < 0.0 or risks.max() > 1.0
    assert stages.min() < 0.0 or stages.max() > 1.0


def test_rejects_unknown_core_type() -> None:
    with pytest.raises(ValueError, match="core_type must be one of"):
        _core(core_type="conv1d")  # type: ignore[arg-type]


def test_rejects_transformer_with_indivisible_hidden_size() -> None:
    with pytest.raises(ValueError, match="divisible by num_heads"):
        _core(core_type="transformer", hidden_dim=10, num_heads=4)


def test_kl_is_zero_when_prior_equals_posterior() -> None:
    core = _core()
    state = core.initial_state(2)
    _recon, _risk, _stage, state, _encoded = core.forward_step(torch.randn(2, 5), state)
    state.mu_q = state.mu_p.clone()
    state.sigma_q = state.sigma_p.clone()
    assert float(kl_divergence([state]).detach()) == pytest.approx(0.0, abs=1e-6)


def test_kl_weight_keeps_free_nats_of_information() -> None:
    core = _core()
    state = core.initial_state(2)
    small = state.h.new_tensor(0.1)
    large = state.h.new_tensor(10.0)
    assert kl_weight(large, 1.0) < kl_weight(small, 1.0)
    assert kl_weight(small, 0.0) == 1.0


def test_dream_trajectory_has_no_observation_beyond_the_burn_in() -> None:
    """Imagination must be a function of the prefix only, not the realized tail."""
    torch.manual_seed(0)
    core = _core()
    observations = torch.randn(2, SEQ_LEN, 5)
    first = dream_trajectory(core, observations, steps=2)
    altered = observations.clone()
    altered[:, -1] += 100.0  # change only the last window
    second = dream_trajectory(core, altered, steps=2)

    assert first.shape == (2, 2, 5)
    assert not torch.allclose(first, second)


def test_dream_consistency_is_a_positive_scalar() -> None:
    core = _core()
    loss = dream_consistency(core, torch.randn(2, SEQ_LEN, 5), steps=2)
    assert loss.ndim == 0
    assert float(loss.detach()) >= 0.0


def test_dream_steps_must_be_shorter_than_the_sequence() -> None:
    core = _core()
    with pytest.raises(ValueError, match="shorter than the sequence length"):
        dream_trajectory(core, torch.randn(2, SEQ_LEN, 5), steps=SEQ_LEN)


# ── imagination ─────────────────────────────────────────────────────────


def test_imagine_returns_one_row_per_sample_and_step(trained, corpus) -> None:
    _run, _manifest, schema = corpus
    history = np.zeros((SEQ_LEN, schema.width), dtype=np.float32)
    rollout = imagine(trained.core, history, k=HORIZON, n_samples=7, seed=1)

    assert rollout.observations.shape == (7, HORIZON, schema.width)
    assert rollout.risks.shape == (7, HORIZON)
    assert rollout.stages.shape == (7, HORIZON, len(trained.result.stage_vocabulary))
    assert float(rollout.risks.min()) >= 0.0 and float(rollout.risks.max()) <= 1.0
    assert rollout.latent_spread.shape == (HORIZON,)


def test_imagine_is_reproducible_for_a_fixed_seed(trained, corpus) -> None:
    _run, _manifest, schema = corpus
    history = np.zeros((SEQ_LEN, schema.width), dtype=np.float32)
    first = imagine(trained.core, history, k=HORIZON, n_samples=5, seed=3)
    second = imagine(trained.core, history, k=HORIZON, n_samples=5, seed=3)

    assert torch.allclose(first.risks, second.risks)


def test_imagine_rejects_empty_inputs(trained) -> None:
    with pytest.raises(ValueError, match="k must be positive"):
        imagine(trained.core, np.zeros((2, 3), dtype=np.float32), k=0)
    with pytest.raises(ValueError, match="n_samples must be positive"):
        imagine(trained.core, np.zeros((2, 3), dtype=np.float32), k=1, n_samples=0)
    with pytest.raises(ValueError, match="at least one observation"):
        imagine(trained.core, np.zeros((0, 3), dtype=np.float32), k=1)


def test_open_loop_error_reports_both_predictors_and_a_skill(trained, corpus) -> None:
    labelled, _manifest, schema = corpus
    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]
    matrix = vectorize_states(states, schema)

    error = open_loop_error(
        trained.core, matrix[:SEQ_LEN], matrix[SEQ_LEN : SEQ_LEN + HORIZON], n_samples=4, seed=0
    )

    assert error.steps == [1, 2, 3]
    assert len(error.model_mae) == len(error.persistence_mae) == 3
    assert all(value >= 0 for value in error.model_mae)
    assert -2.0 <= error.mean_skill <= 1.0


def test_aggregate_open_loop_averages_windows() -> None:
    from sentinel.world_model.imagine import OpenLoopError

    errors = [
        OpenLoopError(steps=[1, 2], model_mae=[0.2, 0.4], persistence_mae=[0.4, 0.4], windows=1)
        for _ in range(3)
    ]
    aggregate = aggregate_open_loop(errors)

    assert aggregate.windows == 3
    assert aggregate.model_mae == pytest.approx([0.2, 0.4])
    assert aggregate.mean_skill == pytest.approx((0.5 + 0.0) / 2)


def test_aggregate_open_loop_rejects_empty_input() -> None:
    with pytest.raises(ValueError, match="at least one window"):
        aggregate_open_loop([])


def test_imagination_forecast_satisfies_the_forecast_contract(trained, corpus) -> None:
    labelled, _manifest, _schema = corpus
    scenario = labelled[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario][20 : 20 + SEQ_LEN]

    forecast, diagnostics = imagination_forecast(
        states,
        trained.core,
        trained.result.feature_schema,
        trained.result.stage_vocabulary,
        max_horizon=HORIZON,
        n_samples=8,
        seed=0,
    )

    assert isinstance(forecast, Forecast)
    assert IMAGINATION_VERSION in forecast.model_version
    assert len(forecast.probability_timeline) == HORIZON
    assert [p.window for p in forecast.probability_timeline] == [1, 2, 3]
    assert forecast.predicted_stage.name in trained.result.stage_vocabulary
    assert 0.0 <= forecast.predicted_stage.probability <= 1.0
    assert forecast.lead_time is not None
    assert any("open-loop imagination" in w for w in forecast.warnings)
    assert all(0.0 <= p.confidence <= 1.0 for p in forecast.probability_timeline)
    assert len(forecast.driving_features) == 5
    assert {"risk_spread", "crossing_rate", "samples"} <= set(diagnostics)


def test_imagination_forecast_rejects_empty_history(trained) -> None:
    with pytest.raises(ValueError, match="at least one network state"):
        imagination_forecast(
            [],
            trained.core,
            trained.result.feature_schema,
            trained.result.stage_vocabulary,
            max_horizon=2,
        )


def test_saliency_ranks_finite_contributions(trained, corpus) -> None:
    _run, _manifest, schema = corpus
    history = np.random.default_rng(0).normal(size=(SEQ_LEN, schema.width)).astype(np.float32)

    drivers = risk_saliency(trained.core, history, schema.names)

    assert len(drivers) == 5
    assert all(d.name in schema.names for d in drivers)
    assert all(np.isfinite(d.contribution) for d in drivers)
    magnitudes = [abs(d.contribution) for d in drivers]
    assert magnitudes == sorted(magnitudes, reverse=True)


# ── training ────────────────────────────────────────────────────────────


def test_stage_vocabulary_uses_training_labels_only(corpus) -> None:
    labelled, manifest, _schema = corpus
    vocabulary = stage_vocabulary(labelled, manifest)
    train_stages = {
        i.label.attack_stage for i in labelled if i.scenario_id in manifest.train_scenarios
    }
    assert set(vocabulary) == train_stages
    assert vocabulary == sorted(vocabulary)


def test_sequences_never_straddle_scenarios(corpus) -> None:
    labelled, manifest, _schema = corpus
    sequences = build_world_sequences(labelled, sequence_length=SEQ_LEN)
    keys = {item.state_key: item for item in labelled}
    assert sequences
    for sequence in sequences:
        assert len({keys[key].scenario_id for key in sequence.state_keys}) == 1
        assert sequence.scenario_id == keys[sequence.state_keys[0]].scenario_id


def test_sequences_skip_stages_outside_the_vocabulary(corpus) -> None:
    """A test-only stage name must be skipped, never coerced into a known class."""
    labelled, _manifest, _schema = corpus
    sequences = build_world_sequences(
        labelled, sequence_length=SEQ_LEN, stage_vocabulary=["Benign"]
    )
    assert sequences
    for sequence in sequences:
        assert set(sequence.stage_index.tolist()) <= {0}


def test_sequences_reject_bad_length(corpus) -> None:
    labelled, _manifest, _schema = corpus
    with pytest.raises(ValueError, match="sequence_length must be positive"):
        build_world_sequences(labelled, sequence_length=0)
    with pytest.raises(ValueError, match="at least one labelled state"):
        build_world_sequences([], sequence_length=2)


def test_training_reports_every_split_and_never_touches_test_gradients(trained, corpus) -> None:
    labelled, manifest, schema = corpus
    result = trained.result

    assert result.model_version == WORLD_MODEL_VERSION
    assert set(result.metrics) >= {"train", "test"}
    assert result.observation_dim == schema.width
    assert result.sequence_length == SEQ_LEN
    assert result.training_seconds > 0
    assert len(result.model_sha256) == 64
    assert result.train_history

    # The manifest recorded in the artifact is the one the model was fitted under.
    assert result.split_manifest == manifest
    train_ids = {i.scenario_id for i in labelled if i.scenario_id in manifest.train_scenarios}
    assert result.stage_vocabulary == stage_vocabulary(labelled, manifest)
    assert train_ids <= set(manifest.train_scenarios)


def test_training_is_deterministic_for_a_fixed_seed(corpus) -> None:
    labelled, manifest, schema = corpus
    config = WorldModelConfig(
        hidden_size=8, latent_dim=2, max_epochs=2, kl_anneal_epochs=1, batch_size=64
    )
    first = train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=config,
        seed=11,
        sequence_length=SEQ_LEN,
    )
    second = train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=config,
        seed=11,
        sequence_length=SEQ_LEN,
    )
    assert first.result.model_sha256 == second.result.model_sha256
    assert (
        first.result.metrics["test"].reconstruction_mse
        == second.result.metrics["test"].reconstruction_mse
    )


def test_open_loop_metrics_are_recorded_per_step(trained) -> None:
    metrics = trained.result.metrics["test"]
    assert len(metrics.open_loop_mae) == 2  # config.rollout_steps
    assert len(metrics.open_loop_persistence_mae) == 2
    assert metrics.open_loop_skill is not None
    assert all(value >= 0 for value in metrics.open_loop_mae)


def test_training_without_rollout_steps_skips_open_loop_metrics(corpus) -> None:
    labelled, manifest, schema = corpus
    run = train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=WorldModelConfig(
            hidden_size=8, latent_dim=2, max_epochs=2, kl_anneal_epochs=1, rollout_steps=0
        ),
        seed=5,
        sequence_length=SEQ_LEN,
    )
    assert run.result.metrics["test"].open_loop_mae == []
    assert run.result.metrics["test"].open_loop_skill is None


# ── artifacts ───────────────────────────────────────────────────────────


def test_artifacts_round_trip_to_an_identical_model(trained, tmp_path: Path) -> None:
    paths = save_world_model_artifacts(trained, tmp_path)
    assert paths["result"].is_file()
    assert paths["weights"].is_file()
    assert paths["report"].is_file()

    restored = load_world_model(trained.result, tmp_path)
    buffer = io.BytesIO()
    torch.save(restored.state_dict(), buffer)
    digest = hashlib.sha256(buffer.getvalue()).hexdigest()

    assert digest == trained.result.model_sha256
    restored.eval()
    history = np.zeros((SEQ_LEN, trained.result.observation_dim), dtype=np.float32)
    assert imagine(restored, history, k=1, n_samples=2, seed=0).risks.shape == (2, 1)


def test_load_reports_missing_weights(trained, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="weights not found"):
        load_world_model(trained.result, tmp_path)


def test_report_states_only_measured_numbers(trained) -> None:
    report = render_report(trained.result)
    assert "world-model-rssm-v1" in report
    assert "Open-Loop State Prediction" in report
    assert "Persistence MAE" in report
    for metric in trained.result.metrics.values():
        assert f"{metric.reconstruction_mse:.4f}" in report
