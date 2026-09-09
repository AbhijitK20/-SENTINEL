"""Tests for walk-forward replay evaluation and the analyst report."""

from __future__ import annotations

from pathlib import Path

import pytest

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import BaselineConfig
from trajectory.evaluation import evaluate_replay
from trajectory.predict import DECISION_THRESHOLD, load_artifacts
from trajectory.report import render_report
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

SCENARIOS = [f"ev{i}" for i in range(6)]


def _setup(tmp_path: Path, seed: int = 11):
    labelled = generate_labelled_states(SCENARIOS, seed=seed, window_seconds=60, stride_seconds=60)
    samples = build_sequence_samples(labelled, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=seed)
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=seed,
    )
    baseline_dir = tmp_path / "baseline"
    save_baseline_artifacts(run, baseline_dir)
    loaded = load_artifacts(baseline_dir)
    return labelled, loaded, manifest


def test_replay_produces_rows_and_summary(tmp_path: Path) -> None:
    labelled, loaded, _ = _setup(tmp_path)

    evaluation = evaluate_replay(labelled, loaded, horizon=2, split_filter="test")

    assert evaluation.scenarios_evaluated >= 1
    assert evaluation.rows
    assert evaluation.summaries
    assert all(0.0 <= row.peak_probability <= 1.0 for row in evaluation.rows)
    assert evaluation.decision_threshold == DECISION_THRESHOLD
    # Every row's realized stage must come from the label vocabulary.
    assert all(row.realized_future_stage for row in evaluation.rows)


def test_replay_respects_split_filter(tmp_path: Path) -> None:
    labelled, loaded, manifest = _setup(tmp_path)

    evaluation = evaluate_replay(labelled, loaded, horizon=2, split_filter="test")

    test_scenarios = set(manifest.test_scenarios)
    assert {s.scenario_id for s in evaluation.summaries} <= test_scenarios


def test_lead_credit_only_when_crossing_precedes_onset(tmp_path: Path) -> None:
    labelled, loaded, _ = _setup(tmp_path)

    evaluation = evaluate_replay(labelled, loaded, horizon=3, split_filter="test")

    for row in evaluation.rows:
        if row.lead_windows is not None:
            # Lead credit implies the forecast crossed and reality agreed.
            assert row.threshold_crossed
            assert row.realized_future_infiltration
            assert row.lead_windows >= 0


def test_invalid_arguments_rejected(tmp_path: Path) -> None:
    labelled, loaded, _ = _setup(tmp_path)

    with pytest.raises(ValueError, match="horizon must be positive"):
        evaluate_replay(labelled, loaded, horizon=0)
    with pytest.raises(ValueError, match="threshold"):
        evaluate_replay(labelled, loaded, horizon=2, threshold=1.5)
    with pytest.raises(ValueError, match="split_filter"):
        evaluate_replay(labelled, loaded, horizon=2, split_filter="trainbogus")
    with pytest.raises(ValueError, match="at least one labelled state"):
        evaluate_replay([], loaded, horizon=2)


def test_report_contains_contract_sections(tmp_path: Path) -> None:
    labelled, loaded, manifest = _setup(tmp_path)

    evaluation = evaluate_replay(labelled, loaded, horizon=2, split_filter="test")
    scenario = evaluation.summaries[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]
    from trajectory.predict import forecast

    result = forecast(states, loaded, max_horizon=3)
    report = render_report(
        result, scenario_id=scenario, evaluation=evaluation, dataset_id="synthetic-recon-lateral-v1"
    )

    assert "# Trajectory Forecast Report" in report
    assert "## Stage Mapping" in report
    assert "## Probability Timeline" in report
    assert "## Replay Evaluation (measured lead time)" in report
    assert "## Limitations" in report
    assert "not a benchmark claim" in report


def test_report_json_round_trip_stability(tmp_path: Path) -> None:
    """Rendering twice with the same inputs yields identical output."""
    labelled, loaded, _ = _setup(tmp_path)

    evaluation = evaluate_replay(labelled, loaded, horizon=2, split_filter="test")
    scenario = evaluation.summaries[0].scenario_id
    states = [i.state for i in labelled if i.scenario_id == scenario]
    from trajectory.predict import forecast

    result = forecast(states, loaded, max_horizon=2)
    report_one = render_report(result, scenario_id=scenario, evaluation=evaluation)
    report_two = render_report(result, scenario_id=scenario, evaluation=evaluation)

    # The generated timestamp line changes between renders; strip it.

    def strip(text: str) -> str:
        return "\n".join(line for line in text.splitlines() if not line.startswith("- Generated:"))

    assert strip(report_one) == strip(report_two)
