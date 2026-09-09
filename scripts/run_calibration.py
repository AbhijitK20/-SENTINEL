"""Leakage-safe decision-threshold calibration from validation-split scores.

    uv run python scripts/run_calibration.py \
        --config configs/default.yaml \
        --output reports/generated/calibration

Trains the same baseline as run_comparison.py, collects validation-split
probabilities for the configured horizon target, and selects a decision
threshold on a fixed grid. The test split is never touched. Writes
calibration.json with every candidate so the choice is auditable.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from trajectory.baseline import train_baseline
from trajectory.calibration import calibrate_threshold
from trajectory.config import load_settings
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default="reports/generated/calibration")
    parser.add_argument("--scenarios", type=int, default=10)
    parser.add_argument("--objective", default="f1", choices=["f1", "youden"])
    args = parser.parse_args()

    settings = load_settings(args.config)
    seed = settings.project.random_seed
    scenario_ids = [f"scenario-{index:02d}" for index in range(1, args.scenarios + 1)]

    labelled = generate_labelled_states(
        scenario_ids,
        seed=seed,
        window_seconds=settings.data.window_seconds,
        stride_seconds=settings.data.stride_seconds,
    )
    samples = build_sequence_samples(
        labelled,
        sequence_length=settings.data.sequence_length,
        horizon=settings.data.forecast_horizon,
    )
    manifest = make_split_manifest(
        scenario_ids,
        seed=seed,
        train_fraction=settings.split.train_fraction,
        validation_fraction=settings.split.validation_fraction,
    )
    run = train_baseline(
        labelled, samples, manifest, config=settings.model.baseline_config, seed=seed
    )

    # Validation-split probabilities for the horizon target, from the fitted
    # baseline on the standardized current window. Test scenarios are excluded.
    schema = run.result.feature_schema
    from trajectory.features import vectorize_states

    validation_items = [
        item for item in labelled if item.scenario_id in manifest.validation_scenarios
    ]
    if not validation_items:
        raise SystemExit("No validation scenarios available for calibration")

    # Score each validation state that has a horizon-forward same-scenario label.
    by_scenario: dict[str, list] = {}
    for item in labelled:
        by_scenario.setdefault(item.scenario_id, []).append(item)
    probabilities: list[float] = []
    labels: list[bool] = []
    for item in validation_items:
        peers = by_scenario[item.scenario_id]
        index = peers.index(item)
        target_index = index + settings.data.forecast_horizon
        if target_index >= len(peers):
            continue
        vector = vectorize_states([item.state], schema)
        proba = float(run.model.predict_proba(vector)[:, 1][0])
        probabilities.append(proba)
        labels.append(bool(peers[target_index].label.infiltration))

    result = calibrate_threshold(probabilities, labels, objective=args.objective)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "calibration.json").write_text(
        json.dumps(result.model_dump(), indent=2), encoding="utf-8"
    )

    print(f"objective={result.objective} best_threshold={result.best_threshold:.2f}")
    print(f"default_threshold={result.default_threshold:.2f}")
    print(f"validation_samples={result.sample_count} positives={result.positive_count}")
    for warning in result.warnings:
        print(f"warning: {warning}")
    top = sorted(result.candidates, key=lambda c: c.objective_value, reverse=True)[:5]
    for candidate in top:
        precision = _f(candidate.precision)
        recall = _f(candidate.recall)
        fpr = _f(candidate.false_positive_rate)
        print(
            f"  threshold={candidate.threshold:.2f} objective={candidate.objective_value:.3f} "
            f"P={precision} R={recall} FPR={fpr}"
        )
    print(f"calibration_json={out / 'calibration.json'}")


def _f(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


if __name__ == "__main__":
    main()
