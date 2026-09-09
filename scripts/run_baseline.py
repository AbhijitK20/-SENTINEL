"""Train and evaluate the logistic-regression baseline reproducibly.

    uv run python scripts/run_baseline.py --config configs/default.yaml \
        --output reports/generated/baseline

Without ``--flow-csv`` the run uses the deterministic synthetic replay scenarios
(see ``trajectory.synthetic``); the report labels the dataset accordingly.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import load_settings
from trajectory.synthetic import DATASET_ID, generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest

DEFAULT_SCENARIOS = [f"scenario-{index:02d}" for index in range(1, 11)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default="reports/generated/baseline")
    parser.add_argument(
        "--scenarios", type=int, default=len(DEFAULT_SCENARIOS), help="synthetic scenario count"
    )
    args = parser.parse_args()

    settings = load_settings(args.config)
    seed = settings.project.random_seed
    scenario_ids = DEFAULT_SCENARIOS[: args.scenarios]

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
    paths = save_baseline_artifacts(run, Path(args.output))

    dataset_note = Path(args.output) / "DATASET.md"
    dataset_note.write_text(
        f"# Dataset\n\n- Identifier: `{DATASET_ID}`\n- Type: synthetic replay, generated locally\n"
        f"- Scenarios: {len(scenario_ids)}\n- Seed: {seed}\n\n"
        "This is pipeline-validation data. It is not real traffic and the metrics above are "
        "not a benchmark claim.\n",
        encoding="utf-8",
    )
    test = run.result.metrics.get("test")
    print(f"dataset={DATASET_ID} scenarios={len(scenario_ids)} seed={seed}")
    for name, path in paths.items():
        print(f"{name}: {path}")
    if test is not None:
        print(
            "test: "
            f"precision={_fmt(test.precision)} recall={_fmt(test.recall)} "
            f"f1={_fmt(test.f1)} fpr={_fmt(test.false_positive_rate)} pr_auc={_fmt(test.pr_auc)}"
        )


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


if __name__ == "__main__":
    main()
