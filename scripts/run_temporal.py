"""Train the GRU temporal model on synthetic replay data and save artifacts.

    uv run python scripts/run_temporal.py --config configs/default.yaml \
        --output reports/generated/temporal
"""

from __future__ import annotations

import argparse

from trajectory.config import load_settings
from trajectory.features import fit_feature_schema
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest
from trajectory.temporal import TemporalConfig, save_temporal_artifacts, train_temporal

DEFAULT_SCENARIOS = [f"scenario-{index:02d}" for index in range(1, 11)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default="reports/generated/temporal")
    parser.add_argument("--scenarios", type=int, default=len(DEFAULT_SCENARIOS))
    parser.add_argument("--max-horizon", type=int, default=5)
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

    train_states = [item for item in labelled if item.scenario_id in manifest.train_scenarios]
    schema = fit_feature_schema(
        [item.state for item in train_states],
        excluded_features=settings.model.baseline_config.excluded_features,
    )

    temporal_config = TemporalConfig(
        hidden_size=32,
        num_layers=1,
        max_epochs=100,
        early_stopping_patience=10,
    )

    run = train_temporal(
        labelled,
        samples,
        manifest,
        feature_schema=schema,
        config=temporal_config,
        seed=seed,
        max_horizon=args.max_horizon,
    )

    paths = save_temporal_artifacts(run, args.output)
    print(f"horizons={len(run.result.horizons)}")
    for name, path in paths.items():
        print(f"{name}: {path}")
    for h in run.result.horizons:
        test = h.metrics.get("test")
        if test is not None:
            print(
                f"h+{h.horizon}: P={_fmt(test.precision)} R={_fmt(test.recall)} "
                f"F1={_fmt(test.f1)} FPR={_fmt(test.false_positive_rate)} "
                f"PR-AUC={_fmt(test.pr_auc)}"
            )


def _fmt(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


if __name__ == "__main__":
    main()
