"""Run baseline and temporal models, then produce a side-by-side comparison.

    uv run python scripts/run_comparison.py --config configs/default.yaml \
        --output reports/generated/comparison
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from trajectory.baseline import save_baseline_artifacts, train_baseline
from trajectory.config import load_settings
from trajectory.features import fit_feature_schema
from trajectory.metrics import BinaryMetrics
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import build_sequence_samples, make_split_manifest
from trajectory.temporal import TemporalConfig, save_temporal_artifacts, train_temporal

DEFAULT_SCENARIOS = [f"scenario-{index:02d}" for index in range(1, 11)]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--output", default="reports/generated/comparison")
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

    # --- baseline ---
    t0 = time.perf_counter()
    baseline_run = train_baseline(
        labelled, samples, manifest, config=settings.model.baseline_config, seed=seed
    )
    baseline_time = time.perf_counter() - t0

    # --- temporal ---
    t0 = time.perf_counter()
    temporal_run = train_temporal(
        labelled,
        samples,
        manifest,
        feature_schema=schema,
        config=TemporalConfig(
            hidden_size=32, num_layers=1, max_epochs=100, early_stopping_patience=10
        ),
        seed=seed,
        max_horizon=args.max_horizon,
    )
    temporal_time = time.perf_counter() - t0

    # --- write artifacts ---
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    save_baseline_artifacts(baseline_run, out / "baseline")
    save_temporal_artifacts(temporal_run, out / "temporal")
    _write_comparison(
        out, baseline_run.result.metrics, temporal_run.result, baseline_time, temporal_time
    )

    # --- print summary ---
    test_b = baseline_run.result.metrics.get("test")
    print(
        f"baseline: P={_f(test_b.precision)} R={_f(test_b.recall)} "
        f"F1={_f(test_b.f1)} FPR={_f(test_b.false_positive_rate)}"
    )
    for h in temporal_run.result.horizons:
        test_t = h.metrics.get("test")
        if test_t is not None:
            print(
                f"temporal h+{h.horizon}: P={_f(test_t.precision)} "
                f"R={_f(test_t.recall)} F1={_f(test_t.f1)} FPR={_f(test_t.false_positive_rate)}"
            )


def _write_comparison(
    out: Path,
    baseline_metrics: dict[str, BinaryMetrics],
    temporal_result,
    baseline_time: float,
    temporal_time: float,
) -> None:
    test_b = baseline_metrics.get("test")
    lines = [
        "# Baseline vs Temporal Comparison",
        "",
        f"- Total baseline training time: {baseline_time * 1000:.1f} ms",
        f"- Total temporal training time: {temporal_time * 1000:.1f} ms",
        "",
        "## Test-Split Metrics",
        "",
        "| Metric | Baseline | "
        + " | ".join(f"Temporal h+{h.horizon}" for h in temporal_result.horizons)
        + " |",
        "|---|" + "---:|" * (1 + len(temporal_result.horizons)),
    ]
    for label, attr in [
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("F1", "f1"),
        ("False-positive rate", "false_positive_rate"),
        ("PR-AUC", "pr_auc"),
    ]:
        vals = [_f(getattr(test_b, attr))]
        for h in temporal_result.horizons:
            test_t = h.metrics.get("test")
            vals.append(_f(getattr(test_t, attr)) if test_t else "n/a")
        lines.append(f"| {label} | " + " | ".join(vals) + " |")

    lines += [
        "",
        "## Notes",
        "",
        "- Baseline: logistic regression on the current window only (no temporal context).",
        "- Temporal: GRU on a sequence of windows (temporal context available).",
        "- Each temporal horizon trains an independent model; this is not a recursive rollout.",
        "- The baseline reference model should be comparable to the logistic-regression baseline.",
        "",
    ]
    (out / "comparison.md").write_text("\n".join(lines), encoding="utf-8")


def _f(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f}"


if __name__ == "__main__":
    main()
