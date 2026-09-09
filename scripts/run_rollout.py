"""Recursive K-step rollout evaluation: transition model + classifier scoring.

    uv run python scripts/run_rollout.py \
        --baseline reports/generated/baseline \
        --output reports/generated/rollout

Fits the linear next-state transition model on training scenarios only, then
walks the same replay windows as scripts/run_replay.py twice — once with the
default per-horizon forecaster and once with the recursive rollout — and
writes a side-by-side comparison (rollout.json + rollout.md).
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from trajectory.evaluation import evaluate_replay
from trajectory.predict import load_artifacts
from trajectory.rollout import (
    fit_transition_model,
    rollout_forecast,
    save_transition_model,
)
from trajectory.synthetic import DATASET_ID, generate_labelled_states
from trajectory.targets import make_split_manifest


def _rollout_forecast_fn(transition_model, baseline_model, schema):
    def _fn(states, artifacts, *, max_horizon, threshold):
        return rollout_forecast(
            states,
            transition_model,
            baseline_model,
            schema,
            max_horizon=max_horizon,
            threshold=threshold,
        )[0]

    return _fn


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="Baseline artifacts directory")
    parser.add_argument("--scenarios", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--horizon", type=int, default=5)
    parser.add_argument("--history", type=int, default=4)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--stride-seconds", type=int, default=60)
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Decision threshold (default: shipped 0.5)",
    )
    parser.add_argument("--output", required=True, help="Output directory")
    args = parser.parse_args()

    from trajectory.predict import DECISION_THRESHOLD as _D  # local import for clarity

    threshold = args.threshold if args.threshold is not None else _D

    loaded = load_artifacts(args.baseline)

    scenario_ids = [f"scenario-{index:02d}" for index in range(1, args.scenarios + 1)]
    labelled = generate_labelled_states(
        scenario_ids,
        seed=args.seed,
        window_seconds=args.window_seconds,
        stride_seconds=args.stride_seconds,
    )
    manifest = make_split_manifest(scenario_ids, seed=args.seed)

    transition = fit_transition_model(
        labelled,
        history_length=args.history,
        scenario_ids=manifest.train_scenarios,
    )
    model_path = save_transition_model(transition, str(Path(args.output) / "transition_model.json"))

    schema = loaded.baseline_result.feature_schema
    baseline_model = loaded.baseline_model
    rollout_fn = _rollout_forecast_fn(transition, baseline_model, schema)

    default_eval = evaluate_replay(
        labelled,
        loaded,
        horizon=args.horizon,
        threshold=threshold,
        split_filter="test",
        max_history=args.history,
    )
    rollout_eval = evaluate_replay(
        labelled,
        loaded,
        horizon=args.horizon,
        threshold=threshold,
        split_filter="test",
        max_history=args.history,
        min_history=args.history,
        forecast_fn=rollout_fn,
    )

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "rollout.json").write_text(
        json.dumps(
            {
                "transition_model_path": model_path,
                "history_length": args.history,
                "threshold": threshold,
                "training_windows": transition.training_windows,
                "default": default_eval.model_dump(),
                "rollout": rollout_eval.model_dump(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    (out / "rollout.md").write_text(
        _render_markdown(transition, threshold, default_eval, rollout_eval),
        encoding="utf-8",
    )

    print(f"transition_model={model_path} training_windows={transition.training_windows}")
    for label, evaluation in (("per-horizon", default_eval), ("rollout", rollout_eval)):
        lead = evaluation.measured_median_lead_windows
        lead_text = f"{lead:.1f}" if lead is not None else "none"
        print(
            f"{label}: median_lead={lead_text} crossing={evaluation.forecast_crossing_rate:.2f} "
            f"false_early={evaluation.false_early_warning_rate:.2f}"
        )


def _render_markdown(transition, threshold, default_eval, rollout_eval) -> str:
    def _row(label, evaluation):
        lead = evaluation.measured_median_lead_windows
        return (f"| {label} | {lead:.1f}" if lead is not None else f"| {label} | none") + (
            f" | {evaluation.forecast_crossing_rate:.2f} "
            f"| {evaluation.false_early_warning_rate:.2f} "
            f"| {evaluation.scenarios_evaluated} |"
        )

    lines = [
        "# Recursive Rollout Evaluation",
        "",
        f"- Transition model version: `{transition.model_version}`",
        f"- History length: {transition.history_length} windows",
        f"- Training windows: {transition.training_windows}",
        f"- Decision threshold: {threshold:.2f}",
        f"- Dataset: `{DATASET_ID}` (synthetic replay; pipeline check, not a benchmark)",
        "",
        "## Forecast vs Reality — Per-Horizon vs Rollout",
        "",
        "| Forecaster | Median lead (win) | Crossing rate | False early rate | Scenarios |",
        "|---|---:|---:|---:|---:|",
        _row("Per-horizon (nowcast)", default_eval),
        _row("Recursive rollout", rollout_eval),
        "",
        "## Notes",
        "",
        "- Both forecasters scored on identical windows, threshold, and split.",
        "- Rollout probabilities are classifier scores on simulated states; drift",
        "  accumulates with horizon by construction and is reported, not hidden.",
        "- The transition model is fitted on training scenarios only.",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
