"""Walk-forward replay evaluation and analyst report generation.

    uv run python scripts/run_replay.py \
        --baseline reports/generated/baseline \
        --temporal reports/generated/temporal \
        --output reports/generated/replay

Produces replay.json (typed contract) and replay.md. When exactly one test
scenario is evaluated, also renders a full forecast_report.md from the last
input window of that scenario.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from trajectory.evaluation import evaluate_replay
from trajectory.predict import forecast, load_artifacts
from trajectory.report import render_report, save_report
from trajectory.synthetic import DATASET_ID, generate_labelled_states
from trajectory.targets import make_split_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="Baseline artifacts directory")
    parser.add_argument("--temporal", default=None, help="Optional temporal artifacts directory")
    parser.add_argument("--scenarios", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--horizon", type=int, default=5)
    parser.add_argument("--max-history", type=int, default=8)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--stride-seconds", type=int, default=60)
    parser.add_argument(
        "--split",
        default="test",
        choices=["test", "validation"],
        help="Which split to evaluate (test by default)",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Decision threshold (default: the shipped 0.5; pass a calibrated value)",
    )
    parser.add_argument("--output", required=True, help="Output directory")
    args = parser.parse_args()

    loaded = load_artifacts(args.baseline, temporal_dir=args.temporal)

    scenario_ids = [f"scenario-{index:02d}" for index in range(1, args.scenarios + 1)]
    labelled = generate_labelled_states(
        scenario_ids,
        seed=args.seed,
        window_seconds=args.window_seconds,
        stride_seconds=args.stride_seconds,
    )
    # The manifest check keeps split filtering consistent with training.
    make_split_manifest(scenario_ids, seed=args.seed)

    # threshold=None lets evaluate_replay() resolve: explicit flag →
    # calibrated threshold stored with the artifacts → shipped 0.5 default.
    evaluation = evaluate_replay(
        labelled,
        loaded,
        horizon=args.horizon,
        threshold=args.threshold,
        split_filter=args.split,
        max_history=args.max_history,
    )

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "replay.json").write_text(
        json.dumps(evaluation.model_dump(), indent=2), encoding="utf-8"
    )

    report = render_report(
        _representative_forecast(labelled, loaded, evaluation, args),
        scenario_id=_representative_scenario(evaluation),
        evaluation=evaluation,
        dataset_id=DATASET_ID,
    )
    save_report(report, out / "replay.md")

    _print_summary(evaluation, out)


def _representative_scenario(evaluation) -> str | None:
    if evaluation.summaries:
        return evaluation.summaries[0].scenario_id
    return None


def _representative_forecast(labelled, loaded, evaluation, args):
    """Forecast from the last valid history of the first evaluated scenario."""
    scenario_id = _representative_scenario(evaluation)
    if scenario_id is None:
        raise SystemExit("No scenarios were evaluated; nothing to report")
    states = [item.state for item in labelled if item.scenario_id == scenario_id]
    states = states[: len(states) - args.horizon]
    return forecast(states, loaded, max_horizon=args.horizon)


def _print_summary(evaluation, out: Path) -> None:
    print(f"scenarios_evaluated={evaluation.scenarios_evaluated} horizon={evaluation.horizon}")
    print(f"threshold={evaluation.decision_threshold:.2f}")
    if evaluation.measured_median_lead_windows is not None:
        print(f"measured_median_lead_windows={evaluation.measured_median_lead_windows:.1f}")
    else:
        print("measured_median_lead_windows=none")
    print(f"forecast_crossing_rate={evaluation.forecast_crossing_rate:.2f}")
    print(f"false_early_warning_rate={evaluation.false_early_warning_rate:.2f}")
    for warning in evaluation.warnings:
        print(f"warning: {warning}")
    print(f"replay_json={out / 'replay.json'}")
    print(f"replay_md={out / 'replay.md'}")


if __name__ == "__main__":
    main()
