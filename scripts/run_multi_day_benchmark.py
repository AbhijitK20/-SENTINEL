"""Multi-day benchmark on CIC-IDS2017.

Trains on Tuesday (FTP/SSH-Patator), validates on Thursday morning (Web Attacks),
and tests on each available attack day separately. Measures lead time per family.

Usage:
    uv run python scripts/run_multi_day_benchmark.py
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from sentinel.baseline import BaselineConfig, save_baseline_artifacts, train_baseline
from sentinel.calibration import calibrate_threshold
from sentinel.cic_ids2017 import AdapterStats, build_labelled_states
from sentinel.cic_ids2017 import load_flow_csv_with_stats as _load_flow
from sentinel.evaluation import evaluate_replay
from sentinel.features import vectorize_states
from sentinel.predict import DECISION_THRESHOLD, load_artifacts
from sentinel.rollout import fit_transition_model, rollout_forecast
from sentinel.schemas import SplitManifest
from sentinel.targets import build_sequence_samples

SEED = 42


def _label_of(event) -> str:
    return event.provenance.rsplit(":", 1)[1]


def _load_day(csv_path, scenario_id, time_window, window_seconds, stride_seconds):
    events, stats = _load_flow(csv_path, scenario_id=scenario_id, time_window=time_window)
    if not events:
        raise SystemExit(f"no flows loaded from {csv_path}")
    flow_labels = [(event.timestamp, _label_of(event)) for event in events]
    labelled = build_labelled_states(
        events, flow_labels,
        window_seconds=window_seconds, stride_seconds=stride_seconds,
        scenario_id=scenario_id,
    )
    return labelled, stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data/raw/cic-ids2017/TrafficLabelling")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--stride-seconds", type=int, default=150)
    parser.add_argument("--sequence-length", type=int, default=4)
    parser.add_argument("--horizon", type=int, default=3)
    parser.add_argument("--history", type=int, default=3)
    parser.add_argument("--output", default="reports/generated/multi-day-benchmark")
    args = parser.parse_args()

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    data_dir = Path(args.data_dir)

    # --- Train on Tuesday ---
    train_path = data_dir / "Tuesday-WorkingHours.pcap_ISCX.csv"
    labelled_train, _ = _load_day(
        train_path, "tuesday-train", None,
        args.window_seconds, args.stride_seconds,
    )
    print(f"Train: {len(labelled_train)} windows")

    # --- Validate on Thursday morning ---
    val_path = data_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    labelled_validation, _ = _load_day(
        val_path, "thursday-morning-validation", None,
        args.window_seconds, args.stride_seconds,
    )
    print(f"Validation: {len(labelled_validation)} windows")

    # Combine train + validation for the manifest
    labelled_all = labelled_train + labelled_validation
    manifest = SplitManifest(
        seed=SEED,
        train_scenarios=["tuesday-train"],
        validation_scenarios=["thursday-morning-validation"],
        test_scenarios=[],  # filled per test
    )

    samples = build_sequence_samples(
        labelled_all,
        sequence_length=args.sequence_length,
        horizon=args.horizon,
    )
    run = train_baseline(
        labelled_all, samples, manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=SEED,
    )
    save_baseline_artifacts(run, out / "baseline")

    # --- Calibrate on Thursday morning ---
    schema = run.result.feature_schema
    by_scenario: dict[str, list] = {}
    for item in labelled_all:
        by_scenario.setdefault(item.scenario_id, []).append(item)

    validation = by_scenario.get("thursday-morning-validation", [])
    probabilities, labels = [], []
    for index, item in enumerate(validation):
        target_index = index + args.horizon
        if target_index >= len(validation):
            continue
        vector = vectorize_states([item.state], schema)
        probabilities.append(float(run.model.predict_proba(vector)[:, 1][0]))
        labels.append(bool(validation[target_index].label.infiltration))

    calibration = calibrate_threshold(probabilities, labels, objective="f1")
    (out / "baseline" / "calibration.json").write_text(
        json.dumps(calibration.model_dump(), indent=2), encoding="utf-8"
    )

    # --- Fit transition model on Tuesday only ---
    transition = fit_transition_model(
        labelled_all,
        history_length=args.history,
        scenario_ids=["tuesday-train"],
    )

    # --- Test days ---
    test_days = [
        ("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
         "thursday-afternoon-infiltration",
         (datetime(2017, 7, 6, 13, 0, tzinfo=UTC), datetime(2017, 7, 6, 17, 0, tzinfo=UTC))),
        ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
         "friday-afternoon-ddos",
         (datetime(2017, 7, 7, 13, 0, tzinfo=UTC), datetime(2017, 7, 7, 17, 0, tzinfo=UTC))),
        ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
         "friday-afternoon-portscan",
         (datetime(2017, 7, 7, 13, 0, tzinfo=UTC), datetime(2017, 7, 7, 17, 0, tzinfo=UTC))),
        ("Friday-WorkingHours-Morning.pcap_ISCX.csv",
         "friday-morning-botnet",
         None),
        ("Wednesday-workingHours.pcap_ISCX.csv",
         "wednesday-dos",
         None),
    ]

    loaded = load_artifacts(out / "baseline")
    results = []

    for csv_name, test_id, test_window in test_days:
        csv_path = data_dir / csv_name
        if not csv_path.exists():
            print(f"SKIP {test_id}: {csv_path} not found")
            continue

        print(f"\n--- Testing {test_id} ---")
        labelled_test, stats = _load_day(
            csv_path, test_id, test_window,
            args.window_seconds, args.stride_seconds,
        )
        print(f"  {stats.rows_converted} flows -> {len(labelled_test)} windows")

        by_scenario[test_id] = labelled_test

        def _rollout(states, _a, *, max_horizon, threshold):
            result = rollout_forecast(
                states, transition, loaded.baseline_model,
                loaded.baseline_result.feature_schema,
                max_horizon=max_horizon, threshold=threshold,
            )
            return result[0] if isinstance(result, tuple) else result

        thresholds = {"calibrated": None, "default_0.50": 0.50}
        evaluations = {}
        for t_name, t_val in thresholds.items():
            per = evaluate_replay(
                labelled_test, loaded,
                horizon=args.horizon,
                threshold=t_val,
                split_filter=None,
            )
            roll = evaluate_replay(
                labelled_test, loaded,
                horizon=args.horizon,
                threshold=t_val,
                split_filter=None,
                forecast_fn=_rollout,
                min_history=args.history,
            )
            evaluations[t_name] = {
                "per_horizon": {
                    "median_lead": per.measured_median_lead_windows,
                    "crossing_rate": per.forecast_crossing_rate,
                    "false_early": per.false_early_warning_rate,
                },
                "rollout": {
                    "median_lead": roll.measured_median_lead_windows,
                    "crossing_rate": roll.forecast_crossing_rate,
                    "false_early": roll.false_early_warning_rate,
                },
            }

        result = {
            "attack_family": test_id,
            "flows": stats.rows_converted,
            "windows": len(labelled_test),
            "evaluations": evaluations,
        }
        results.append(result)

        per = evaluations["default_0.50"]["per_horizon"]
        print(f"  Per-horizon (0.50): lead={per['median_lead']}, crossing={per['crossing_rate']:.0%}, false_early={per['false_early']:.0%}")

    # --- Save ---
    report = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "protocol": "Train Tuesday (FTP/SSH-Patator), validate Thursday-morning (Web Attacks), test each day",
        "train_windows": len(labelled_train),
        "validation_windows": len(labelled_validation),
        "results": results,
    }
    (out / "multi_day_results.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    print(f"\nResults saved to {out / 'multi_day_results.json'}")


if __name__ == "__main__":
    main()
