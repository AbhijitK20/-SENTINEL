"""Full real-data benchmark on CIC-IDS2017 with a cross-day temporal split.

    uv run python scripts/run_real_benchmark.py \
        --data-dir data/raw/cic-ids2017/TrafficLabelling \
        --output reports/generated/real-benchmark

Leakage-safe protocol respecting strict temporal order across days:

- TRAIN      Tuesday 2017-07-04, full working day (08:00-17:00).
             Brute Force attacks (FTP/SSH-Patator) provide positives.
- VALIDATION Thursday 2017-07-06 morning (08:00-12:59).
             Web Attacks provide positives for threshold calibration.
- TEST       Thursday 2017-07-06 afternoon (13:00-17:00).
             Covers the published Infiltration window 14:19-15:45
             (UNB schedule) plus benign tail.

Models never see any window from or after the test period. The dataset is
used under its published research terms with the required citation
(Sharafaldin, Lashkari & Ghorbani, ICISSP 2018); no data is committed.

Dataset defects handled inside the adapter (all verified against the raw
files and documented there): 12-hour clock without AM/PM (hours 1-7 are PM),
cp1252-encoded morning file with en-dash labels, 288,602 appended void rows
in the morning file, leading-space headers and plural column variants.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from trajectory.baseline import (
    BaselineConfig,
    save_baseline_artifacts,
    train_baseline,
)
from trajectory.calibration import calibrate_threshold
from trajectory.cic_ids2017 import AdapterStats, build_labelled_states
from trajectory.cic_ids2017 import load_flow_csv_with_stats as _load_flow
from trajectory.evaluation import evaluate_replay
from trajectory.features import vectorize_states
from trajectory.predict import DECISION_THRESHOLD, load_artifacts
from trajectory.rollout import fit_transition_model, rollout_forecast
from trajectory.schemas import SplitManifest
from trajectory.targets import build_sequence_samples

SEED = 42


def _label_of(event) -> str:
    """Recover the raw CICFlowMeter label stored in event provenance."""
    return event.provenance.rsplit(":", 1)[1]


def _load_day(
    csv_path: Path,
    scenario_id: str,
    *,
    time_window: tuple[datetime, datetime] | None,
    window_seconds: int,
    stride_seconds: int,
):
    """One CSV -> (labelled states, adapter stats) for a single scenario."""
    events, stats = _load_flow(csv_path, scenario_id=scenario_id, time_window=time_window)
    if not events:
        raise SystemExit(f"no flows loaded from {csv_path}; check the time window")
    flow_labels = [(event.timestamp, _label_of(event)) for event in events]
    labelled = build_labelled_states(
        events,
        flow_labels,
        window_seconds=window_seconds,
        stride_seconds=stride_seconds,
        scenario_id=scenario_id,
    )
    return labelled, stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--data-dir",
        default="data/raw/cic-ids2017/TrafficLabelling",
        help="Directory holding the extracted TrafficLabelling day CSVs",
    )
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--stride-seconds", type=int, default=150)
    parser.add_argument("--sequence-length", type=int, default=4)
    parser.add_argument("--horizon", type=int, default=3)
    parser.add_argument("--history", type=int, default=3)
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Pin the decision threshold (default: auto-resolve from calibration.json)",
    )
    parser.add_argument("--output", default="reports/generated/real-benchmark")
    args = parser.parse_args()

    data_dir = Path(args.data_dir)
    csv_train = (
        data_dir / "Tuesday-WorkingHours.pcap_ISCX.csv",
        "tuesday-train",
        None,  # full working day
    )
    csv_validation = (
        data_dir / "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
        "thursday-morning-validation",
        None,  # morning file: hours 8-12 (void rows skipped by the adapter)
    )
    afternoon_start = datetime(2017, 7, 6, 13, 0, tzinfo=UTC)
    afternoon_end = datetime(2017, 7, 6, 17, 0, tzinfo=UTC)
    csv_test = (
        data_dir / "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "thursday-afternoon-test",
        (afternoon_start, afternoon_end),
    )

    labelled_parts: list = []
    stats_by_phase: dict[str, AdapterStats] = {}
    for csv_path, scenario_id, window in (csv_train, csv_validation, csv_test):
        labelled, stats = _load_day(
            csv_path,
            scenario_id,
            time_window=window,
            window_seconds=args.window_seconds,
            stride_seconds=args.stride_seconds,
        )
        labelled_parts.append(labelled)
        stats_by_phase[scenario_id] = stats
        print(f"{scenario_id}: {stats.rows_converted} flows -> {len(labelled)} windows")

    labelled = [item for part in labelled_parts for item in part]
    manifest = SplitManifest(
        seed=SEED,
        train_scenarios=[csv_train[1]],
        validation_scenarios=[csv_validation[1]],
        test_scenarios=[csv_test[1]],
    )

    samples = build_sequence_samples(
        labelled,
        sequence_length=args.sequence_length,
        horizon=args.horizon,
    )
    if not samples:
        raise SystemExit("no sequence samples; reduce sequence length or horizon")

    # 1. Train on Tuesday only (leak audit inside train_baseline).
    run = train_baseline(
        labelled,
        samples,
        manifest,
        config=BaselineConfig(decision_threshold=DECISION_THRESHOLD),
        seed=SEED,
    )

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    save_baseline_artifacts(run, out / "baseline")

    # 2. Calibrate on Thursday-morning validation probabilities. Each sample's
    # target is the infiltration flag of the state `horizon` windows ahead
    # within the same scenario (windows are stride-ordered per scenario).
    schema = run.result.feature_schema
    by_scenario: dict[str, list] = {}
    for item in labelled:
        by_scenario.setdefault(item.scenario_id, []).append(item)
    validation = by_scenario[csv_validation[1]]
    probabilities: list[float] = []
    labels: list[bool] = []
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

    # 3. Replay evaluation on Thursday afternoon. Honest A/B: the calibrated
    # threshold AND the pinned 0.50 default on identical windows.
    loaded = load_artifacts(out / "baseline")

    # 4. Recursive rollout fitted on Tuesday training windows only.
    transition = fit_transition_model(
        labelled,
        history_length=args.history,
        scenario_ids=[csv_train[1]],
    )

    def rollout_fn(states, artifacts, *, max_horizon, threshold):
        return rollout_forecast(
            states,
            transition,
            artifacts.baseline_model,
            artifacts.baseline_result.feature_schema,
            max_horizon=max_horizon,
            threshold=threshold,
        )[0]

    thresholds: dict[str, float | None] = {
        "calibrated": args.threshold,  # None -> auto-resolve from calibration.json
        "default_0.50": 0.50,  # pinned for like-for-like A/B
    }
    evaluations: dict[str, dict] = {}
    for name, threshold in thresholds.items():
        evaluations[name] = {
            "per_horizon": evaluate_replay(
                labelled,
                loaded,
                horizon=args.horizon,
                threshold=threshold,
                split_filter="test",
                max_history=args.history,
                min_history=args.history,
            ).model_dump(),
            "rollout": evaluate_replay(
                labelled,
                loaded,
                horizon=args.horizon,
                threshold=threshold,
                split_filter="test",
                max_history=args.history,
                min_history=args.history,
                forecast_fn=rollout_fn,
            ).model_dump(),
        }

    # 5. Persist and report.
    label_counts: dict[str, int] = {}
    for item in labelled:
        key = f"{item.scenario_id}:{item.label.attack_stage}"
        label_counts[key] = label_counts.get(key, 0) + 1

    result = {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "dataset": "CIC-IDS2017 (TrafficLabelling CICFlowMeter CSVs)",
        "citation": "Sharafaldin, Lashkari & Ghorbani, ICISSP 2018",
        "protocol": {
            "train": "Tuesday 2017-07-04 full day (FTP/SSH-Patator)",
            "validation": "Thursday 2017-07-06 morning (Web Attacks)",
            "test": "Thursday 2017-07-06 afternoon (Infiltration 14:19-15:45)",
        },
        "window_seconds": args.window_seconds,
        "stride_seconds": args.stride_seconds,
        "sequence_length": args.sequence_length,
        "horizon": args.horizon,
        "history": args.history,
        "seed": SEED,
        "adapter_stats": {
            scenario: stats.model_dump() for scenario, stats in stats_by_phase.items()
        },
        "windows": {scenario: len(items) for scenario, items in by_scenario.items()},
        "label_counts": label_counts,
        "calibration": {
            "best_threshold": calibration.best_threshold,
            "default_threshold": calibration.default_threshold,
            "pinned_threshold": args.threshold,
            "validation_samples": calibration.sample_count,
            "warnings": calibration.warnings,
        },
        "evaluations": evaluations,
    }
    (out / "real_benchmark.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    (out / "REAL_BENCHMARK.md").write_text(_render_markdown(result), encoding="utf-8")

    print(f"calibrated_threshold={calibration.best_threshold:.2f} windows={result['windows']}")
    for eval_name, pair in evaluations.items():
        for kind in ("per_horizon", "rollout"):
            ev = pair[kind]
            lead = ev["measured_median_lead_windows"]
            print(
                f"{eval_name}/{kind}: median_lead="
                f"{'none' if lead is None else f'{lead:.1f}'} "
                f"crossing={ev['forecast_crossing_rate']:.2f} "
                f"false_early={ev['false_early_warning_rate']:.2f}"
            )
    print(f"report={out / 'REAL_BENCHMARK.md'}")


def _lead(value: float | None) -> str:
    return "none" if value is None else f"{value:.1f}"


def _render_markdown(result: dict) -> str:
    lines = [
        "# Real-Data Benchmark — CIC-IDS2017",
        "",
        f"- Generated: {result['generated_at']}",
        f"- Dataset: {result['dataset']} — citation required: {result['citation']}. "
        "No dataset content is committed to the repository.",
        "- Protocol (strict temporal order across days):",
        f"  - TRAIN: {result['protocol']['train']}",
        f"  - VALIDATION: {result['protocol']['validation']}",
        f"  - TEST: {result['protocol']['test']}",
        f"- Windows: {result['window_seconds']} s / stride {result['stride_seconds']} s · "
        f"sequence {result['sequence_length']} · horizon +{result['horizon']} · "
        f"seed {result['seed']}",
        f"- Windows per split: {result['windows']}",
        f"- Calibration: threshold {result['calibration']['best_threshold']:.2f} "
        f"from {result['calibration']['validation_samples']} validation samples "
        f"(warnings: {result['calibration']['warnings'] or 'none'})",
        "",
        "### Adapter statistics (documented dataset defects handled)",
        "",
    ]
    for scenario, stats in result["adapter_stats"].items():
        lines.append(
            f"- {scenario}: {stats['rows_read']} rows read, "
            f"{stats['rows_converted']} converted, {stats['rows_rejected']} rejected, "
            f"{stats['rows_void']} void (packaging defect)"
        )
    lines += [
        "",
        "## Forecast vs Reality (test phase: Thursday afternoon, after all training data)",
        "",
        "Both thresholds score identical windows: the validation-calibrated value "
        "and the pinned 0.50 default.",
        "",
        "| Threshold | Forecaster | Median lead (win) | Crossing rate | False early |",
        "|---|---|---:|---:|---:|",
    ]
    for eval_name, pair in result["evaluations"].items():
        for kind, label in (("per_horizon", "Per-horizon"), ("rollout", "Recursive rollout")):
            ev = pair[kind]
            lines.append(
                f"| {eval_name} ({ev['decision_threshold']:.2f}) | {label} | "
                f"{_lead(ev['measured_median_lead_windows'])} | "
                f"{ev['forecast_crossing_rate']:.2f} | "
                f"{ev['false_early_warning_rate']:.2f} |"
            )
    lines += [
        "",
        "## Claim Status",
        "",
        "**This is a real-traffic result on CIC-IDS2017 with cross-day temporal "
        "splits. It demonstrates the pipeline end-to-end on real data. The test "
        "phase contains a single attack family (36 Infiltration flows); this is "
        "NOT a general performance claim.**",
        "",
        "## Limitations",
        "",
        "- Two days of one capture week; the test attack family (Infiltration) "
        "never appears in training, which is realistic for zero-day-style "
        "evaluation but limits score comparability.",
        "- Extreme class imbalance: 36 attack flows vs ~287k benign on the test "
        "day; window-level positives are a handful of windows.",
        "- CICFlowMeter timestamps carry the documented 12-hour defect; the "
        "adapter's correction was validated against the published UNB schedule "
        "(Infiltration lands at 14:19-15:45).",
        "- Window labels derive from flow labels via documented precedence; no "
        "independent stage ground truth exists.",
        "- Lead time is measured against label onset under those labelling rules.",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
