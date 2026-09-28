"""Rolling-origin backtest: retrain at each origin, measure degradation honestly.

The headline metrics elsewhere in this repo come from one model trained once on
a fixed split. That answers "how good is this model", not "what happens to it as
the network drifts". This script answers the second question: it walks forward
through the data, retraining from scratch at every origin using only what was
available before it, and evaluating on the fold that follows.

Why this is not the same number as ``run_replay.py``:

* the model is refit per origin, so no fold ever influenced the weights that
  scored it;
* the decision threshold is calibrated on the validation slice of the *same*
  origin, never on the fold being scored;
* population stability index is reported per origin, so a metric drop can be
  attributed to drift rather than guessed at.

    uv run python scripts/run_backtest.py --output reports/generated/backtest

Every number printed here was produced by this run on synthetic data. Nothing
is carried over from a previous run or from documentation.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import numpy as np

from sentinel.baseline import train_baseline
from sentinel.calibration import calibrate_threshold
from sentinel.config import BaselineConfig
from sentinel.drift import EXCEEDS_NULL, compare_feature
from sentinel.evaluation import evaluate_replay
from sentinel.features import vectorize_states
from sentinel.predict import artifacts_from_runs
from sentinel.synthetic import DATASET_ID, generate_labelled_states
from sentinel.targets import build_sequence_samples, make_split_manifest

BACKTEST_VERSION = "rolling-origin-backtest-v2"

# Only the features whose movement most often accompanies a change in attack
# behaviour. A PSI over every one of 98 features would bury the signal in noise
# and invite the reader to treat any number as meaningful.
WATCHED_FEATURES = (
    "flow_count",
    "total_bytes",
    "bytes_max",
    "flow_duration_mean",
    "dst_port_count",
    "flag_psh_ratio",
    "syn_ratio",
    "unique_dst_count",
)


@dataclass(frozen=True)
class OriginResult:
    """One retrain-and-score cycle."""

    origin: int
    train_scenarios: tuple[str, ...]
    validation_scenarios: tuple[str, ...]
    test_scenarios: tuple[str, ...]
    threshold: float
    direction_accuracy: float
    forecast_crossing_rate: float
    false_early_warning_rate: float
    pre_onset_warning_rate: float
    during_attack_detection_rate: float
    median_lead_windows: float | None
    max_feature_psi: float
    worst_feature: str
    drifted_features: tuple[str, ...]


def _psi_table(
    reference: list[dict[str, float]],
    current: list[dict[str, float]],
    null_rows: list[dict[str, float]] | None = None,
) -> list[tuple[str, float, str | None]]:
    """PSI per watched feature, skipping any absent from either side.

    ``null_rows`` are held-out rows from the same population as ``reference`` -
    the validation scenarios here. They supply the threshold the band is measured
    against; without them no band is emitted. The previous version called anything
    above 0.25 "drifted", which Sprint 8 showed is what *every* block of ordinary
    noise exceeds.
    """
    names = [f for f in WATCHED_FEATURES if f in reference[0] and f in current[0]]
    blocks = _null_blocks(null_rows, names) if null_rows else None
    return [
        (
            name,
            compare_feature(
                name,
                [row[name] for row in reference],
                [row[name] for row in current],
                null_blocks=blocks.get(name) if blocks else None,
            ),
        )
        for name in names
    ]


#: Contiguous chunks the held-out rows are cut into. A block is one unit of
#: observation, and PSI depends on block size, so the same size is used to place
#: the threshold and to place the observation.
NULL_BLOCKS = 4


def _null_blocks(
    null_rows: list[dict[str, float]], names: list[str]
) -> dict[str, list[list[float]]]:
    usable = [row for row in null_rows if all(name in row for name in names)]
    if len(usable) < NULL_BLOCKS:
        return {}
    size = len(usable) // NULL_BLOCKS
    return {
        name: [
            [row[name] for row in usable[index * size : (index + 1) * size]]
            for index in range(NULL_BLOCKS)
        ]
        for name in names
    }


def run_backtest(
    *,
    scenarios: list[str],
    seed: int = 42,
    origins: int = 4,
    fold_size: int = 2,
    window_seconds: int = 60,
    stride_seconds: int = 60,
    sequence_length: int = 2,
    horizon: int = 3,
) -> tuple[list[OriginResult], list[str]]:
    """Walk forward, retraining at each origin. Returns rows and any warnings."""
    # Each origin needs at least one train fold, a validation fold and a test
    # fold, so the earliest origin starts at two warm-up folds in.
    needed = (origins + 3) * fold_size
    if len(scenarios) < needed:
        raise ValueError(
            f"{origins} origins of {fold_size} scenarios need {needed} scenarios "
            f"(2 warm-up folds plus one test fold per origin), got {len(scenarios)}"
        )
    labelled = generate_labelled_states(
        scenarios[:needed],
        seed=seed,
        window_seconds=window_seconds,
        stride_seconds=stride_seconds,
    )
    by_scenario: dict[str, list] = {}
    for item in labelled:
        by_scenario.setdefault(item.scenario_id, []).append(item)

    rows: list[OriginResult] = []
    warnings: list[str] = []
    for origin in range(origins):
        # Layout per origin: [...train folds][validation fold][test fold].
        # The test fold is the newest data and is never used to fit anything.
        end = (origin + 3) * fold_size
        test_ids = scenarios[end - fold_size : end]
        validation_ids = scenarios[end - 2 * fold_size : end - fold_size]
        train_ids = scenarios[: end - 2 * fold_size]

        seen_states = [s for sid in scenarios[:end] for s in by_scenario[sid]]
        manifest = make_split_manifest(train_ids + validation_ids + test_ids, seed=seed).model_copy(
            update={
                "train_scenarios": list(train_ids),
                "validation_scenarios": list(validation_ids),
                "test_scenarios": list(test_ids),
            }
        )

        samples = build_sequence_samples(
            seen_states, sequence_length=sequence_length, horizon=horizon
        )
        run = train_baseline(
            seen_states,
            samples,
            manifest,
            config=BaselineConfig(decision_threshold=0.5),
            seed=seed + origin,
        )

        # Threshold calibration sees validation probabilities only.
        validation_samples = [s for s in samples if s.scenario_id in validation_ids]
        if validation_samples:
            states_by_key = {item.state_key: item for item in seen_states}
            validation_x = vectorize_states(
                [states_by_key[s.input_state_keys[-1]].state for s in validation_samples],
                run.result.feature_schema,
            )
            calibration = calibrate_threshold(
                list(run.model.predict_proba(validation_x)[:, 1]),
                [s.target.target_infiltration for s in validation_samples],
            )
            threshold = float(calibration.best_threshold)
        else:
            threshold = 0.5
            warnings.append(f"origin {origin}: no validation samples; fell back to threshold 0.5")

        artifacts = artifacts_from_runs(run)
        evaluation = evaluate_replay(
            [s for sid in test_ids for s in by_scenario[sid]],
            artifacts,
            horizon=horizon,
            threshold=threshold,
            split_filter=None,
        )

        reference_rows = _feature_rows(seen_states, run.result.feature_schema)
        current_rows = _feature_rows(
            [s for sid in test_ids for s in by_scenario[sid]], run.result.feature_schema
        )
        null_rows = _feature_rows(
            [s for sid in validation_ids for s in by_scenario[sid]], run.result.feature_schema
        )
        psi = _psi_table(reference_rows, current_rows, null_rows)
        worst_name, worst_report = max(psi, key=lambda pair: pair[1].psi, default=(None, None))
        worst_value = worst_report.psi if worst_report else 0.0
        drifted = tuple(name for name, report in psi if report.band == EXCEEDS_NULL)

        rows.append(
            OriginResult(
                origin=origin,
                train_scenarios=tuple(train_ids),
                validation_scenarios=tuple(validation_ids),
                test_scenarios=tuple(test_ids),
                threshold=threshold,
                direction_accuracy=float(
                    np.mean([row.correct_direction for row in evaluation.rows])
                    if evaluation.rows
                    else 0.0
                ),
                forecast_crossing_rate=evaluation.forecast_crossing_rate,
                false_early_warning_rate=evaluation.false_early_warning_rate,
                pre_onset_warning_rate=evaluation.pre_onset_warning_rate,
                during_attack_detection_rate=evaluation.during_attack_detection_rate,
                median_lead_windows=evaluation.measured_median_lead_windows,
                max_feature_psi=worst_value,
                worst_feature=worst_name,
                drifted_features=drifted,
            )
        )
    return rows, warnings


def _feature_rows(labelled, schema) -> list[dict[str, float]]:
    """One feature dict per window, unwrapping the labelled-state envelope."""
    matrix = vectorize_states([item.state for item in labelled], schema)
    return [dict(zip(schema.names, row, strict=True)) for row in matrix]


def _summarise(rows: list[OriginResult]) -> dict[str, float]:
    def mean(selector) -> float:
        return float(np.mean([selector(row) for row in rows])) if rows else 0.0

    leads = [row.median_lead_windows for row in rows if row.median_lead_windows is not None]
    return {
        "origins": float(len(rows)),
        "mean_direction_accuracy": mean(lambda r: r.direction_accuracy),
        "mean_forecast_crossing_rate": mean(lambda r: r.forecast_crossing_rate),
        "mean_false_early_warning_rate": mean(lambda r: r.false_early_warning_rate),
        "mean_pre_onset_warning_rate": mean(lambda r: r.pre_onset_warning_rate),
        "mean_during_attack_detection_rate": mean(lambda r: r.during_attack_detection_rate),
        "mean_max_feature_psi": mean(lambda r: r.max_feature_psi),
        "median_lead_windows": float(np.median(leads)) if leads else float("nan"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=int, default=14)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--origins", type=int, default=4)
    parser.add_argument("--fold-size", type=int, default=2)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--stride-seconds", type=int, default=60)
    parser.add_argument("--sequence-length", type=int, default=2)
    parser.add_argument("--horizon", type=int, default=3)
    parser.add_argument("--output", default="reports/generated/backtest")
    args = parser.parse_args()

    scenarios = [f"bo{i:02d}" for i in range(args.scenarios)]
    rows, warnings = run_backtest(
        scenarios=scenarios,
        seed=args.seed,
        origins=args.origins,
        fold_size=args.fold_size,
        window_seconds=args.window_seconds,
        stride_seconds=args.stride_seconds,
        sequence_length=args.sequence_length,
        horizon=args.horizon,
    )

    payload = {
        "backtest_version": BACKTEST_VERSION,
        "dataset_id": DATASET_ID,
        "generated_at": datetime.now(UTC).isoformat(),
        "origins": args.origins,
        "fold_size": args.fold_size,
        "horizon": args.horizon,
        "rows": [row.__dict__ for row in rows],
        "summary": _summarise(rows),
        "warnings": warnings
        + [
            "All figures are from synthetic data generated by this run. They do "
            "not describe real network traffic.",
        ],
    }
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "backtest.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out / "backtest.md").write_text(_render(payload), encoding="utf-8")

    for row in rows:
        print(
            f"origin {row.origin}: dir_acc={row.direction_accuracy:.2f} "
            f"cross={row.forecast_crossing_rate:.2f} "
            f"false_early={row.false_early_warning_rate:.2f} "
            f"threshold={row.threshold:.2f} "
            f"max_psi={row.max_feature_psi:.2f} ({row.worst_feature})"
        )
    summary = payload["summary"]
    print(
        f"mean_direction_accuracy={summary['mean_direction_accuracy']:.2f} "
        f"mean_false_early_warning_rate={summary['mean_false_early_warning_rate']:.2f}"
    )
    for warning in payload["warnings"]:
        print(f"warning: {warning}")
    print(f"backtest_json={out / 'backtest.json'}")
    print(f"backtest_md={out / 'backtest.md'}")


def _render(payload: dict) -> str:
    lines = [
        "# Rolling-origin backtest",
        "",
        f"- version: `{payload['backtest_version']}`",
        f"- dataset: `{payload['dataset_id']}` (**synthetic**, generated by this run)",
        f"- generated: {payload['generated_at']}",
        f"- origins: {payload['origins']}, fold size: {payload['fold_size']}, "
        f"horizon: {payload['horizon']}",
        "",
        "At each origin the model is retrained from scratch on the scenarios seen "
        "so far, the threshold is calibrated on that origin's validation slice, and "
        "only the following fold is scored.",
        "",
        "| origin | threshold | direction acc | crossing rate | false early | "
        "pre-onset warn | during-attack detect | median lead | max PSI | worst feature |",
        "|---|---|---|---|---|---|---|---|---|---|",
    ]
    for row in payload["rows"]:
        lead = "none" if row["median_lead_windows"] is None else f"{row['median_lead_windows']:.1f}"
        lines.append(
            f"| {row['origin']} | {row['threshold']:.2f} | {row['direction_accuracy']:.2f} | "
            f"{row['forecast_crossing_rate']:.2f} | {row['false_early_warning_rate']:.2f} | "
            f"{row['pre_onset_warning_rate']:.2f} | {row['during_attack_detection_rate']:.2f} | "
            f"{lead} | {row['max_feature_psi']:.2f} | {row['worst_feature']} |"
        )
    summary = payload["summary"]
    lines += [
        "",
        "## Across origins",
        "",
        f"- mean direction accuracy: {summary['mean_direction_accuracy']:.2f}",
        f"- mean false early-warning rate: {summary['mean_false_early_warning_rate']:.2f}",
        f"- mean pre-onset warning rate: {summary['mean_pre_onset_warning_rate']:.2f}",
        f"- mean during-attack detection rate: {summary['mean_during_attack_detection_rate']:.2f}",
        f"- mean worst-feature PSI: {summary['mean_max_feature_psi']:.2f}",
    ]
    drifted = sorted({f for row in payload["rows"] for f in row["drifted_features"]})
    lines.append(
        f"- features exceeding their calibrated null at some origin: "
        f"{', '.join(drifted) if drifted else 'none'}"
    )
    lines += ["", "## Warnings", ""]
    lines += [f"- {warning}" for warning in payload["warnings"]]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
