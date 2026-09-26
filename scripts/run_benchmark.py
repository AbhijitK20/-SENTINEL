"""One-command reproducible benchmark: train, calibrate, evaluate, report.

    uv run python scripts/run_benchmark.py --output reports/generated/benchmark

Orchestrates the tested pipeline scripts into a single deterministic run:

1. ``run_comparison.py``  — trains baseline + temporal, writes artifacts.
2. ``run_calibration.py`` — leakage-safe threshold on validation split.
3. Copies ``calibration.json`` beside the baseline artifacts so every later
   step (and the dashboard) auto-loads the calibrated threshold.
4. ``run_replay.py``      — walk-forward evaluation at default and calibrated
   thresholds on identical windows.
5. ``run_rollout.py``     — recursive rollout vs per-horizon comparison.
6. ``run_forecast.py``    — demo forecast from the saved artifacts.
7. Aggregates everything into ``benchmark.json`` and ``BENCHMARK.md``.

All numbers come from typed contracts; the report separates what may be
claimed (pipeline validation on synthetic replay) from what may not (real
traffic performance).
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = REPO_ROOT / "scripts"


def _run(name: str, args: list[str]) -> None:
    """Run one pipeline script; fail loudly on non-zero exit."""
    command = [sys.executable, str(SCRIPTS / name), *args]
    print(f"[benchmark] {' '.join(command)}")
    completed = subprocess.run(command, cwd=REPO_ROOT, capture_output=True, text=True, timeout=1800)
    if completed.returncode != 0:
        print(completed.stdout)
        print(completed.stderr, file=sys.stderr)
        raise SystemExit(f"[benchmark] {name} failed with exit code {completed.returncode}")
    for line in completed.stdout.strip().splitlines():
        print(f"[benchmark]   {line}")


def _read_json(path: Path) -> dict:
    if not path.is_file():
        raise SystemExit(f"[benchmark] expected artifact missing: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--scenarios", type=int, default=10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--horizon", type=int, default=5)
    parser.add_argument("--output", default="reports/generated/benchmark")
    args = parser.parse_args()

    out = Path(args.output)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    pipeline = out / "pipeline"

    # 1. Train baseline + temporal, write artifacts.
    _run(
        "run_comparison.py",
        ["--config", args.config, "--output", str(pipeline), "--scenarios", str(args.scenarios)],
    )

    # 2. Calibrate on the validation split, then 3. auto-wire the threshold.
    _run("run_calibration.py", ["--config", args.config, "--output", str(out / "calibration")])
    calibration = _read_json(out / "calibration" / "calibration.json")
    best_threshold = float(calibration["best_threshold"])
    shutil.copy(
        out / "calibration" / "calibration.json",
        pipeline / "baseline" / "calibration.json",
    )

    baseline_dir = str(pipeline / "baseline")
    temporal_dir = str(pipeline / "temporal")

    # 4. Walk-forward replay: calibrated and default thresholds.
    _run(
        "run_replay.py",
        [
            "--baseline",
            baseline_dir,
            "--temporal",
            temporal_dir,
            "--threshold",
            f"{best_threshold:.2f}",
            "--scenarios",
            str(args.scenarios),
            "--seed",
            str(args.seed),
            "--horizon",
            str(args.horizon),
            "--output",
            str(out / "replay_calibrated"),
        ],
    )
    _run(
        "run_replay.py",
        [
            "--baseline",
            baseline_dir,
            "--temporal",
            temporal_dir,
            # Pin 0.50 explicitly: auto-resolution would otherwise pick up the
            # calibrated threshold we just wired into the artifacts.
            "--threshold",
            "0.50",
            "--scenarios",
            str(args.scenarios),
            "--seed",
            str(args.seed),
            "--horizon",
            str(args.horizon),
            "--output",
            str(out / "replay_default"),
        ],
    )

    # 5. Rollout comparison; 6. demo forecast.
    _run(
        "run_rollout.py",
        [
            "--baseline",
            baseline_dir,
            "--scenarios",
            str(args.scenarios),
            "--seed",
            str(args.seed),
            "--horizon",
            str(args.horizon),
            "--output",
            str(out / "rollout"),
        ],
    )
    _run(
        "run_forecast.py",
        [
            "--baseline",
            baseline_dir,
            "--temporal",
            temporal_dir,
            "--output",
            str(out / "forecast.json"),
        ],
    )

    # 7. World model: train the RSSM, then score open-loop state prediction
    #    against the linear transition model and persistence on identical
    #    test-scenario windows, plus the imagination forecaster in replay.
    _run(
        "run_world_model.py",
        [
            "--config",
            args.config,
            "--baseline",
            baseline_dir,
            "--scenarios",
            str(args.scenarios),
            "--seed",
            str(args.seed),
            "--horizon",
            str(args.horizon),
            "--output",
            str(out / "world_model"),
        ],
    )

    # 8. Aggregate.
    benchmark = _aggregate(args, out, calibration, best_threshold)
    (out / "benchmark.json").write_text(json.dumps(benchmark, indent=2), encoding="utf-8")
    (out / "BENCHMARK.md").write_text(_render_markdown(benchmark), encoding="utf-8")
    print(f"[benchmark] benchmark.json={out / 'benchmark.json'}")
    print(f"[benchmark] BENCHMARK.md={out / 'BENCHMARK.md'}")


def _aggregate(args, out: Path, calibration: dict, best_threshold: float) -> dict:
    baseline = _read_json(out / "pipeline" / "baseline" / "baseline_result.json")
    temporal = _read_json(out / "pipeline" / "temporal" / "temporal_result.json")
    replay_cal = _read_json(out / "replay_calibrated" / "replay.json")
    replay_def = _read_json(out / "replay_default" / "replay.json")
    rollout = _read_json(out / "rollout" / "rollout.json")
    forecast = _read_json(out / "forecast.json")
    world = _read_json(out / "world_model" / "world_model_benchmark.json")

    last_horizon = temporal["horizons"][-1] if temporal["horizons"] else None
    return {
        "generated_at": datetime.now(tz=UTC).isoformat(),
        "experiment": {
            "config": args.config,
            "seed": args.seed,
            "scenarios": args.scenarios,
            "horizon": args.horizon,
            "dataset_id": "synthetic-recon-lateral-v2",
            "feature_version": baseline["feature_schema"]["version"],
            "baseline_model_version": baseline["model_version"],
            "temporal_model_version": temporal["model_version"],
        },
        "baseline_test": baseline["metrics"]["test"],
        "temporal_last_horizon": {
            "horizon": last_horizon["horizon"],
            "metrics": last_horizon["metrics"]["test"],
        }
        if last_horizon
        else None,
        "calibration": {
            "objective": calibration["objective"],
            "best_threshold": best_threshold,
            "default_threshold": calibration["default_threshold"],
            "validation_f1_at_best": _candidate_f1(calibration, best_threshold),
            "validation_f1_at_default": _candidate_f1(
                calibration, calibration["default_threshold"]
            ),
            "sample_count": calibration["sample_count"],
        },
        "replay_default": _replay_summary(replay_def),
        "replay_calibrated": _replay_summary(replay_cal),
        "rollout": {
            "per_horizon": _replay_summary(rollout["default"]),
            "recursive": _replay_summary(rollout["rollout"]),
        },
        "demo_forecast": {
            "peak_probability": max(
                point["infiltration_probability"] for point in forecast["probability_timeline"]
            ),
            "predicted_stage": forecast["predicted_stage"]["name"],
            "lead_windows": (forecast.get("lead_time") or {}).get("lead_windows"),
            "threshold": (forecast.get("lead_time") or {}).get("threshold"),
        },
        "world_model": {
            "model_version": world["model"]["model_version"],
            "core_type": world["experiment"]["core_type"],
            "best_epoch": world["model"]["best_epoch"],
            "training_seconds": world["model"]["training_seconds"],
            "test_reconstruction_mse": world["model"]["split_metrics"]["test"][
                "reconstruction_mse"
            ],
            "test_kl_nats": world["model"]["split_metrics"]["test"]["kl_nats"],
            "test_stage_macro_f1": world["model"]["split_metrics"]["test"]["stage_macro_f1"],
            "open_loop_skill": {
                key: world["open_loop"][key]["skill"]
                for key in ("world_model", "linear_transition", "ablation_no_rollout_loss")
                if world["open_loop"].get(key)
            },
            "forecast_comparison": world.get("forecast_comparison"),
        },
    }


def _candidate_f1(calibration: dict, threshold: float) -> float | None:
    for candidate in calibration["candidates"]:
        if abs(candidate["threshold"] - threshold) < 1e-9:
            return candidate["f1"]
    return None


def _replay_summary(replay: dict) -> dict:
    return {
        "decision_threshold": replay["decision_threshold"],
        "median_lead_windows": replay["measured_median_lead_windows"],
        "crossing_rate": replay["forecast_crossing_rate"],
        "false_early_warning_rate": replay["false_early_warning_rate"],
        "scenarios_evaluated": replay["scenarios_evaluated"],
    }


def _fmt(value: float | None, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _render_markdown(b: dict) -> str:
    baseline, temporal = b["baseline_test"], b["temporal_last_horizon"]
    calibration = b["calibration"]
    replay_cal, replay_def = b["replay_calibrated"], b["replay_default"]
    world = b["world_model"]
    rollout = b["rollout"]
    demo = b["demo_forecast"]
    experiment = b["experiment"]

    lines = [
        "# Trajectory Benchmark Report",
        "",
        f"- Generated: {b['generated_at']}",
        f"- Dataset: `{experiment['dataset_id']}` (deterministic synthetic replay)",
        f"- Config: `{experiment['config']}` · seed {experiment['seed']} · "
        f"{experiment['scenarios']} scenarios · horizon +{experiment['horizon']}",
        f"- Feature version: `{experiment['feature_version']}`",
        f"- Models: `{experiment['baseline_model_version']}` vs "
        f"`{experiment['temporal_model_version']}`",
        "",
        "## Claim Status",
        "",
        "**These numbers validate the pipeline on synthetic replay data. They are "
        "not a benchmark claim on real traffic and must not appear in submission "
        "material as real-traffic results.**",
        "",
        "## Baseline vs Temporal (test split)",
        "",
        "| Metric | Baseline | Temporal h+"
        + (str(temporal["horizon"]) if temporal else "?")
        + " |",
        "|---|---:|---:|",
        f"| Precision | {_fmt(baseline['precision'])} | "
        f"{_fmt(temporal['metrics']['precision']) if temporal else 'n/a'} |",
        f"| Recall | {_fmt(baseline['recall'])} | "
        f"{_fmt(temporal['metrics']['recall']) if temporal else 'n/a'} |",
        f"| F1 | {_fmt(baseline['f1'])} | "
        f"{_fmt(temporal['metrics']['f1']) if temporal else 'n/a'} |",
        f"| FPR | {_fmt(baseline['false_positive_rate'])} | "
        f"{_fmt(temporal['metrics']['false_positive_rate']) if temporal else 'n/a'} |",
        f"| PR-AUC | {_fmt(baseline['pr_auc'])} | "
        f"{_fmt(temporal['metrics']['pr_auc']) if temporal else 'n/a'} |",
        "",
        "## Threshold Calibration (validation split only)",
        "",
        f"- Objective: `{calibration['objective']}` · best threshold "
        f"**{calibration['best_threshold']:.2f}** (default "
        f"{calibration['default_threshold']:.2f})",
        f"- Validation F1: {_fmt(calibration['validation_f1_at_best'])} at best vs "
        f"{_fmt(calibration['validation_f1_at_default'])} at default "
        f"({calibration['sample_count']} validation samples)",
        "",
        "## Forecast vs Reality (walk-forward replay)",
        "",
        "| Evaluation | Threshold | Median lead (win) | Crossing rate | False early |",
        "|---|---:|---:|---:|---:|",
        f"| Per-horizon (default) | {replay_def['decision_threshold']:.2f} | "
        f"{_fmt(replay_def['median_lead_windows'], 1)} | "
        f"{replay_def['crossing_rate']:.2f} | "
        f"{replay_def['false_early_warning_rate']:.2f} |",
        f"| Per-horizon (calibrated) | {replay_cal['decision_threshold']:.2f} | "
        f"{_fmt(replay_cal['median_lead_windows'], 1)} | "
        f"{replay_cal['crossing_rate']:.2f} | "
        f"{replay_cal['false_early_warning_rate']:.2f} |",
        f"| Recursive rollout | {rollout['recursive']['decision_threshold']:.2f} | "
        f"{_fmt(rollout['recursive']['median_lead_windows'], 1)} | "
        f"{rollout['recursive']['crossing_rate']:.2f} | "
        f"{rollout['recursive']['false_early_warning_rate']:.2f} |",
        "",
        "## Demo Forecast (saved artifacts)",
        "",
        f"- Peak probability: **{demo['peak_probability']:.3f}** → "
        f"{demo['predicted_stage']} · lead {demo['lead_windows']} window(s) "
        f"at threshold {demo['threshold']:.2f}",
        "",
        "## World Model — open-loop state prediction (test scenarios)",
        "",
        f"- Model: `{world['model_version']}` · core `{world['core_type']}` · best epoch "
        f"{world['best_epoch']} · {world['training_seconds']:.1f} s",
        f"- Test reconstruction MSE {world['test_reconstruction_mse']:.4f} · "
        f"KL {world['test_kl_nats']:.4f} nats · stage macro-F1 "
        f"{_fmt(world['test_stage_macro_f1'])}",
        "- Open-loop skill: `1 - imagined-vs-realized MAE / persistence MAE` on",
        "  standardized state features. Positive means the model predicts unseen",
        "  future windows better than repeating the last observed window.",
        "",
        "| Transition model | Open-loop skill |",
        "|---|---:|",
    ]
    for key, label in (
        ("world_model", "World model (RSSM)"),
        ("linear_transition", "Linear ridge transition"),
        ("ablation_no_rollout_loss", "Ablation: no open-loop objective"),
    ):
        skill = world["open_loop_skill"].get(key)
        lines.append(f"| {label} | {'n/a' if skill is None else f'{skill:+.3f}'} |")
    comparison = world.get("forecast_comparison") or {}
    if comparison:
        lines += [
            "",
            "| Forecaster (replay) | Median lead (win) | Crossing rate | False early |",
            "|---|---:|---:|---:|",
        ]
        for name, row in comparison.items():
            lines.append(
                f"| {name} | {_fmt(row['median_lead_windows'], 1)} | "
                f"{row['crossing_rate']:.2f} | {row['false_early_warning_rate']:.2f} |"
            )

    lines += [
        "",
        "## Limitations",
        "",
        "- Synthetic replay transitions stages abruptly; measured lead time is 0.0",
        "  windows because reconnaissance is labelled non-infiltration and features",
        "  switch within one window. Real datasets with attack dwell time are",
        "  required to demonstrate lead > 0 (CIC-IDS2017 adapter is implemented; a",
        "  licensed real-data run is pending).",
        "- The per-horizon forecaster is nowcast, not rollout. The recursive linear",
        "  rollout and the RSSM imagination forecaster both simulate forward; the",
        "  open-loop table above is the fair comparison between transition models.",
        "- Probabilities are model evidence, not certainty; a positive forecast is",
        "  decision support, never automatic response.",
    ]
    return "\n".join(lines)


if __name__ == "__main__":
    main()
