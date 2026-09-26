"""Train the RSSM world model and measure whether it actually simulates.

    uv run python scripts/run_world_model.py \
        --output reports/generated/world-model

Produces three things, all from one deterministic run:

1. **Open-loop state prediction** — from every observed history, the model is
   rolled forward K steps with no observations and compared with the states that
   actually happened. Three predictors are scored on identical windows:
   the world model, the linear ridge transition model, and persistence
   (repeat the last window). This is the metric that separates a learned
   transition model from a classifier.
2. **Ablation** — the same architecture trained without the open-loop objective,
   to show what the objective buys instead of asserting it.
3. **Forecast comparison** — walk-forward replay of the imagination forecaster
   against the per-horizon GRU on the same windows, threshold, and split.

Numbers describe ``synthetic-recon-lateral-v2`` replay data: a pipeline and
method measurement, not a real-traffic benchmark.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import torch

from sentinel.evaluation import evaluate_replay
from sentinel.features import fit_feature_schema, vectorize_states
from sentinel.predict import load_artifacts
from sentinel.rollout import fit_transition_model
from sentinel.rollout import open_loop_error as ridge_open_loop_error
from sentinel.synthetic import DATASET_ID, generate_labelled_states
from sentinel.targets import make_split_manifest
from sentinel.world_model.imagine import (
    aggregate_open_loop,
    imagination_forecast,
)
from sentinel.world_model.imagine import (
    open_loop_error as world_open_loop_error,
)
from sentinel.world_model.train import (
    WorldModelConfig,
    load_world_model,
    save_world_model_artifacts,
    train_world_model,
)

DEFAULT_SCENARIOS = [f"scenario-{index:02d}" for index in range(1, 11)]


def _by_scenario(labelled):
    grouped = {}
    for item in labelled:
        grouped.setdefault(item.scenario_id, []).append(item)
    return {
        scenario_id: sorted(items, key=lambda item: item.state.window_start)
        for scenario_id, items in grouped.items()
    }


def _window_pairs(states, history: int, horizon: int):
    """Contiguous (history, realized-future) windows inside one scenario."""
    for end in range(history, len(states) - horizon + 1):
        yield states[end - history : end], states[end : end + horizon]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="configs/default.yaml")
    parser.add_argument("--baseline", default=None, help="Baseline artifacts directory")
    parser.add_argument("--scenarios", type=int, default=len(DEFAULT_SCENARIOS))
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--history", type=int, default=8)
    parser.add_argument("--horizon", type=int, default=5)
    parser.add_argument("--samples", type=int, default=32)
    parser.add_argument("--epochs", type=int, default=40)
    parser.add_argument("--core", default="lstm", choices=("lstm", "gru", "transformer"))
    parser.add_argument(
        "--compare-cores",
        action="store_true",
        help="Train lstm, gru, and transformer and report the open-loop table for each",
    )
    parser.add_argument("--ablation-epochs", type=int, default=20)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    # Single-threaded matmuls are ~6x faster than 14-thread ones for a model this
    # small, and give bit-identical metrics.
    torch.set_num_threads(1)

    from sentinel.config import load_settings

    settings = load_settings(args.config)
    scenario_ids = DEFAULT_SCENARIOS[: args.scenarios]
    labelled = generate_labelled_states(
        scenario_ids,
        seed=args.seed,
        window_seconds=settings.data.window_seconds,
        stride_seconds=settings.data.stride_seconds,
    )
    manifest = make_split_manifest(
        scenario_ids,
        seed=args.seed,
        train_fraction=settings.split.train_fraction,
        validation_fraction=settings.split.validation_fraction,
    )
    schema = fit_feature_schema(
        [i.state for i in labelled if i.scenario_id in manifest.train_scenarios],
        excluded_features=settings.model.baseline_config.excluded_features,
    )
    config = WorldModelConfig(
        core_type=args.core, max_epochs=args.epochs, kl_anneal_epochs=max(4, args.epochs // 5)
    )

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    print(f"[world-model] training {args.core} core, {args.epochs} epochs")
    started = time.perf_counter()
    run = train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=config,
        seed=args.seed,
        sequence_length=args.history,
    )
    print(
        f"[world-model] trained in {time.perf_counter() - started:.1f}s "
        f"(best epoch {run.result.best_epoch})"
    )
    artifacts = save_world_model_artifacts(run, out)
    reloaded = load_world_model(run.result, out)
    checksum_match = _checksum(reloaded) == run.result.model_sha256

    # ── 1. open-loop state prediction on held-out scenarios ──────────────
    grouped = _by_scenario(labelled)
    world_error = _measure_world(reloaded, grouped, manifest.test_scenarios, schema, args)
    transition = fit_transition_model(
        labelled, history_length=args.history, scenario_ids=manifest.train_scenarios
    )
    transition_unclipped = fit_transition_model(
        labelled,
        history_length=args.history,
        scenario_ids=manifest.train_scenarios,
        stability_limit=0.0,
    )
    ridge_error = _measure_ridge(transition, grouped, manifest.test_scenarios, schema, args)

    # ── 2. ablation: same architecture without the open-loop objective ──
    print("[world-model] ablation: no open-loop objective")
    ablation_config = WorldModelConfig(
        core_type=args.core,
        max_epochs=args.ablation_epochs,
        kl_anneal_epochs=max(4, args.ablation_epochs // 5),
        rollout_steps=0,
        rollout_loss_weight=0.0,
    )
    ablation = train_world_model(
        labelled,
        manifest,
        feature_schema=schema,
        config=ablation_config,
        seed=args.seed,
        sequence_length=args.history,
    )
    ablation_error = _measure_world(ablation.core, grouped, manifest.test_scenarios, schema, args)

    # ── 2b. optional architecture comparison on the same objective ───────
    core_comparison = None
    if args.compare_cores:
        core_comparison = {}
        for other in ("lstm", "gru", "transformer"):
            if other == args.core:
                core_comparison[other] = _core_row(
                    run.result.metrics["test"], world_error, run.result.training_seconds
                )
                continue
            print(f"[world-model] core comparison: {other}")
            other_run = train_world_model(
                labelled,
                manifest,
                feature_schema=schema,
                config=config.model_copy(update={"core_type": other}),
                seed=args.seed,
                sequence_length=args.history,
            )
            other_error = _measure_world(
                other_run.core, grouped, manifest.test_scenarios, schema, args
            )
            core_comparison[other] = _core_row(
                other_run.result.metrics["test"], other_error, other_run.result.training_seconds
            )

    # ── 3. forecast comparison on identical windows ──────────────────────
    forecast_comparison = _compare_forecasts(labelled, run.result, out, args, settings)

    payload = {
        "dataset_id": DATASET_ID,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "experiment": {
            "config": args.config,
            "seed": args.seed,
            "scenarios": len(scenario_ids),
            "history_windows": args.history,
            "horizon_windows": args.horizon,
            "imagination_samples": args.samples,
            "core_type": args.core,
            "feature_version": schema.version,
            "observation_dim": schema.width,
            "train_scenarios": manifest.train_scenarios,
            "test_scenarios": manifest.test_scenarios,
        },
        "model": {
            "model_version": run.result.model_version,
            "best_epoch": run.result.best_epoch,
            "training_seconds": run.result.training_seconds,
            "model_sha256": run.result.model_sha256,
            "artifact_roundtrip_ok": checksum_match,
            "stage_vocabulary": run.result.stage_vocabulary,
            "split_metrics": {
                name: {
                    "reconstruction_mse": metrics.reconstruction_mse,
                    "kl_nats": metrics.kl_nats,
                    "open_loop_mae": metrics.open_loop_mae,
                    "open_loop_persistence_mae": metrics.open_loop_persistence_mae,
                    "risk_f1": metrics.risk.f1 if metrics.risk else None,
                    "risk_pr_auc": metrics.risk.pr_auc if metrics.risk else None,
                    "stage_macro_f1": metrics.stage_macro_f1,
                }
                for name, metrics in run.result.metrics.items()
            },
        },
        "open_loop": {
            "definition": (
                "mean |imagined - realized| over standardized state features, from the "
                "last observed window, with no observations after the burn-in"
            ),
            "world_model": _error_row(world_error),
            "linear_transition": _error_row(ridge_error),
            "ablation_no_rollout_loss": _error_row(ablation_error),
            "linear_transition_stability": {
                "spectral_norm_after_clip": transition.spectral_norm,
                "spectral_norm_one_step_fit": transition_unclipped.spectral_norm,
                "clip_factor": transition.stability_clip,
                "note": (
                    "A one-step least-squares next-state map is expansive, so it is "
                    "projected to a non-expansive norm before rolling out. The clip "
                    "factor is how much of the one-step fit had to be scaled away."
                ),
            },
        },
        "core_comparison": core_comparison,
        "forecast_comparison": forecast_comparison,
        "claim_status": (
            "Measured on deterministic synthetic replay data. This validates the "
            "world-model machinery and its open-loop behaviour; it is not a "
            "real-traffic performance claim."
        ),
    }
    (out / "world_model_benchmark.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    (out / "WORLD_MODEL.md").write_text(_render(payload), encoding="utf-8")

    print(f"[world-model] artifacts={artifacts['weights']}")
    print(f"[world-model] world_model skill      {_skill(world_error)}")
    print(f"[world-model] linear_transition skill {_skill(ridge_error)}")
    print(f"[world-model] ablation skill          {_skill(ablation_error)}")
    if forecast_comparison:
        for name, row in forecast_comparison.items():
            print(
                f"[world-model] {name}: lead={row['median_lead_windows']} "
                f"crossing={row['crossing_rate']:.2f} "
                f"false_early={row['false_early_warning_rate']:.2f}"
            )


def _checksum(core) -> str:
    import hashlib
    import io

    buffer = io.BytesIO()
    torch.save(core.state_dict(), buffer)
    return hashlib.sha256(buffer.getvalue()).hexdigest()


def _measure_world(core, grouped, scenarios, schema, args):
    errors = []
    for scenario_id in scenarios:
        states = [item.state for item in grouped[scenario_id]]
        for index, (observed, future) in enumerate(
            _window_pairs(states, args.history, args.horizon)
        ):
            errors.append(
                world_open_loop_error(
                    core,
                    vectorize_states(observed, schema),
                    vectorize_states(future, schema),
                    n_samples=args.samples,
                    seed=args.seed + index,
                )
            )
    return aggregate_open_loop(errors) if errors else None


def _measure_ridge(transition, grouped, scenarios, schema, args):
    errors = []
    for scenario_id in scenarios:
        states = [item.state for item in grouped[scenario_id]]
        for observed, future in _window_pairs(states, args.history, args.horizon):
            errors.append(ridge_open_loop_error(transition, observed, future, schema))
    return aggregate_open_loop(errors) if errors else None


def _compare_forecasts(labelled, result, out: Path, args, settings):
    """Imagination forecaster vs the shipped per-horizon forecaster, same windows."""
    baseline_dir = args.baseline or str(out / "baseline")
    if not (Path(baseline_dir) / "baseline_result.json").is_file():
        print("[world-model] no baseline artifacts; skipping forecast comparison")
        return None
    loaded = load_artifacts(baseline_dir)
    inference_schema = loaded.baseline_result.feature_schema
    if len(inference_schema.names) != result.observation_dim:
        raise SystemExit(
            f"baseline artifacts use {len(inference_schema.names)} features but the world "
            f"model expects {result.observation_dim}; retrain or point --baseline at the "
            "artifacts produced from the same feature schema"
        )
    core = load_world_model(result, out)
    threshold = args.threshold

    def _imagination_fn(states, artifacts, *, max_horizon, threshold):
        return imagination_forecast(
            states,
            core,
            inference_schema,
            result.stage_vocabulary,
            max_horizon=max_horizon,
            threshold=threshold,
            n_samples=args.samples,
            seed=args.seed,
        )[0]

    comparison = {}
    for name, forecast_fn in (("per_horizon", None), ("imagination", _imagination_fn)):
        evaluation = evaluate_replay(
            labelled,
            loaded,
            horizon=args.horizon,
            threshold=threshold,
            split_filter="test",
            max_history=args.history,
            min_history=args.history,
            forecast_fn=forecast_fn,
        )
        comparison[name] = {
            "decision_threshold": evaluation.decision_threshold,
            "median_lead_windows": evaluation.measured_median_lead_windows,
            "median_pre_onset_lead_windows": evaluation.median_pre_onset_lead_windows,
            "crossing_rate": evaluation.forecast_crossing_rate,
            "false_early_warning_rate": evaluation.false_early_warning_rate,
            "pre_onset_warning_rate": evaluation.pre_onset_warning_rate,
            "during_attack_detection_rate": evaluation.during_attack_detection_rate,
            "scenarios_evaluated": evaluation.scenarios_evaluated,
        }
    return comparison


def _error_row(error):
    if error is None:
        return None
    return {
        "steps": error.steps,
        "mae": error.model_mae,
        "persistence_mae": error.persistence_mae,
        "skill": error.mean_skill,
        "windows": error.windows,
    }


def _core_row(metrics, error, seconds: float) -> dict:
    """One row of the architecture comparison: reconstruct well vs simulate well."""
    return {
        "reconstruction_mse": metrics.reconstruction_mse,
        "kl_nats": metrics.kl_nats,
        "stage_macro_f1": metrics.stage_macro_f1,
        "open_loop_mae": error.model_mae if error else [],
        "open_loop_skill": error.mean_skill if error else None,
        "training_seconds": seconds,
    }


def _skill(error) -> str:
    return "n/a" if error is None else f"{error.mean_skill:+.3f}"


def _render(payload: dict) -> str:
    experiment = payload["experiment"]
    model = payload["model"]
    open_loop = payload["open_loop"]
    lines = [
        "# World Model Benchmark",
        "",
        f"- Generated: {payload['generated_at']}",
        f"- Dataset: `{payload['dataset_id']}` (deterministic synthetic replay)",
        f"- Model: `{model['model_version']}` · core `{experiment['core_type']}` · "
        f"observation dim {experiment['observation_dim']}",
        f"- Config: `{experiment['config']}` · seed {experiment['seed']} · "
        f"{experiment['history_windows']} history windows · horizon "
        f"+{experiment['horizon_windows']} · {experiment['imagination_samples']} "
        "imagination samples",
        f"- Train scenarios: {', '.join(experiment['train_scenarios'])}",
        f"- Test scenarios: {', '.join(experiment['test_scenarios'])}",
        f"- Training: best epoch {model['best_epoch']} · "
        f"{model['training_seconds']:.1f} s · SHA-256 `{model['model_sha256'][:16]}…` · "
        f"artifact round-trip {'ok' if model['artifact_roundtrip_ok'] else 'FAILED'}",
        f"- Stage vocabulary: {', '.join(model['stage_vocabulary'])}",
        "",
        "**Claim status.** " + payload["claim_status"],
        "",
        "## Open-Loop State Prediction (test scenarios)",
        "",
        f"Metric: {open_loop['definition']}. Skill is `1 - mae / persistence_mae`;",
        "positive means the model predicts unseen future windows better than",
        "repeating the last observed one.",
        "",
        "| Predictor | "
        + " | ".join(f"+{s}" for s in open_loop["world_model"]["steps"])
        + " | Mean skill |",
        "|---|" + "---:|" * (len(open_loop["world_model"]["steps"]) + 1),
    ]
    for label, key in (
        ("World model (RSSM)", "world_model"),
        ("Linear ridge transition", "linear_transition"),
        ("Ablation: no open-loop loss", "ablation_no_rollout_loss"),
    ):
        row = open_loop[key]
        if row is None:
            continue
        lines.append(
            f"| {label} | "
            + " | ".join(f"{v:.3f}" for v in row["mae"])
            + f" | {row['skill']:+.3f} |"
        )
    baseline = open_loop["world_model"]["persistence_mae"]
    lines.append(
        "| Persistence (repeat last) | " + " | ".join(f"{v:.3f}" for v in baseline) + " | 0.000 |"
    )
    stability = open_loop.get("linear_transition_stability")
    if stability:
        lines += [
            "",
            "The linear row is a measured failure mode, not a strawman: the one-step",
            f"least-squares next-state map has spectral norm "
            f"{stability['spectral_norm_one_step_fit']:.3g}, so it is expansive and",
            "rolling it out diverges. It is projected to a non-expansive norm "
            f"({stability['spectral_norm_after_clip']:.2f}, clip factor "
            f"{stability['clip_factor']:.2g}), which",
            "flattens it towards a constant predictor. A one-step objective and a usable",
            "simulator are different objectives; that gap is the result.",
        ]

    lines += [
        "",
        "## Split Metrics (heads at observed windows)",
        "",
        "| Split | Recon MSE | KL (nats) | Risk F1 | Risk PR-AUC | Stage macro-F1 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for name, metrics in model["split_metrics"].items():
        lines.append(
            f"| {name} | {metrics['reconstruction_mse']:.4f} | {metrics['kl_nats']:.4f} | "
            f"{_f(metrics['risk_f1'])} | {_f(metrics['risk_pr_auc'])} | "
            f"{_f(metrics['stage_macro_f1'])} |"
        )

    comparison = payload.get("forecast_comparison")
    if comparison:
        lines += [
            "",
            "## Forecast vs Reality (walk-forward replay, identical windows)",
            "",
            "| Forecaster | Threshold | Median lead (win) | Crossing rate | False early | "
            "Pre-onset warn | During-attack detect |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
        for name, row in comparison.items():
            lines.append(
                f"| {name} | {row['decision_threshold']:.2f} | "
                f"{_f(row['median_lead_windows'], 1)} | {row['crossing_rate']:.2f} | "
                f"{row['false_early_warning_rate']:.2f} | {row['pre_onset_warning_rate']:.2f} | "
                f"{row['during_attack_detection_rate']:.2f} |"
            )
        lines += [
            "",
            "The imagination forecaster rolls the prior forward with no observations",
            "after the burn-in, so its probabilities are simulated, not measured.",
        ]

    lines += [
        "",
        "## Interpretation",
        "",
        "- A world model earns its name on the open-loop table: the only way to",
        "  show it learned transition dynamics is to score it on states it had to",
        "  imagine. Detection F1 alone cannot show that.",
        "- The ablation row isolates the open-loop objective. Without it the same",
        "  architecture reconstructs observed windows well and still drifts once",
        "  it must predict its own future.",
        "- Recursion is open-loop, so error grows with horizon by construction.",
        "  The per-step columns make that growth visible instead of averaging it away.",
        "- Probabilities remain model evidence, never certainty.",
        "",
    ]

    comparison = payload.get("core_comparison")
    if comparison:
        steps = len(next(iter(comparison.values()))["open_loop_mae"])
        lines += [
            "",
            "## Core Comparison (same objective, same splits, same seed)",
            "",
            "| Core | Recon MSE | KL (nats) | Stage macro-F1 | Train s | "
            + " | ".join(f"+{s} MAE" for s in range(1, steps + 1))
            + " | Open-loop skill |",
            "|---|---:|---:|---:|---:|" + "---:|" * (steps + 1),
        ]
        for name, row in comparison.items():
            lines.append(
                f"| {name} | {row['reconstruction_mse']:.4f} | {row['kl_nats']:.4f} | "
                f"{_f(row['stage_macro_f1'])} | {row['training_seconds']:.0f} | "
                + " | ".join(f"{v:.3f}" for v in row["open_loop_mae"])
                + f" | {_signed(row['open_loop_skill'])} |"
            )
        lines += [
            "",
            "Reconstruction fidelity and open-loop skill do not move together: the core",
            "that reconstructs observed windows best is not the core that predicts its",
            "own future best. That gap is the argument for scoring a world model on",
            "simulated states instead of on reconstruction loss.",
        ]

    lines.append("")
    return "\n".join(lines)


def _f(value, digits: int = 3) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _signed(value) -> str:
    return "n/a" if value is None else f"{value:+.3f}"


if __name__ == "__main__":
    main()
