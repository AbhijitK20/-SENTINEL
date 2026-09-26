"""The golden path, end to end, from committed artifacts, with no clicking.

Every other demo in this repo needs something running first: docker, a live
sensor, a browser, or a person. This one does not. It loads the committed
release bundle, replays a scenario that escalates the way ``docs/DEMO_SCENARIO.md``
describes, and prints what the system would have shown an analyst at each beat -
forecast, explanation, detectors, stage - so the whole claim can be checked in
one command.

    uv run python scripts/demo_script.py
    uv run python scripts/demo_script.py --output reports/generated/demo_script

It is also the smoke test CI runs, so a change that breaks the product's central
path fails the build instead of being discovered during a demo.

Everything printed here comes from artifacts in the repository. The scenario is
synthetic and is labelled as such in the output.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from sentinel.detectors import run_all_detectors
from sentinel.predict import forecast, load_artifacts
from sentinel.synthetic import DATASET_ID, generate_labelled_states
from sentinel.world_model.imagine import imagination_forecast
from sentinel.world_model.train import WorldModelResult, load_world_model

DEMO_VERSION = "golden-path-demo-v1"
DEFAULT_BUNDLE = "models/release/v1"
DEFAULT_HORIZON = 4


def _beat(number: int, title: str) -> str:
    return f"\n{'=' * 72}\nBEAT {number}  {title}\n{'=' * 72}"


def run_demo(
    bundle: str | Path = DEFAULT_BUNDLE,
    *,
    seed: int = 42,
    horizon: int = DEFAULT_HORIZON,
) -> dict:
    """Walk one escalating scenario and record what the system reported.

    The scenario is the attack's own synthetic generator, so the demo cannot
    silently pass on data that does not contain an attack.
    """
    root = Path(bundle)
    if not root.is_dir():
        raise FileNotFoundError(
            f"release bundle not found at {root}. Run 'make export' or point "
            "--bundle at an artifacts directory."
        )
    artifacts = load_artifacts(root)
    scenario_id = "demo"
    labelled = generate_labelled_states(
        [scenario_id], seed=seed, window_seconds=60, stride_seconds=60
    )
    states = [item.state for item in labelled if item.scenario_id == scenario_id]
    if len(states) <= horizon:
        raise ValueError(
            f"scenario produced {len(states)} windows, which is too few to forecast {horizon} ahead"
        )

    report: dict = {
        "demo_version": DEMO_VERSION,
        "dataset_id": DATASET_ID,
        "generated_at": datetime.now(UTC).isoformat(),
        "bundle": str(root),
        "model_version": artifacts.baseline_result.model_version,
        "threshold": artifacts.calibrated_threshold,
        "beats": [],
    }

    print(_beat(1, "artifacts load"))
    print(f"bundle                {root}")
    print(f"baseline              {artifacts.baseline_result.model_version}")
    print(f"features              {artifacts.baseline_result.feature_schema.width}")
    if artifacts.temporal_result is not None:
        print(f"temporal              {artifacts.temporal_result.model_version}")
    if artifacts.calibrated_threshold is not None:
        print(f"calibrated threshold  {artifacts.calibrated_threshold:.2f}")
    else:
        print("calibrated threshold  none shipped; falling back to 0.5")

    print(_beat(2, "benign traffic, no alert expected"))
    history = states[:3]
    quiet = forecast(history, artifacts, max_horizon=horizon)
    quiet_peak = max(p.infiltration_probability for p in quiet.probability_timeline)
    print(f"windows               {len(history)}")
    print(f"peak probability      {quiet_peak:.2f}")
    print(f"stage                 {quiet.predicted_stage.name}")
    for finding in run_all_detectors(history[-1], tuple(history[:-1])):
        if finding.is_alert:
            print(
                f"detector              {finding.attack_type} p={finding.probability:.2f} "
                f"{finding.severity}"
            )
    report["beats"].append(
        {
            "beat": 2,
            "name": "benign",
            "windows": len(history),
            "peak_probability": quiet_peak,
            "stage": quiet.predicted_stage.name,
        }
    )

    print(_beat(3, "attack develops, probability crosses and the model explains itself"))
    observed = states[:-horizon]
    result = forecast(observed, artifacts, max_horizon=horizon)
    peak = max(p.infiltration_probability for p in result.probability_timeline)
    print(f"windows               {len(observed)}")
    print("timeline")
    for point in result.probability_timeline:
        marker = (
            "*"
            if point.infiltration_probability >= (artifacts.calibrated_threshold or 0.5)
            else " "
        )
        print(f"  +{point.window}  {point.infiltration_probability:5.2f} {marker}")
    print(f"peak                  {peak:.2f}")
    print(
        f"stage                 {result.predicted_stage.name} ({result.predicted_stage.confidence})"
    )
    if result.stage_mapping is not None:
        mapping = result.stage_mapping
        print(f"mitre                 {mapping.mitre_reference or 'unmapped'}")
        print(f"rationale             {mapping.rationale}")
    if result.explanation is not None:
        explanation = result.explanation
        print(f"explanation method    {explanation.method}")
        print(f"                      {explanation.method_detail}")
        print("top drivers")
        for feature in explanation.current_window:
            print(f"  {feature.name:<24} {feature.contribution:+7.3f} {feature.direction}")
        print(f"caveat                {explanation.caveat}")
    else:
        print("explanation           none produced")
    report["beats"].append(
        {
            "beat": 3,
            "name": "attack",
            "windows": len(observed),
            "peak_probability": peak,
            "stage": result.predicted_stage.name,
            "explanation_method": result.explanation.method if result.explanation else None,
            "top_drivers": [
                f.name for f in (result.explanation.current_window if result.explanation else [])
            ],
        }
    )

    print(_beat(4, "detectors fire on the observed windows"))
    for index, state in enumerate(observed, start=1):
        history_slice = observed[: index - 1]
        for finding in run_all_detectors(state, tuple(history_slice)):
            if not finding.is_alert:
                continue
            print(
                f"window {index:>2}  {finding.attack_type:<18} p={finding.probability:.2f} "
                f"{finding.severity:<8} {finding.mitre_technique or 'unmapped'}"
            )
            report["beats"].append(
                {
                    "beat": 4,
                    "name": "detector",
                    "window": index,
                    "attack_type": finding.attack_type,
                    "probability": finding.probability,
                    "severity": finding.severity,
                    "mitre_technique": finding.mitre_technique,
                }
            )
    if not any(b["beat"] == 4 for b in report["beats"]):
        print("no detector fired on this scenario; the attack shape did not match a rule")

    print(_beat(5, "imagination: the world model rolled forward, with its spread"))
    world_json = root / "world_model.json"
    if world_json.is_file():
        result_contract = WorldModelResult.model_validate_json(
            world_json.read_text(encoding="utf-8")
        )
        core = load_world_model(result_contract, root)
        burn_in = max(1, min(len(observed), result_contract.sequence_length))
        simulated, diagnostics = imagination_forecast(
            observed[-burn_in:],
            core,
            artifacts.baseline_result.feature_schema,
            result_contract.stage_vocabulary,
            max_horizon=horizon,
            threshold=artifacts.calibrated_threshold or 0.5,
            n_samples=32,
            seed=seed,
        )
        print(f"model                 {result_contract.model_version}")
        print(f"burn-in               {burn_in} observed windows")
        for point in simulated.probability_timeline:
            print(
                f"  +{point.window}  {point.infiltration_probability:5.2f} "
                f"sample_agreement={point.confidence:.2f}"
            )
        print(f"stage                 {simulated.predicted_stage.name}")
        print(f"risk spread (std)     {diagnostics['risk_spread']:.3f}")
        print(f"latent spread         {diagnostics['latent_spread']:.3f}")
        print(f"crossing rate         {diagnostics['crossing_rate']:.2f}")
        for warning in simulated.warnings:
            print(f"warning               {warning}")
        report["beats"].append(
            {
                "beat": 5,
                "name": "imagination",
                "model_version": result_contract.model_version,
                "risk_spread": diagnostics["risk_spread"],
                "crossing_rate": diagnostics["crossing_rate"],
                "timeline": [p.infiltration_probability for p in simulated.probability_timeline],
            }
        )
    else:
        print("no world_model.json in the bundle; run 'make bench-world && make export'")
        report["beats"].append({"beat": 5, "name": "imagination", "skipped": True})

    print(_beat(6, "what this run does and does not show"))
    print("shown:   the committed artifacts score a scenario, explain themselves,")
    print("         fire detectors, and simulate forward with a measured spread.")
    print("not shown: any real network. The scenario is synthetic, and every number")
    print("         above is reproducible from this command alone.")
    report["beats"].append({"beat": 6, "name": "scope"})
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", default=DEFAULT_BUNDLE)
    parser.add_argument("--horizon", type=int, default=DEFAULT_HORIZON)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()

    report = run_demo(args.bundle, horizon=args.horizon, seed=args.seed)
    if args.output:
        out = Path(args.output)
        out.mkdir(parents=True, exist_ok=True)
        (out / "demo.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\ndemo_json={out / 'demo.json'}")


if __name__ == "__main__":
    main()
