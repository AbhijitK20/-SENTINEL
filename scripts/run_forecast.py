"""Load saved baseline (+ optional temporal) artifacts and emit a forecast JSON.

    uv run python scripts/run_forecast.py \
        --baseline reports/generated/baseline \
        --temporal reports/generated/temporal \
        --output reports/generated/forecast/forecast.json

If ``--temporal`` is omitted, the timeline uses the baseline probability
with a conservative decay and a warning is recorded in the forecast.
"""

from __future__ import annotations

import argparse

from trajectory.ledger import AlertLedger
from trajectory.predict import forecast, load_artifacts, save_forecast
from trajectory.synthetic import generate_labelled_states
from trajectory.targets import make_split_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", required=True, help="Baseline artifacts directory")
    parser.add_argument(
        "--temporal",
        default=None,
        help="Optional temporal artifacts directory",
    )
    parser.add_argument(
        "--scenarios", type=int, default=4, help="Number of synthetic scenarios to use as input"
    )
    parser.add_argument("--seed", type=int, default=42, help="Synthetic seed")
    parser.add_argument("--max-horizon", type=int, default=5)
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Decision threshold (default: shipped 0.5; pass a calibrated value)",
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="Override scenario id (defaults to first test scenario)",
    )
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--ledger",
        default=None,
        help="Optional JSONL trust ledger path for registering the forecast",
    )
    args = parser.parse_args()

    loaded = load_artifacts(args.baseline, temporal_dir=args.temporal)

    scenario_ids = [f"scenario-{index:02d}" for index in range(1, args.scenarios + 1)]
    labelled = generate_labelled_states(
        scenario_ids,
        seed=args.seed,
        window_seconds=60,
        stride_seconds=60,
    )
    manifest = make_split_manifest(scenario_ids, seed=args.seed)

    target_scenario = args.scenario or (manifest.test_scenarios or scenario_ids)[0]
    states = [item.state for item in labelled if item.scenario_id == target_scenario]
    if not states:
        raise SystemExit(f"No states found for scenario {target_scenario!r}")

    # threshold=None lets forecast() resolve: explicit flag → calibrated
    # threshold stored with the artifacts → shipped 0.5 default.
    result = forecast(states, loaded, max_horizon=args.max_horizon, threshold=args.threshold)
    path = save_forecast(result, args.output)

    if args.ledger:
        record = AlertLedger(args.ledger).append_forecast(result)
        print(f"alert_id={record.alert_id} ledger_path={args.ledger}")

    peak = max(result.probability_timeline, key=lambda point: point.infiltration_probability)
    print(
        f"scenario={target_scenario} peak_window={peak.window} "
        f"peak_probability={peak.infiltration_probability:.3f}"
    )
    print(
        f"predicted_stage={result.predicted_stage.name} "
        f"confidence={result.predicted_stage.confidence}"
    )
    if result.stage_mapping is not None:
        mapping = result.stage_mapping
        print(
            f"stage_mapping={mapping.stage} version={mapping.mapping_version} "
            f"mitre={mapping.mitre_reference or 'n/a'} evidence_rules={len(mapping.evidence)}"
        )
    if result.lead_time is not None:
        lead = result.lead_time
        lead_text = str(lead.lead_windows) if lead.lead_windows is not None else "not-crossed"
        print(
            f"lead_time_windows={lead_text} horizon={lead.horizon_windows} "
            f"threshold={lead.threshold:.2f}"
        )
    print(f"forecast_path={path}")
    for warning in result.warnings:
        print(f"warning: {warning}")


if __name__ == "__main__":
    main()
