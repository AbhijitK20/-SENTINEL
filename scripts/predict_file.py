"""Forecast a telemetry file offline: PCAP or flow CSV in, timeline out.

    uv run python scripts/predict_file.py \
        --input captures/incident.pcap \
        --baseline reports/generated/benchmark/pipeline/baseline \
        --temporal reports/generated/benchmark/pipeline/temporal \
        --world-model reports/generated/benchmark/world_model \
        --forecaster imagination \
        --output reports/generated/file-forecast/forecast.json

Prints what the problem statement asks a demo interface to show: the
infiltration probability timeline, the flagged windows, the predicted attack
stage with its MITRE mapping, and the driving features. Runs fully offline from
saved artifacts; no network client is imported.
"""

from __future__ import annotations

import argparse
from pathlib import Path

from sentinel.file_forecast import forecast_from_file
from sentinel.ledger import AlertLedger
from sentinel.predict import load_artifacts, save_forecast


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="PCAP or flow CSV file")
    parser.add_argument("--baseline", required=True, help="Baseline artifacts directory")
    parser.add_argument("--temporal", default=None, help="Temporal artifacts directory")
    parser.add_argument("--world-model", default=None, help="World model artifacts directory")
    parser.add_argument(
        "--forecaster",
        default="per_horizon",
        choices=("per_horizon", "imagination"),
        help="imagination requires --world-model",
    )
    parser.add_argument("--max-horizon", type=int, default=5)
    parser.add_argument("--threshold", type=float, default=None)
    parser.add_argument("--window-seconds", type=int, default=60)
    parser.add_argument("--stride-seconds", type=int, default=30)
    parser.add_argument("--history-windows", type=int, default=None)
    parser.add_argument("--imagination-samples", type=int, default=64)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", required=True, help="Forecast JSON path")
    parser.add_argument("--ledger", default=None, help="Optional JSONL trust ledger path")
    args = parser.parse_args()

    loaded = load_artifacts(args.baseline, temporal_dir=args.temporal)
    result = forecast_from_file(
        args.input,
        loaded,
        forecaster=args.forecaster,
        world_model_dir=args.world_model,
        max_horizon=args.max_horizon,
        threshold=args.threshold,
        window_seconds=args.window_seconds,
        stride_seconds=args.stride_seconds,
        history_windows=args.history_windows,
        imagination_samples=args.imagination_samples,
        seed=args.seed,
    )
    path = save_forecast(result.forecast, args.output)
    result_path = Path(args.output).with_name(Path(args.output).stem + "_run.json")
    result_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")

    if args.ledger:
        record = AlertLedger(args.ledger).append_forecast(result.forecast)
        print(f"alert_id={record.alert_id} ledger_path={args.ledger}")

    telemetry = result.telemetry
    print(f"input={telemetry.path} source={telemetry.source_format} events={telemetry.events}")
    print(
        f"windows={telemetry.states} "
        f"[{telemetry.first_window_start} .. {telemetry.last_window_end}]"
    )
    print(
        f"coverage flow={telemetry.flow_coverage} packet={telemetry.packet_coverage} "
        f"features_present={telemetry.features_present}"
    )
    for warning in telemetry.ingestion_warnings:
        print(f"ingestion_warning: {warning}")

    print(f"forecaster={result.forecaster} model_version={result.forecast.model_version}")
    print(f"threshold={result.threshold:.2f}")
    print("timeline:")
    for point in result.forecast.probability_timeline:
        flag = "  <-- flagged" if point.window in result.flagged_windows else ""
        print(
            f"  +{point.window}  P(infiltration)={point.infiltration_probability:.3f}  "
            f"confidence={point.confidence:.3f}{flag}"
        )
    if result.flagged_windows:
        print(f"flagged_windows={result.flagged_windows}")
    else:
        print("flagged_windows=none (no horizon crosses the threshold)")

    stage = result.forecast.predicted_stage
    print(
        f"predicted_stage={stage.name} probability={stage.probability:.3f} "
        f"confidence={stage.confidence}"
    )
    mapping = result.forecast.stage_mapping
    if mapping is not None:
        print(
            f"stage_mapping={mapping.stage} mitre={mapping.mitre_reference or 'n/a'} "
            f"rationale={mapping.rationale}"
        )
        for evidence in mapping.evidence:
            print(
                f"  evidence: {evidence.name} — {evidence.description} ({evidence.confidence:.2f})"
            )
    if result.forecast.lead_time is not None:
        lead = result.forecast.lead_time
        crossing = lead.lead_windows if lead.lead_windows is not None else "not-crossed"
        print(f"lead_time_windows={crossing} horizon={lead.horizon_windows}")
    print("driving_features:")
    for driver in result.forecast.driving_features:
        print(f"  {driver.direction:>10}  {driver.name}  contribution={driver.contribution:+.4f}")
    if result.forecast.affected_entities:
        print(f"affected_entities={result.forecast.affected_entities}")
    print(f"forecast_path={path}")
    print(f"run_path={result_path}")
    for warning in result.forecast.warnings:
        print(f"warning: {warning}")


if __name__ == "__main__":
    main()
