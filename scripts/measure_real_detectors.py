"""Does a per-deployment baseline fix lateral movement on real traffic?

    uv run python scripts/measure_real_detectors.py \
        --data-dir data/raw/cic-ids2017/TrafficLabelling \
        --output reports/generated/real-detectors

`research/ATTACK_DETECTION_REAL_DATA.md` measured the detector suite on all
983 real CIC-IDS2017 windows and found lateral movement alerting on 952 of them,
including 96.7% of benign windows. The absolute byte band is tuned on synthetic
volume, and real benign volume is roughly 149x that figure, so the band sits
below ordinary traffic and fires almost everywhere. No recalibration of an
absolute threshold fixes that, and a rolling-history z-score was measured and
rejected because lateral movement is sustained, so the baseline rises with it.

This script measures the one design change that should: a `DeploymentBaseline`
learned from a **disjoint, known-benign reference period** and then frozen, so a
sustained attack cannot contaminate its own reference.

It reports the alert rate twice on the same windows - once with the absolute band
and once with the fitted baseline - so the two are directly comparable and the
claim in the research doc can be checked rather than believed.

The reference period is the first `reference_fraction` of benign windows in
chronological order; everything after that is evaluation, so no evaluation
window contributes to the baseline it is scored against.

Dataset used under its published research terms with the required citation
(Sharafaldin, Lashkari & Ghorbani, ICISSP 2018). No data is committed.
"""

from __future__ import annotations

import argparse
import json
from datetime import UTC, datetime
from pathlib import Path

from run_loeo_benchmark import load_all_days

from sentinel.detectors import (
    LATERAL_LOOKBACK,
    MIN_HISTORY,
    fit_deployment_baseline,
    run_all_detectors,
)
from sentinel.targets import LabelledState

REAL_DETECTOR_MEASUREMENT_VERSION = "real-detector-measurement-v1"


def _known_edge_rates(labelled: list[LabelledState]) -> list[float | None]:
    """Known-edge byte rate per window, using only strictly prior windows.

    Mirrors `detect_lateral`'s own lookback semantics so the reference period is
    measured the same way the detector measures live traffic.
    """
    from sentinel.detectors import LATERAL_LOOKBACK, _window_seconds

    rates: list[float | None] = []
    for i, item in enumerate(labelled):
        prior = [labelled[j] for j in range(max(0, i - LATERAL_LOOKBACK), i)]
        if len(prior) < MIN_HISTORY:
            rates.append(None)
            continue
        seen: set[tuple[str, str]] = set()
        for p in prior:
            seen.update((e["source"], e["destination"]) for e in p.state.edge_summary)
        known = sum(
            e["bytes"] for e in item.state.edge_summary if (e["source"], e["destination"]) in seen
        )
        rates.append(known / _window_seconds(item.state))
    return rates


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data/raw/cic-ids2017/TrafficLabelling")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--stride-seconds", type=int, default=150)
    parser.add_argument("--reference-fraction", type=float, default=0.3)
    parser.add_argument("--output", default="reports/generated/real-detectors")
    args = parser.parse_args()

    print("loading real CIC-IDS2017 days:")
    labelled = load_all_days(
        Path(args.data_dir),
        window_seconds=args.window_seconds,
        stride_seconds=args.stride_seconds,
    )
    if not labelled:
        raise SystemExit("no windows built; check --data-dir")

    rates = _known_edge_rates(labelled)
    usable = [(i, r) for i, r in enumerate(rates) if r is not None]
    benign_idx = [i for i, r in usable if labelled[i].label.attack_stage == "Benign"]
    if not benign_idx:
        raise SystemExit("no benign windows with sufficient history")

    # Reference period = earliest benign windows, disjoint from evaluation.
    cut = max(1, int(len(benign_idx) * args.reference_fraction))
    reference_idx = benign_idx[:cut]
    reference_rates = [rates[i] for i in reference_idx]
    baseline = fit_deployment_baseline([r for r in reference_rates if r is not None])

    print(
        f"\nreference: {len(reference_idx)} benign windows, "
        f"known-edge median {baseline.median_bytes_per_sec:.0f} B/s "
        f"(MAD {baseline.mad_bytes_per_sec:.0f})"
    )

    def score_window(i: int, *, use_baseline: bool) -> tuple[bool, bool]:
        """Return (is_alert, is_lateral_alert) for window i."""
        history = tuple(labelled[j].state for j in range(max(0, i - LATERAL_LOOKBACK), i))
        findings = run_all_detectors(
            labelled[i].state, history, deployment_baseline=baseline if use_baseline else None
        )
        lateral = next(f for f in findings if f.attack_type == "lateral_movement")
        return any(f.is_alert for f in findings), bool(lateral.is_alert)

    eval_idx = benign_idx[cut:] + [
        i for i, _ in usable if labelled[i].label.attack_stage != "Benign"
    ]
    rows: list[dict] = []
    for i in eval_idx:
        band_alert, band_lat = score_window(i, use_baseline=False)
        base_alert, base_lat = score_window(i, use_baseline=True)
        rows.append(
            {
                "stage": labelled[i].label.attack_stage,
                "known_edge_bps": rates[i],
                "band_lateral_alert": band_lat,
                "baseline_lateral_alert": base_lat,
                "band_any_alert": band_alert,
                "baseline_any_alert": base_alert,
            }
        )

    def rate(subset, key):
        return sum(1 for r in subset if r[key]) / len(subset) if subset else float("nan")

    benign = [r for r in rows if r["stage"] == "Benign"]
    attacks = [r for r in rows if r["stage"] != "Benign"]
    report = {
        "version": REAL_DETECTOR_MEASUREMENT_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset_id": "cic-ids2017",
        "total_windows": len(labelled),
        "evaluation_windows": len(rows),
        "reference_windows": len(reference_idx),
        "baseline": {
            "median_bytes_per_sec": baseline.median_bytes_per_sec,
            "mad_bytes_per_sec": baseline.mad_bytes_per_sec,
            "samples": baseline.samples,
            "alert_sigma": baseline.alert_sigma,
        },
        "benign": {
            "n": len(benign),
            "lateral_alert_rate_absolute_band": rate(benign, "band_lateral_alert"),
            "lateral_alert_rate_deployment_baseline": rate(benign, "baseline_lateral_alert"),
        },
        "attack": {
            "n": len(attacks),
            "lateral_alert_rate_absolute_band": rate(attacks, "band_lateral_alert"),
            "lateral_alert_rate_deployment_baseline": rate(attacks, "baseline_lateral_alert"),
        },
        "any_rule": {
            "benign_alert_rate_absolute_band": rate(benign, "band_any_alert"),
            "benign_alert_rate_deployment_baseline": rate(benign, "baseline_any_alert"),
        },
    }

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "real-detectors.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    print(f"\n{'rule':<28}{'absolute band':>15}{'deployment baseline':>21}")
    print("-" * 64)
    print(
        f"{'lateral, benign':<28}"
        f"{report['benign']['lateral_alert_rate_absolute_band']:>14.1%}"
        f"{report['benign']['lateral_alert_rate_deployment_baseline']:>20.1%}"
    )
    print(
        f"{'lateral, attack':<28}"
        f"{report['attack']['lateral_alert_rate_absolute_band']:>14.1%}"
        f"{report['attack']['lateral_alert_rate_deployment_baseline']:>20.1%}"
    )
    print(
        f"{'any rule, benign':<28}"
        f"{report['any_rule']['benign_alert_rate_absolute_band']:>14.1%}"
        f"{report['any_rule']['benign_alert_rate_deployment_baseline']:>20.1%}"
    )
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
