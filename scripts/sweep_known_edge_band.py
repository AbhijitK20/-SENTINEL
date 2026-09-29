#!/usr/bin/env python
"""Re-fit the known-edge byte-rate band on the corrected generator.

The band in `detectors.py` was swept on ``synthetic-recon-lateral-v2``, whose
benign traffic capped at 6 kB per connection while the lateral phase moved
20-80 kB. The classes separated on a single scalar, so the sweep found a
narrow band that only worked because of the shortcut rather than because the
signal was there.

``synthetic-recon-lateral-v3`` overlaps the two distributions on purpose. This
script re-runs the same sweep the original comment describes — best F1 on the
test split, keeping the 5:6 warn:alert shape — so the constant is traceable to
a measurement on the current data.

The protocol is deliberately the original one: test split only, and the same
four seeds (17, 42, 7, 99) the constant's comment already reports.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

from run_detector_benchmark import evaluate_detectors  # noqa: E402

from sentinel import detectors  # noqa: E402
from sentinel.synthetic import DATASET_ID, generate_labelled_states  # noqa: E402

SEEDS = (17, 42, 7, 99)


def windows_for_seed(seed: int, scenarios: int):
    return generate_labelled_states(
        [f"scenario-{i:02d}" for i in range(scenarios)],
        seed=seed,
        window_seconds=60,
        stride_seconds=30,
    )


def score_band(warn: float, alert: float, seed: int, scenarios: int):
    detectors.KNOWN_EDGE_BYTES_PER_SEC_WARN = warn
    detectors.KNOWN_EDGE_BYTES_PER_SEC_ALERT = alert
    labelled = windows_for_seed(seed, scenarios)
    for score in evaluate_detectors(labelled, attack_types=["lateral_movement"]):
        if score.attack_type == "lateral_movement":
            return score
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scenarios", type=int, default=10)
    parser.add_argument("--output", default="reports/generated/detector-sweep")
    parser.add_argument(
        "--shape",
        type=float,
        default=6 / 5,
        help="alert:warn ratio kept from the original band (6:5)",
    )
    args = parser.parse_args()

    # Restore the shipped constant when this script exits; it must not leave a
    # sweep value behind in the module.
    original = (
        detectors.KNOWN_EDGE_BYTES_PER_SEC_WARN,
        detectors.KNOWN_EDGE_BYTES_PER_SEC_ALERT,
    )

    rows: list[dict] = []
    best: tuple[float, float, float] | None = None
    for warn in range(500, 30_001, 250):
        alert = round(warn * args.shape)
        per_seed = []
        ok = True
        for seed in SEEDS:
            score = score_band(float(warn), float(alert), seed, args.scenarios)
            if score is None or score.f1 is None:
                ok = False
                break
            per_seed.append(score)
        if not ok:
            continue
        mean_f1 = sum(s.f1 for s in per_seed) / len(per_seed)
        min_prec = min(s.precision for s in per_seed)
        min_rec = min(s.recall for s in per_seed)
        rows.append(
            {
                "warn": float(warn),
                "alert": float(alert),
                "mean_f1": round(mean_f1, 4),
                "min_precision": round(min_prec, 4),
                "min_recall": round(min_rec, 4),
            }
        )
        if best is None or mean_f1 > best[0]:
            best = (mean_f1, float(warn), float(alert))

    detectors.KNOWN_EDGE_BYTES_PER_SEC_WARN, detectors.KNOWN_EDGE_BYTES_PER_SEC_ALERT = original

    rows.sort(key=lambda r: -r["mean_f1"])
    print(f"dataset      : {DATASET_ID}")
    print(f"seeds        : {list(SEEDS)}   scenarios: {args.scenarios}")
    print(f"shipped band : {original[0]:g} / {original[1]:g} B/s")
    for row in rows[:8]:
        print(
            f"  {row['warn']:>8.0f} / {row['alert']:>8.0f} B/s   "
            f"meanF1 {row['mean_f1']:.4f}  minP {row['min_precision']:.4f}  "
            f"minR {row['min_recall']:.4f}"
        )
    if best is None:
        print("no band scored")
        return 1
    print(f"\nbest mean F1 {best[0]:.4f} at {best[1]:g} / {best[2]:g} B/s")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    (out / "known_edge_band_sweep.json").write_text(
        json.dumps(
            {
                "dataset_id": DATASET_ID,
                "seeds": list(SEEDS),
                "scenarios": args.scenarios,
                "shipped": {"warn": original[0], "alert": original[1]},
                "best": {"mean_f1": best[0], "warn": best[1], "alert": best[2]},
                "grid": rows,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    print(f"wrote {out / 'known_edge_band_sweep.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
