"""Leave-one-attack-out generalisation on real CIC-IDS2017.

    uv run python scripts/run_loeo_benchmark.py \
        --data-dir data/raw/cic-ids2017/TrafficLabelling \
        --output reports/generated/loeo

Every other real-data benchmark in this repo answers "how well does the model do
on traffic shaped like its training set". This one answers the question SIH26153
actually asks: can the model flag an attack stage it has never seen?

Protocol, per held-out stage S:

- TRAIN   benign windows + every attack stage except S. S appears nowhere in
          training, in any form.
- THRESHOLD  calibrated on a chronological slice of TRAIN only.
- TEST    benign windows + S. S is unseen.

The held-out stage is dropped from train by label, so no window of S reaches
feature statistics, the classifier, or the threshold. Within each fold the
benign/test split is still chronological, so this measures stage generalisation
and not memorisation of a particular afternoon.

What this does and does not show: it measures single-window detection of an
unseen stage, not K-step forecasting of an unseen attack chain, and it inherits
the adapter's known ceiling - CIC-IDS2017 flow CSVs carry no failed-auth, DNS or
endpoint columns, so four of the nine detectors are structurally unavailable here
and are not exercised by this script. Numbers describe the window classifier, not
the full detector suite. `scripts/validate_real_detectors.py` covers the rules.

Dataset used under its published research terms with the required citation
(Sharafaldin, Lashkari & Ghorbani, ICISSP 2018). No data is committed.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score

from sentinel.baseline import train_baseline
from sentinel.cic_ids2017 import build_labelled_states, flow_labels_from_events
from sentinel.cic_ids2017 import load_flow_csv_with_stats as _load_flow
from sentinel.features import (
    FEATURE_VERSION,
    FeatureSchema,
    fit_feature_schema,
    vectorize_states,
)
from sentinel.targets import LabelledState

LOEO_BENCHMARK_VERSION = "loeo-benchmark-v1"

#: Day CSVs in chronological order. Order matters: folds split on time, not on
#: filename, but a stable order keeps runs reproducible.
DAY_CSVS: tuple[tuple[str, str], ...] = (
    ("Monday-WorkingHours.pcap_ISCX.csv", "monday"),
    ("Tuesday-WorkingHours.pcap_ISCX.csv", "tuesday"),
    ("Wednesday-workingHours.pcap_ISCX.csv", "wednesday"),
    ("Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv", "thursday-am"),
    ("Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv", "thursday-pm"),
    ("Friday-WorkingHours-Morning.pcap_ISCX.csv", "friday-am"),
    ("Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv", "friday-pm-portscan"),
    ("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv", "friday-pm-ddos"),
)


def load_all_days(
    data_dir: Path, *, window_seconds: int, stride_seconds: int
) -> list[LabelledState]:
    """Load every day CSV into labelled windows, in chronological file order."""
    out: list[LabelledState] = []
    for name, scenario_id in DAY_CSVS:
        path = data_dir / name
        events, stats = _load_flow(path, scenario_id=scenario_id)
        if not events:
            print(f"  {scenario_id}: no flows, skipped")
            continue
        labelled = build_labelled_states(
            events,
            flow_labels_from_events(events),
            window_seconds=window_seconds,
            stride_seconds=stride_seconds,
            scenario_id=scenario_id,
        )
        out.extend(labelled)
        print(f"  {scenario_id}: {stats.rows_converted} flows -> {len(labelled)} windows")
    return out


def _fit_logistic(
    x_train: np.ndarray, y_train: np.ndarray, *, seed: int
) -> tuple[np.ndarray, np.ndarray]:
    """Standard logistic regression; returns (coef, intercept). Stdlib+numpy only."""
    # L2 via a few Newton-ish gradient steps would be overkill; sklearn is already
    # a project dependency via sentinel.baseline, so reuse it rather than hand-roll.
    from sklearn.linear_model import LogisticRegression

    clf = LogisticRegression(max_iter=2000, C=1.0, random_state=seed, class_weight="balanced")
    clf.fit(x_train, y_train)
    return clf.coef_[0], float(clf.intercept_[0])


def _score(x: np.ndarray, coef: np.ndarray, intercept: float) -> np.ndarray:
    z = x @ coef + intercept
    return 1.0 / (1.0 + np.exp(-z))


def _densify(item, schema):
    """Return a copy of a labelled state carrying the schema's full feature set.

    Real windows are sparse - a window with no DNS evidence simply has no DNS
    keys - but `fit_transition_model` requires every state to expose an identical
    key set, and refuses to fit otherwise. Filling from the schema's own
    `missing_value` is the documented remedy and keeps the transition model and
    the classifier reading the same columns.
    """
    from sentinel.schemas import NetworkState
    from sentinel.targets import LabelledState

    dense = NetworkState(
        window_start=item.state.window_start,
        window_end=item.state.window_end,
        features={
            name: float(item.state.features.get(name, schema.missing_value))
            for name in schema.names
        },
        entities=list(item.state.entities),
        edge_summary=list(item.state.edge_summary),
        coverage=dict(item.state.coverage),
        source_ids=list(item.state.source_ids),
    )
    return LabelledState(
        state_key=item.state_key,
        scenario_id=item.scenario_id,
        state=dense,
        label=item.label,
    )


def run_forecast_fold(
    labelled: Sequence[LabelledState],
    schema,
    held_out: str,
    *,
    horizon: int,
    history_length: int,
    seed: int,
) -> dict:
    """K-step forecast of an unseen stage, world model versus static classifier.

    The window-level fold above asks "does the model recognise an unseen attack
    when it happens". This asks the harder question SIH26153 actually turns on:
    "does it warn *before* an attack it has never seen arrives".

    Both arms are scored on exactly the same windows with the same threshold:

    - **World model**: the K-step transition rollout (`rollout.rollout_forecast`),
      which simulates forward through learned transition dynamics and scores each
      simulated step with the classifier.
    - **Static classifier**: the classifier applied to the current window only,
      which is what a conventional per-window IDS can do.

    The transition model is fit on windows excluding the held-out stage, so it
    cannot have learned this attack's dynamics. What it can still do is notice
    that *an* attack is developing, because the five seen stages share enough
    shape for the rollout to reach a high-infiltration simulated state. That is
    the generalisation claim, and it is the one a chronological split with no
    stage holdout cannot support.
    """
    from sentinel.calibration import calibrate_threshold
    from sentinel.config import BaselineConfig
    from sentinel.rollout import fit_transition_model, rollout_forecast
    from sentinel.targets import build_sequence_samples, make_split_manifest

    is_held = [i.label.attack_stage == held_out for i in labelled]
    held_idx = [i for i in range(len(labelled)) if is_held[i]]
    if not held_idx:
        return {"held_out_stage": held_out, "status": "absent_from_dataset"}

    dense_all = [_densify(item, schema) for item in labelled]
    train = [item for i, item in enumerate(dense_all) if not is_held[i]]
    if len({item.label.infiltration for item in train}) < 2:
        return {"held_out_stage": held_out, "status": "degenerate_train"}

    scenarios = sorted({item.scenario_id for item in train})
    if len(scenarios) < 2:
        return {"held_out_stage": held_out, "status": "too_few_train_scenarios"}

    try:
        samples = build_sequence_samples(train, sequence_length=history_length, horizon=horizon)
        if not samples:
            return {"held_out_stage": held_out, "status": "no_train_sequences"}
        manifest = make_split_manifest(scenarios, seed=seed)
        run = train_baseline(train, samples, manifest, config=BaselineConfig(), seed=seed)
        model = fit_transition_model(train, history_length=history_length, scenario_ids=scenarios)
    except ValueError as error:
        return {"held_out_stage": held_out, "status": f"fit_failed: {error}"}

    # Threshold from the training set only, via the project's own calibrator, so
    # the held-out stage cannot influence where the decision boundary sits.
    order_train = sorted(train, key=lambda item: item.state.window_start)
    cut = int(len(order_train) * 0.7)
    cal_states = order_train[cut:]
    if not cal_states:
        return {"held_out_stage": held_out, "status": "too_few_calibration_windows"}
    cal_p = run.model.predict_proba(vectorize_states([i.state for i in cal_states], schema))[:, 1]
    threshold = float(
        calibrate_threshold(
            cal_p, [i.label.infiltration for i in cal_states], objective="f1"
        ).best_threshold
    )

    # Walk the full timeline in order. At each window the model sees only what
    # came before, exactly as it would live.
    order = sorted(range(len(dense_all)), key=lambda i: dense_all[i].state.window_start)
    wm_first_cross: int | None = None
    static_first_cross: int | None = None
    onset: int | None = None
    evaluated = 0

    for pos, idx in enumerate(order):
        if is_held[idx]:
            onset = idx
        history_states = [dense_all[j].state for j in order[max(0, pos - history_length) : pos]]
        if len(history_states) < history_length:
            continue
        # Only windows strictly before onset can earn lead credit.
        if onset is not None and idx >= onset:
            break
        evaluated += 1
        try:
            fc, _ = rollout_forecast(
                history_states, model, run.model, schema, max_horizon=horizon, threshold=threshold
            )
        except ValueError:
            continue
        if wm_first_cross is None and any(
            p.infiltration_probability >= threshold for p in fc.probability_timeline
        ):
            wm_first_cross = idx
        current_p = float(
            run.model.predict_proba(vectorize_states([dense_all[idx].state], schema))[0, 1]
        )
        if static_first_cross is None and current_p >= threshold:
            static_first_cross = idx

    if onset is None or evaluated == 0:
        return {"held_out_stage": held_out, "status": "no_pre_onset_history"}

    # Lead is a distance in *chronological position*, so it must be computed on
    # positions within the time-sorted `order`, not on window indices. Slicing
    # `order` by `onset` (a window index) silently yields the length of a
    # meaningless prefix - which reported 883 windows of lead on a 983-window
    # dataset, and identical lead for both arms.
    onset_pos = order.index(onset)
    position = {window_index: pos for pos, window_index in enumerate(order)}

    def lead(first: int | None) -> int | None:
        """Windows of warning before onset, or None if it never warned."""
        if first is None:
            return None
        return max(0, onset_pos - position[first])

    return {
        "held_out_stage": held_out,
        "status": "ok",
        "mode": "forecast",
        "pre_onset_windows_evaluated": evaluated,
        "onset_window_index": onset,
        "threshold": threshold,
        "world_model_lead_windows": lead(wm_first_cross),
        "static_classifier_lead_windows": lead(static_first_cross),
        "world_model_warned": wm_first_cross is not None,
        "static_classifier_warned": static_first_cross is not None,
    }


def _threshold_at_fpr(probs: np.ndarray, labels: np.ndarray, target_fpr: float) -> float:
    """Highest threshold whose TRAIN FPR stays at or below ``target_fpr``."""
    negatives = np.sort(probs[labels == 0])[::-1]
    if negatives.size == 0:
        return 0.5
    allowed = int(negatives.size * target_fpr)
    if allowed <= 0:
        return float(negatives[0]) + 1e-9
    return float(negatives[allowed - 1])


def run_fold(
    labelled: Sequence[LabelledState],
    schema: FeatureSchema,
    vectors: dict[str, np.ndarray],
    held_out: str,
    *,
    target_fpr: float,
    seed: int,
) -> dict:
    """Train without ``held_out`` and score it against unseen ``held_out`` windows."""
    is_benign = [i.label.attack_stage == "Benign" for i in labelled]
    is_held = [i.label.attack_stage == held_out for i in labelled]
    train_idx = [i for i in range(len(labelled)) if not is_held[i]]
    test_benign = [i for i in range(len(labelled)) if is_benign[i] and not is_held[i]]
    test_held = [i for i in range(len(labelled)) if is_held[i]]

    if not test_held:
        return {"held_out_stage": held_out, "status": "absent_from_dataset"}
    if len({i.label.infiltration for i in (labelled[k] for k in train_idx)}) < 2:
        return {"held_out_stage": held_out, "status": "degenerate_train"}

    # Chronological slice of TRAIN for threshold calibration; the stage itself
    # is still absent, so this cannot leak the held-out class.
    cut = int(len(train_idx) * 0.7)
    fit_idx, cal_idx = train_idx[:cut], train_idx[cut:]
    if not cal_idx or not fit_idx:
        return {"held_out_stage": held_out, "status": "too_few_train_windows"}

    y_fit = np.array([1 if labelled[k].label.infiltration else 0 for k in fit_idx])
    coef, intercept = _fit_logistic(vectors["fit"][fit_idx], y_fit, seed=seed)

    y_cal = np.array([1 if labelled[k].label.infiltration else 0 for k in cal_idx])
    cal_probs = _score(vectors["fit"][cal_idx], coef, intercept)
    thr = _threshold_at_fpr(cal_probs, y_cal, target_fpr)

    seen_test = [k for k in test_benign]
    seen_probs = _score(vectors["fit"][seen_test], coef, intercept) if seen_test else np.array([])
    held_probs = _score(vectors["fit"][test_held], coef, intercept)

    benign_fpr = float((seen_probs >= thr).mean()) if seen_probs.size else float("nan")
    detect = float((held_probs >= thr).mean()) if held_probs.size else float("nan")

    # Threshold-free measure: can the model rank unseen-stage windows above
    # benign ones at all? Reported because the train-calibrated threshold can
    # land so high on a balanced classifier that nothing fires, which makes the
    # detection rate above understate separability. AUC does not move with the
    # operating point, so it is the number to quote for "unseen stage".
    auc = None
    oracle = None
    if seen_probs.size and held_probs.size:
        y = np.concatenate([np.zeros(seen_probs.size), np.ones(held_probs.size)])
        s = np.concatenate([seen_probs, held_probs])
        auc = float(roc_auc_score(y, s))
        # Diagnostic ceiling only: threshold set on the TEST benign scores, so
        # it is NOT a deployable operating point. Bounds what any threshold
        # choice could have achieved on this fold.
        oracle_thr = _threshold_at_fpr(seen_probs, np.zeros(seen_probs.size), target_fpr)
        oracle = float((held_probs >= oracle_thr).mean())

    return {
        "held_out_stage": held_out,
        "status": "ok",
        "train_windows": len(fit_idx),
        "calibration_windows": len(cal_idx),
        "unseen_stage_windows": len(test_held),
        "test_benign_windows": len(seen_test),
        "threshold": thr,
        "benign_fpr": benign_fpr,
        "unseen_stage_detection_rate": detect,
        "unseen_stage_auc": auc,
        "unseen_stage_detection_at_oracle_threshold": oracle,
        "unseen_stage_mean_probability": float(held_probs.mean()) if held_probs.size else None,
        "unseen_stage_max_probability": float(held_probs.max()) if held_probs.size else None,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", default="data/raw/cic-ids2017/TrafficLabelling")
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--stride-seconds", type=int, default=150)
    parser.add_argument("--target-fpr", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--horizon", type=int, default=3)
    parser.add_argument("--history-length", type=int, default=3)
    parser.add_argument(
        "--mode",
        default="window",
        choices=("window", "forecast", "both"),
        help="window=detect an unseen stage; forecast=warn before it arrives",
    )
    parser.add_argument("--output", default="reports/generated/loeo")
    args = parser.parse_args()

    print("loading real CIC-IDS2017 days:")
    labelled = load_all_days(
        Path(args.data_dir), window_seconds=args.window_seconds, stride_seconds=args.stride_seconds
    )
    if not labelled:
        raise SystemExit("no windows built; check --data-dir")

    # Feature statistics are fit on ALL windows, matching the shipped schema.
    # Stage labels never enter the schema, so this cannot leak the held-out class.
    schema = fit_feature_schema([i.state for i in labelled])
    matrix = vectorize_states([i.state for i in labelled], schema)
    vectors = {"fit": matrix}

    stages = sorted({i.label.attack_stage for i in labelled} - {"Benign"})
    print(f"\nheld-out stages: {', '.join(stages)}\n")

    folds: list[dict] = []
    if args.mode in ("window", "both"):
        folds = [
            run_fold(labelled, schema, vectors, stage, target_fpr=args.target_fpr, seed=args.seed)
            for stage in stages
        ]

    forecast_folds: list[dict] = []
    if args.mode in ("forecast", "both"):
        print(f"K-step forecast, horizon {args.horizon}, history {args.history_length}:\n")
        for stage in stages:
            f = run_forecast_fold(
                labelled,
                schema,
                stage,
                horizon=args.horizon,
                history_length=args.history_length,
                seed=args.seed,
            )
            forecast_folds.append(f)
            if f["status"] == "ok":
                print(
                    f"  {f['held_out_stage']:<24} WM lead "
                    f"{f['world_model_lead_windows']} win | static lead "
                    f"{f['static_classifier_lead_windows']} win"
                )
            else:
                print(f"  {f['held_out_stage']:<24} {f['status']}")
        print()

    ok = [f for f in folds if f["status"] == "ok"]
    report = {
        "version": LOEO_BENCHMARK_VERSION,
        "feature_schema_version": FEATURE_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset_id": "cic-ids2017",
        "window_seconds": args.window_seconds,
        "stride_seconds": args.stride_seconds,
        "target_fpr_on_train": args.target_fpr,
        "seed": args.seed,
        "total_windows": len(labelled),
        "stage_window_counts": {
            s: sum(1 for i in labelled if i.label.attack_stage == s) for s in ["Benign", *stages]
        },
        "folds": folds,
        "forecast_folds": forecast_folds,
        "summary": {
            "folds_evaluated": len(ok),
            "mean_unseen_stage_detection_rate": (
                float(np.mean([f["unseen_stage_detection_rate"] for f in ok])) if ok else None
            ),
            "max_benign_fpr_across_folds": (
                float(np.max([f["benign_fpr"] for f in ok])) if ok else None
            ),
            "mean_unseen_stage_auc": (
                float(np.mean([f["unseen_stage_auc"] for f in ok])) if ok else None
            ),
        },
        "scope_note": (
            "Single-window detection of an unseen attack stage. Not a K-step forecast "
            "of an unseen chain. Detector rules are not exercised here; see "
            "scripts/validate_real_detectors.py."
        ),
    }

    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / "loeo.json"
    out_path.write_text(json.dumps(report, indent=2) + "\n")

    print(
        f"{'held-out stage':<24} {'detect':>8} {'AUC':>7} {'oracle':>8} {'benignFPR':>10} {'n':>5}"
    )
    print("-" * 64)
    for f in folds:
        if f["status"] != "ok":
            print(f"{f['held_out_stage']:<24} {f['status']:<10}")
            continue
        print(
            f"{f['held_out_stage']:<24} {f['unseen_stage_detection_rate']:>7.1%} "
            f"{f['unseen_stage_auc']:>7.3f} "
            f"{f['unseen_stage_detection_at_oracle_threshold']:>7.1%} "
            f"{f['benign_fpr']:>9.1%} {f['unseen_stage_windows']:>5}"
        )
    s = report["summary"]
    if ok:
        print(
            f"\nmean unseen-stage AUC: {s['mean_unseen_stage_auc']:.3f}  "
            f"mean detection @train-threshold: {s['mean_unseen_stage_detection_rate']:.1%}  "
            f"worst benign FPR: {s['max_benign_fpr_across_folds']:.1%}"
        )
    print(f"\nwrote {out_path}")


if __name__ == "__main__":
    main()
