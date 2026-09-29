#!/usr/bin/env python
"""Diagnose shortcut separability in the SENTINEL synthetic benchmark.

Answers one question per candidate shortcut: how well can a single feature
recover the infiltration label on its own? A generator that hands the model the
answer through one scalar produces a high number here, and that number is the
thing to watch across a generator change.

Run before and after a generator edit; the protocol is identical both times.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sentinel.config import load_settings  # noqa: E402
from sentinel.features import fit_feature_schema, vectorize_states  # noqa: E402
from sentinel.synthetic import generate_labelled_states  # noqa: E402
from sentinel.targets import make_split_manifest  # noqa: E402

OUT = Path("/tmp/separability")


def _clf(settings, seed):
    cfg = settings.model.baseline_config
    return make_pipeline(
        StandardScaler(),
        LogisticRegression(
            C=cfg.regularization_c,
            max_iter=cfg.max_iterations,
            class_weight=cfg.class_weight,
            random_state=seed,
        ),
    )


def volume_only_baseline(states, y, names, train_idx, test_idx, settings, seed):
    """The strongest single volume feature, used as the shortcut reference.

    Deliberately naive. If one feature alone approaches the full model, the full
    model is not measuring what it claims to measure. This is the number the
    sanity test pins.
    """
    best_auc, best_name = -1.0, None
    for name in names:
        x = np.array([s.features.get(name, 0.0) for s in states], dtype=float)
        if not np.isfinite(x).all() or np.allclose(x, x[0]):
            continue
        auc = max(roc_auc_score(y, x), 1 - roc_auc_score(y, x))
        if auc > best_auc:
            best_auc, best_name = auc, name
    x = np.array([[s.features.get(best_name, 0.0)] for s in states], dtype=float)
    clf = _clf(settings, seed)
    clf.fit(x[train_idx], y[train_idx])
    p = clf.predict_proba(x[test_idx])[:, 1]
    return {
        "feature": best_name,
        "univariate_auc": float(best_auc),
        "test_roc_auc": float(roc_auc_score(y[test_idx], p)),
        "test_pr_auc": float(average_precision_score(y[test_idx], p)),
        "test_f1": float(f1_score(y[test_idx], (p >= 0.5).astype(int), zero_division=0)),
    }


def full_baseline(states, y, names, labelled, manifest, settings, seed):
    """The project's own baseline, refit here so before/after share one harness."""
    train_idx = np.array(
        [i for i, ls in enumerate(labelled) if ls.scenario_id in manifest.train_scenarios]
    )
    test_idx = np.array(
        [i for i, ls in enumerate(labelled) if ls.scenario_id in manifest.test_scenarios]
    )
    schema = fit_feature_schema(
        [labelled[i].state for i in train_idx],
        excluded_features=settings.model.baseline_config.excluded_features,
    )
    clf = _clf(settings, seed)
    clf.fit(vectorize_states([labelled[i].state for i in train_idx], schema), y[train_idx])
    p = clf.predict_proba(vectorize_states([labelled[i].state for i in test_idx], schema))[:, 1]
    thr = settings.model.baseline_config.decision_threshold
    pred = (p >= thr).astype(int)
    neg = (y[test_idx] == 0).sum()
    return {
        "test_roc_auc": float(roc_auc_score(y[test_idx], p)),
        "test_pr_auc": float(average_precision_score(y[test_idx], p)),
        "test_f1": float(f1_score(y[test_idx], pred, zero_division=0)),
        "test_precision": float(precision_score(y[test_idx], pred, zero_division=0)),
        "test_recall": float(recall_score(y[test_idx], pred, zero_division=0)),
        "test_false_positive_rate": float(((pred == 1) & (y[test_idx] == 0)).sum() / max(1, neg)),
    }


def single_feature_auc(states, names, label, direction_free=True):
    """ROC-AUC of each single feature, sign-corrected, against the label.

    Sign-corrected so a feature that runs backwards (low bytes = infiltration)
    is not scored as a useless feature.
    """
    rows = []
    for name in names:
        x = np.array([s.features.get(name, 0.0) for s in states], dtype=float)
        if not np.isfinite(x).all() or np.allclose(x, x[0]):
            continue
        auc = roc_auc_score(label, x)
        rows.append((max(auc, 1 - auc) if direction_free else auc, name, auc))
    rows.sort(reverse=True)
    return rows


def main() -> int:
    settings = load_settings("configs/default.yaml")
    data, split_cfg = settings.data, settings.split
    scenarios = [f"scenario-{i:02d}" for i in range(10)]

    labelled = generate_labelled_states(
        scenarios,
        seed=settings.project.random_seed,
        window_seconds=data.window_seconds,
        stride_seconds=data.stride_seconds,
    )
    manifest = make_split_manifest(
        scenarios,
        seed=settings.project.random_seed,
        train_fraction=split_cfg.train_fraction,
        validation_fraction=split_cfg.validation_fraction,
    )

    states = [ls.state for ls in labelled]
    names = sorted({k for s in states for k in s.features})
    y = np.array([1 if ls.label.infiltration else 0 for ls in labelled])

    print(f"scenarios      : {len(scenarios)}")
    print(f"seed           : {settings.project.random_seed}")
    print(f"window/stride  : {data.window_seconds}s / {data.stride_seconds}s")
    print(f"windows        : {len(states)}   features: {len(names)}")
    print(
        f"splits         : train={len(manifest.train_scenarios)} "
        f"val={len(manifest.validation_scenarios)} "
        f"test={len(manifest.test_scenarios)} scenarios "
        "(scenario-level, never window-level)"
    )
    print(f"infiltration   : {int(y.sum())} / {len(y)}  ({y.mean():.3f})")

    # per-stage class distribution
    stages: dict[str, int] = {}
    for ls in labelled:
        stages[ls.label.attack_stage] = stages.get(ls.label.attack_stage, 0) + 1
    print(f"stages         : {stages}")

    # per-stage descriptive stats on the volume-ish features
    print("\n--- per-stage feature distribution (the shortcut surface) ---")
    keys = [
        "bytes",
        "bytes_sum",
        "packets",
        "event_count",
        "dst_port_nunique",
        "src_nunique",
        "dst_nunique",
        "iat_mean",
        "payload_size_sum",
    ]
    header = f"{'feature':22s}" + "".join(
        f"{k[:13]:>26s}" for k in ["Benign", "Reconnaissance", "Lateral Movement"]
    )
    print(header)
    for name in keys:
        if name not in names:
            continue
        cells = []
        for stage in ("Benign", "Reconnaissance", "Lateral Movement"):
            vals = np.array(
                [
                    ls.state.features.get(name, 0.0)
                    for ls in labelled
                    if ls.label.attack_stage == stage
                ]
            )
            if vals.size:
                p10, p90 = np.percentile(vals, 10), np.percentile(vals, 90)
                cells.append(f"{np.median(vals):9.1f} [{p10:7.1f},{p90:7.1f}]")
            else:
                cells.append(f"{'-':>26s}")
        print(f"{name:22s}" + "".join(f"{c:>26s}" for c in cells))

    # single-feature recovery
    print("\n--- single-feature ROC-AUC against infiltration (sign-corrected) ---")
    print("A value near 1.0 means one feature alone nearly gives away the label.")
    rows = single_feature_auc(states, names, y)
    for auc, name, raw in rows[:15]:
        print(f"  {name:24s} {auc:.4f}   (raw {raw:.4f})")
    best_auc, best_name, _ = rows[0]

    # exact-separation check: is there a threshold with zero overlap?
    print("\n--- overlap check on the strongest shortcut ---")
    x = np.array([s.features.get(best_name, 0.0) for s in states], dtype=float)
    lo, hi = x[y == 0].max(), x[y == 1].min()
    print(f"  feature       : {best_name}")
    print(f"  benign max    : {lo:.1f}")
    print(f"  infiltration min: {hi:.1f}")
    print(f"  separable     : {lo < hi}  (benign max < infiltration min => zero overlap)")

    summary = {
        "windows": len(states),
        "features": len(names),
        "infiltration_rate": float(y.mean()),
        "stages": stages,
        "best_single_feature": best_name,
        "best_single_feature_auc": float(best_auc),
        "separable_by": best_name,
        "separable": bool(lo < hi),
        "top10": [{"feature": n, "auc": float(a)} for a, n, _ in rows[:10]],
    }

    train_idx = np.array(
        [i for i, ls in enumerate(labelled) if ls.scenario_id in manifest.train_scenarios]
    )
    test_idx = np.array(
        [i for i, ls in enumerate(labelled) if ls.scenario_id in manifest.test_scenarios]
    )
    full = full_baseline(
        states, y, names, labelled, manifest, settings, settings.project.random_seed
    )
    single = volume_only_baseline(
        states, y, names, train_idx, test_idx, settings, settings.project.random_seed
    )
    print("\n--- test-split metrics (scenario-level holdout, seed 42) ---")
    print(
        f"  full baseline (98 features) : ROC-AUC {full['test_roc_auc']:.4f}  "
        f"PR-AUC {full['test_pr_auc']:.4f}  F1 {full['test_f1']:.4f}  "
        f"P {full['test_precision']:.4f}  R {full['test_recall']:.4f}  "
        f"FPR {full['test_false_positive_rate']:.4f}"
    )
    print(
        f"  ONE feature ({single['feature'][:16]:16s}): ROC-AUC {single['test_roc_auc']:.4f}  "
        f"PR-AUC {single['test_pr_auc']:.4f}  F1 {single['test_f1']:.4f}"
    )
    gap = full["test_roc_auc"] - single["test_roc_auc"]
    print(f"  gap full-minus-single       : {gap:+.4f}")
    print("  A near-zero gap means the extra 97 features add nothing and the")
    print("  benchmark is really a one-feature problem.")

    summary["full_baseline"] = full
    summary["single_feature_baseline"] = single
    summary["roc_auc_gap"] = float(gap)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(summary, indent=2))
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
