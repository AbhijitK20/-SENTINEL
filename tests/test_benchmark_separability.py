# SPDX-License-Identifier: Apache-2.0
"""The synthetic benchmark must not become a one-feature problem again.

`synthetic-recon-lateral-v2` drew each phase from a disjoint band of byte
volumes, port sets, destination hosts and TCP flag words. The infiltration
label was therefore recoverable from one scalar: over 98 features the baseline
scored ROC-AUC 0.9933 on the test split while a *single* feature scored 0.9861
- a gap of 0.0072. Ninety-seven features were decoration, and every published
metric measured the shortcut rather than forecasting.

Two things are pinned here, and they are different claims:

1. **No single feature may be a near-perfect classifier.** One number, one
   interpretation, stable across seeds.
2. **The full feature set must beat the best single feature by a real margin.**
   This is the one that matters. A dataset can have no perfectly separating
   feature and still be trivial, if one feature gets to 0.99 on its own.

The thresholds are not arbitrary and are not aspiration targets. They are set
with headroom *below* the v3 measurement so that ordinary seed-to-seed wobble
does not fail the build, while a return to v2-like separability does. The
comment on each records the measurement it was derived from.
"""

from __future__ import annotations

import numpy as np
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from sentinel.features import fit_feature_schema, vectorize_states
from sentinel.synthetic import DATASET_ID, generate_labelled_states
from sentinel.targets import make_split_manifest

SEEDS = (42, 17, 7)
SCENARIOS = 6

#: v3 measured, per seed, on the scenario-level test split:
#:   best single-feature ROC-AUC 0.741 / full model 0.930  -> gap 0.113
#: A single feature at 0.95 would mean the shortcut is back, whatever the
#: headline says. The floor is 0.90, well clear of the measurement.
MAX_SINGLE_FEATURE_AUC = 0.90

#: v3 measured gap 0.113. A gap under 0.03 means the other 97 features add
#: nothing, which is the v2 failure mode in its exact original shape (0.0072).
MIN_FULL_MINUS_SINGLE_GAP = 0.03


@pytest.fixture(scope="module")
def benchmark():
    settings = [
        generate_labelled_states(
            [f"scenario-{i:02d}" for i in range(SCENARIOS)],
            seed=seed,
            window_seconds=60,
            stride_seconds=30,
        )
        for seed in SEEDS
    ]
    return settings


def _best_single_feature(states, y, names):
    best = (-1.0, None)
    for name in names:
        x = np.array([s.features.get(name, 0.0) for s in states], dtype=float)
        if not np.isfinite(x).all() or np.allclose(x, x[0]):
            continue
        auc = max(roc_auc_score(y, x), 1 - roc_auc_score(y, x))
        if auc > best[0]:
            best = (float(auc), name)
    return best


def _clf():
    return make_pipeline(
        StandardScaler(),
        LogisticRegression(C=1.0, max_iter=1000, class_weight="balanced", random_state=42),
    )


def test_dataset_id_records_the_non_trivial_generator() -> None:
    """The id moved with the data so a v2 artifact cannot be applied to v3."""
    assert DATASET_ID == "synthetic-recon-lateral-v3"


@pytest.mark.parametrize("seed", SEEDS)
def test_no_single_feature_is_a_near_perfect_classifier(seed: int) -> None:
    """One feature must not recover the infiltration label on its own."""
    labelled = generate_labelled_states(
        [f"scenario-{i:02d}" for i in range(SCENARIOS)],
        seed=seed,
        window_seconds=60,
        stride_seconds=30,
    )
    states = [item.state for item in labelled]
    names = sorted({k for s in states for k in s.features})
    y = np.array([1 if item.label.infiltration else 0 for item in labelled])
    auc, name = _best_single_feature(states, y, names)
    assert auc < MAX_SINGLE_FEATURE_AUC, (
        f"seed {seed}: feature {name!r} alone reaches ROC-AUC {auc:.4f} against the "
        f"infiltration label. That is the v2 failure mode returning: the label is "
        "recoverable from one scalar, so the benchmark measures the generator, not "
        "forecasting. See scripts/diagnose_separability.py."
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_the_full_feature_set_beats_the_best_single_feature(seed: int) -> None:
    """The other features must earn their place.

    This is the assertion that would have caught v2. A single feature scoring
    0.9861 against a full model's 0.9933 is a one-feature benchmark wearing a
    98-feature costume.
    """
    scenario_ids = [f"scenario-{i:02d}" for i in range(SCENARIOS)]
    labelled = generate_labelled_states(
        scenario_ids, seed=seed, window_seconds=60, stride_seconds=30
    )
    states = [item.state for item in labelled]
    names = sorted({k for s in states for k in s.features})
    y = np.array([1 if item.label.infiltration else 0 for item in labelled])
    manifest = make_split_manifest(
        scenario_ids, seed=seed, train_fraction=0.6, validation_fraction=0.2
    )
    train = np.array(
        [i for i, it in enumerate(labelled) if it.scenario_id in manifest.train_scenarios]
    )
    test = np.array(
        [i for i, it in enumerate(labelled) if it.scenario_id in manifest.test_scenarios]
    )
    if len(set(y[test])) < 2:
        pytest.skip("test split is single-class for this scenario count")

    # Single-feature reference, fit on the same training rows.
    _, best_name = _best_single_feature(states, y, names)
    x1 = np.array([[s.features.get(best_name, 0.0)] for s in states], dtype=float)
    one = _clf()
    one.fit(x1[train], y[train])
    single_auc = roc_auc_score(y[test], one.predict_proba(x1[test])[:, 1])

    # The project's own feature pipeline: schema fit on train only.
    schema = fit_feature_schema([labelled[i].state for i in train], excluded_features=[])
    full = _clf()
    full.fit(vectorize_states([labelled[i].state for i in train], schema), y[train])
    full_auc = roc_auc_score(
        y[test],
        full.predict_proba(vectorize_states([labelled[i].state for i in test], schema))[:, 1],
    )

    gap = full_auc - single_auc
    assert gap > MIN_FULL_MINUS_SINGLE_GAP, (
        f"seed {seed}: the full model ({full_auc:.4f}) beats the single best feature "
        f"{best_name!r} ({single_auc:.4f}) by only {gap:+.4f}. At or below "
        f"{MIN_FULL_MINUS_SINGLE_GAP} the other {len(names) - 1} features are not "
        "earning their place, which is the v2 condition (gap 0.0072)."
    )


@pytest.mark.parametrize("seed", SEEDS)
def test_benign_and_infiltration_overlap_on_volume(seed: int) -> None:
    """Window bytes must not separate the classes on their own.

    The specific artefact this replaces: on v2 the 10th percentile of
    infiltration windows (64,077 B) sat above the 90th percentile of benign
    windows (41,125 B), i.e. zero overlap, so `bytes` was a deterministic
    function of the label.
    """
    labelled = generate_labelled_states(
        [f"scenario-{i:02d}" for i in range(SCENARIOS)],
        seed=seed,
        window_seconds=60,
        stride_seconds=30,
    )
    benign, attack = [], []
    for item in labelled:
        value = item.state.features.get("bytes", 0.0)
        (attack if item.label.infiltration else benign).append(value)
    benign_arr, attack_arr = np.array(benign), np.array(attack)
    assert benign_arr.size > 5 and attack_arr.size > 5
    assert attack_arr.min() < benign_arr.max(), (
        "no benign window exceeds the smallest infiltration window: the classes are "
        "perfectly separated by volume, which is the v2 generator"
    )
    lo_b, hi_b = np.percentile(benign_arr, 10), np.percentile(benign_arr, 90)
    lo_a, hi_a = np.percentile(attack_arr, 10), np.percentile(attack_arr, 90)
    assert lo_a < hi_b and lo_b < hi_a, (
        f"volume interquartile ranges do not overlap: "
        f"benign p10-p90 [{lo_b:.0f}, {hi_b:.0f}], attack p10-p90 [{lo_a:.0f}, {hi_a:.0f}]"
    )


def test_the_benchmark_fixture_itself_is_usable(benchmark) -> None:
    """Guard the fixture: an empty or single-class set would skip every check."""
    for labelled in benchmark:
        assert len(labelled) > 50
        labels = {item.label.infiltration for item in labelled}
        assert labels == {True, False}, "a seed produced a single-class dataset"
