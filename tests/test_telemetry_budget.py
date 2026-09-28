# SPDX-License-Identifier: Apache-2.0
"""Telemetry budget: the claim is "no measurable loss", never "equally good".

The measurement this guards against is subtle. On this data the top 5 features
outscore all 98, and the ablation curve is non-monotonic - both are signatures of
noise on a 68-window validation split, not of a real ranking. These tests pin the
distinction: the tool must be able to say "cannot tell", and must say so when it
should.
"""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.telemetry_budget import (
    TIERS,
    AblationPoint,
    AblationResult,
    ablation_curve,
    audit_tier_coverage,
    bootstrap_difference,
    cost_of,
    describe_profile,
    pareto_frontier,
    rank_by_weight,
    required_tiers,
    tier_for,
)


def _subset(names: list[str], key: str) -> list[str]:
    return names


def _point(n: int, score: float, cost: float, ci: tuple[float, float]) -> AblationPoint:
    low, high = ci
    return AblationPoint(
        features=tuple(f"f{i}" for i in range(n)),
        score=score,
        n_features=n,
        cost=cost,
        tiers=("flow_window",),
        mean_full=score,
        loss_from_full=0.0,
        ci_low=low,
        ci_high=high,
        indistinguishable=low <= 0.0 <= high,
    )


# ── the cost model ──────────────────────────────────────────────────────


def test_tiers_are_ordered_by_collection_effort() -> None:
    ordinals = [tier.ordinal for tier in TIERS]
    assert ordinals == sorted(ordinals)
    assert len(set(ordinals)) == len(ordinals)


def test_packet_features_are_the_most_expensive() -> None:
    assert tier_for("ttl_mean").name == "packet"
    assert tier_for("retransmission_rate").name == "packet"
    assert tier_for("frag_count").name == "packet"


def test_per_flow_features_cost_more_than_window_aggregates() -> None:
    assert tier_for("iat_mean").name == "flow_per_flow"
    assert tier_for("dst_port_nunique").name == "flow_per_flow"
    assert tier_for("bytes_sum").name == "flow_window"
    assert tier_for("flow_count").name == "flow_window"


def test_one_packet_feature_makes_the_whole_set_expensive() -> None:
    cheap = cost_of(["bytes_sum", "flow_count", "packets_sum"])
    mixed = cost_of(["bytes_sum", "ttl_mean"])
    assert mixed > cheap


def test_an_empty_set_costs_nothing() -> None:
    assert cost_of([]) == 0.0


def test_tier_audit_counts_every_feature_exactly_once() -> None:
    names = ["bytes_sum", "iat_mean", "ttl_mean", "dst_port_nunique", "flow_count"]
    counts = audit_tier_coverage(names)
    assert sum(counts.values()) == len(names)
    assert counts["packet"] == 1
    assert counts["flow_per_flow"] == 2


def test_required_tiers_are_ascending_and_deduplicated() -> None:
    assert required_tiers(["bytes_sum", "ttl_mean", "iat_mean", "ttl_p90"]) == [
        "flow_window",
        "flow_per_flow",
        "packet",
    ]


def test_a_profile_describes_what_it_needs() -> None:
    described = describe_profile(["bytes_sum", "ttl_mean"])
    assert described["n_features"] == 2
    assert described["required_tiers"] == ["flow_window", "packet"]
    assert described["cost_units"] > 0


# ── the bootstrap ───────────────────────────────────────────────────────


def test_a_paired_bootstrap_is_narrower_than_an_unpaired_one() -> None:
    # Both subsets are evaluated on the same windows, so the pairing must be
    # used; otherwise the interval charges for variance that cancels.
    rng = np.random.default_rng(0)
    shared = rng.uniform(size=200)
    full = shared + rng.normal(0, 0.05, size=200)
    subset = shared + rng.normal(0, 0.05, size=200)

    paired_low, paired_high = bootstrap_difference(full, subset, iterations=500)
    paired_width = paired_high - paired_low

    rng2 = np.random.default_rng(1)
    unpaired = bootstrap_difference(full, rng2.permutation(subset), iterations=500, seed=2)
    unpaired_width = unpaired[1] - unpaired[0]

    assert paired_width < unpaired_width


def test_the_interval_contains_zero_when_there_is_no_difference() -> None:
    rng = np.random.default_rng(3)
    scores = rng.uniform(size=300)
    low, high = bootstrap_difference(scores, scores.copy(), iterations=400)
    assert low == pytest.approx(0.0, abs=1e-9)
    assert high == pytest.approx(0.0, abs=1e-9)


def test_the_interval_excludes_zero_when_there_is_a_real_difference() -> None:
    rng = np.random.default_rng(4)
    full = rng.normal(0.80, 0.05, size=400)
    subset = rng.normal(0.50, 0.05, size=400)
    low, high = bootstrap_difference(full, subset, iterations=500)
    assert low > 0.0, "a real 0.30 gap should not straddle zero"


def test_a_worse_subset_gives_a_positive_interval_for_a_lower_is_better_metric() -> None:
    """Regression: the interval and the loss must point the same way.

    Brier is lower-is-better, so a *worse* subset is one with a *larger* mean,
    and the CI for ``subset - full`` must sit above zero. The original call site
    passed the arguments the other way round, which left the sign of every
    reported bound upside down while still straddling zero, so the existing tests
    - all of which used a higher-is-better arrangement - passed throughout.
    """
    rng = np.random.default_rng(5)
    full = rng.normal(0.02, 0.004, size=400)
    subset = full + 0.01
    low, high = bootstrap_difference(subset, full, iterations=500)
    assert low > 0.0
    assert (low, high) != bootstrap_difference(full, subset, iterations=500)


def test_the_interval_agrees_with_the_reported_loss() -> None:
    """The CI and the point estimate must point the same way.

    Checking the endpoints in isolation is what let the sign bug hide: a flipped
    interval still contains zero, so the earlier tests all passed. Agreement
    between the point estimate and the bounds is the check that fails.
    """
    rng = np.random.default_rng(6)
    full = rng.uniform(0.01, 0.03, size=80)
    # Noisy, not a constant shift: a constant offset makes every paired
    # difference identical, the interval collapses to a point, and the test
    # would measure float rounding rather than the sign convention.
    worse = full + 0.005 + rng.normal(0, 0.001, size=80)
    result = ablation_curve(
        subsets={"full": ("a", "b"), "lean": ("a",)},
        per_window_scores={"full": full, "lean": worse},
        bootstrap_iterations=400,
    )
    point = result.points[0]
    assert point.loss_from_full > 0.0, "dropping features made Brier worse"
    assert point.ci_low <= point.loss_from_full <= point.ci_high


def test_misaligned_windows_are_rejected() -> None:
    with pytest.raises(ValueError, match="same windows"):
        bootstrap_difference(np.zeros(10), np.zeros(9))


def test_an_empty_bootstrap_is_rejected() -> None:
    with pytest.raises(ValueError, match="at least one window"):
        bootstrap_difference(np.array([]), np.array([]))


# ── the curve ───────────────────────────────────────────────────────────


def _noisy_curve(n_windows: int = 80) -> dict:
    """Per-window scores where small subsets are indistinguishable from the full set.

    Mirrors the real measurement: on a small validation split the difference
    between 5 and 15 features is inside the noise. The per-window noise is
    deliberately comparable to the gap - with a shared low-noise term the paired
    difference has almost no variance and the bootstrap detects everything, which
    would make the test pass for the wrong reason.
    """
    rng = np.random.default_rng(11)
    base = rng.uniform(0, 1, size=n_windows)
    full = np.clip(0.5 + 0.50 * base + rng.normal(0, 0.10, n_windows), 0, 1)
    return {
        "full": full,
        "top5": np.clip(0.5 + 0.48 * base + rng.normal(0, 0.10, n_windows), 0, 1),
        "top10": np.clip(0.5 + 0.49 * base + rng.normal(0, 0.10, n_windows), 0, 1),
        "top20": np.clip(0.5 + 0.20 * base + rng.normal(0, 0.10, n_windows), 0, 1),
    }


def test_a_subset_inside_the_noise_is_called_indistinguishable() -> None:
    scores = _noisy_curve()
    subsets = {
        "full": [f"f{i}" for i in range(98)],
        "top5": [f"f{i}" for i in range(5)],
        "top10": [f"f{i}" for i in range(10)],
        "top20": [f"f{i}" for i in range(20)],
    }
    result = ablation_curve(subsets, scores, bootstrap_iterations=600)
    by_key = {point.n_features: point for point in result.points}

    assert by_key[5].indistinguishable
    assert by_key[10].indistinguishable
    assert not by_key[20].indistinguishable, "a real 0.28 gap should be detected"
    assert result.is_reliable


def test_the_recommendation_is_the_smallest_indistinguishable_set() -> None:
    scores = _noisy_curve()
    subsets = {
        "full": [f"f{i}" for i in range(98)],
        "top5": [f"f{i}" for i in range(5)],
        "top10": [f"f{i}" for i in range(10)],
        "top20": [f"f{i}" for i in range(20)],
    }
    result = ablation_curve(subsets, scores, bootstrap_iterations=600)
    assert result.recommendation is not None
    assert len(result.recommendation) == 5
    assert "no measurable loss" in result.note
    assert "not" in result.note and "equally good" in result.note


def test_no_recommendation_when_every_subset_is_worse() -> None:
    rng = np.random.default_rng(12)
    full = np.clip(rng.normal(0.9, 0.02, size=200), 0, 1)
    subsets = {
        "full": [f"f{i}" for i in range(30)],
        "half": [f"f{i}" for i in range(15)],
    }
    result = ablation_curve(subsets, {"full": full, "half": full * 0.5}, bootstrap_iterations=400)
    assert result.recommendation is None
    assert not result.is_reliable
    assert "no smaller profile is recommended" in result.note
    # The curve is still returned, so the cost of using the full set is visible.
    assert result.points


def test_a_missing_full_key_is_rejected() -> None:
    with pytest.raises(ValueError, match="must contain 'full'"):
        ablation_curve({"top5": ["a"]}, {"top5": np.array([0.5])}, bootstrap_iterations=10)


def test_a_misaligned_subset_is_rejected_not_silently_averaged() -> None:
    subsets = {"full": ["a", "b"], "top5": ["a"]}
    scores = {"full": np.zeros(10), "top5": np.zeros(5)}
    with pytest.raises(ValueError, match="paired"):
        ablation_curve(subsets, scores, bootstrap_iterations=10)


def test_the_curve_is_ordered_by_size() -> None:
    scores = _noisy_curve()
    subsets = {
        "full": [f"f{i}" for i in range(50)],
        "top5": ["a"],
        "top20": [f"f{i}" for i in range(20)],
    }
    result = ablation_curve(subsets, scores, bootstrap_iterations=200)
    sizes = [point.n_features for point in result.points]
    assert sizes == sorted(sizes)


def test_the_result_serialises_for_the_report() -> None:
    scores = _noisy_curve()
    subsets = {"full": [f"f{i}" for i in range(20)], "top5": [f"f{i}" for i in range(5)]}
    payload = ablation_curve(subsets, scores, bootstrap_iterations=200).as_dict()
    assert payload["n_features_full"] == 20
    assert payload["bootstrap_iterations"] == 200
    assert "curve" in payload and payload["curve"]
    assert "version" in payload


# ── ranking and the frontier ────────────────────────────────────────────


def test_ranking_takes_the_largest_magnitudes() -> None:
    names = ["a", "b", "c", "d"]
    weights = [0.1, -0.9, 0.4, 0.2]
    assert rank_by_weight(names, weights, 2) == ["b", "c"]


def test_ranking_ignores_the_sign() -> None:
    assert rank_by_weight(["a", "b"], [-5.0, 1.0], 1) == ["a"]


def test_ranking_cannot_exceed_the_feature_count() -> None:
    with pytest.raises(ValueError, match="more features than exist"):
        rank_by_weight(["a"], [1.0], 5)


def test_the_frontier_drops_dominated_points() -> None:
    points = [
        _point(5, 0.90, 1.0, (-0.01, 0.01)),
        _point(10, 0.85, 2.0, (-0.1, 0.1)),  # dominated: worse and costlier
        _point(20, 0.95, 3.0, (0.01, 0.1)),
        _point(30, 0.80, 4.0, (-0.2, 0.2)),
    ]
    frontier = pareto_frontier(points)
    assert [p.n_features for p in frontier] == [5, 20]


def test_a_dominated_point_is_still_in_the_full_curve() -> None:
    # Hiding it would misrepresent the trade; the frontier is a view, not a filter
    # applied to the data.
    scores = _noisy_curve()
    subsets = {"full": [f"f{i}" for i in range(30)], "top5": [f"f{i}" for i in range(5)]}
    result = ablation_curve(subsets, scores, bootstrap_iterations=200)
    assert len(result.points) == 1
    assert len(pareto_frontier(result.points)) <= len(result.points)


def test_an_empty_frontier_is_allowed() -> None:
    assert pareto_frontier([]) == []


def test_the_result_can_report_that_nothing_is_reliable() -> None:
    empty = AblationResult()
    assert not empty.is_reliable
    assert empty.as_dict()["recommendation"] is None


# -- forward selection, which replaced ranking by coefficient magnitude ----
# Ranking by |coef| gave a non-monotone curve: 8 features indistinguishable
# from 98 while 12 was measurably worse, which is incoherent for a nested
# family. These pin the properties the replacement has to have.


def _separable_problem(n: int = 200, n_useful: int = 3, seed: int = 5):
    """Labels depend on a few columns; the rest are noise columns."""
    rng = np.random.default_rng(seed)
    columns = rng.normal(size=(n, 12))
    labels = (columns[:, :n_useful].sum(axis=1) > 0).astype(float)
    return columns, labels


def test_forward_selection_finds_the_useful_columns_first() -> None:
    import sys as _sys
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path as _Path

    spec = spec_from_file_location(
        "sentinel_telemetry_script",
        _Path(__file__).resolve().parents[1] / "scripts" / "run_telemetry_budget.py",
    )
    assert spec and spec.loader
    module = module_from_spec(spec)
    _sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    columns, labels = _separable_problem()
    names = [f"c{i}" for i in range(columns.shape[1])]
    mask = np.ones(len(labels), dtype=bool)
    selected = module.forward_select(columns, labels, mask, names, (1, 2, 3, 4), seed=5)

    assert sorted(selected) == [1, 2, 3, 4]
    for size in (2, 3, 4):
        assert len(selected[size]) == size
    # The first pick should be one of the three columns that matter.
    first = names.index(selected[1][0])
    assert first < 3, f"forward selection opened with noise column c{first}"


def test_forward_selection_is_nested() -> None:
    import sys as _sys
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path as _Path

    spec = spec_from_file_location(
        "sentinel_telemetry_script2",
        _Path(__file__).resolve().parents[1] / "scripts" / "run_telemetry_budget.py",
    )
    assert spec and spec.loader
    module = module_from_spec(spec)
    _sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    columns, labels = _separable_problem(seed=9)
    names = [f"c{i}" for i in range(columns.shape[1])]
    mask = np.ones(len(labels), dtype=bool)
    selected = module.forward_select(columns, labels, mask, names, (2, 4, 6), seed=9)

    for smaller, larger in ((2, 4), (4, 6)):
        assert selected[smaller] == selected[larger][:smaller], (
            "forward selection must be nested: a feature set at depth k has to "
            "be a prefix of the set at depth k+1"
        )


def test_forward_selection_reaches_the_sizes_it_was_asked_for() -> None:
    import sys as _sys
    from importlib.util import module_from_spec, spec_from_file_location
    from pathlib import Path as _Path

    spec = spec_from_file_location(
        "sentinel_telemetry_script3",
        _Path(__file__).resolve().parents[1] / "scripts" / "run_telemetry_budget.py",
    )
    assert spec and spec.loader
    module = module_from_spec(spec)
    _sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    columns, labels = _separable_problem(seed=13, n_useful=2)
    names = [f"c{i}" for i in range(columns.shape[1])]
    mask = np.ones(len(labels), dtype=bool)
    # The earlier bug added one feature per candidate size, so asking for
    # (3, 5, 8) returned 1, 2, 3 - the depths it never asked about.
    selected = module.forward_select(columns, labels, mask, names, (3, 5, 8), seed=13)
    assert sorted(selected) == [3, 5, 8]
    assert len(selected[8]) == 8
