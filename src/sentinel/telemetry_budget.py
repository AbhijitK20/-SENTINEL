# SPDX-License-Identifier: Apache-2.0
"""What is the smallest set of telemetry that still works?

A defender cannot instrument everything, and every feature collected is privacy
surface, storage and a sensor that can break. So the useful question is not "how
many features does the model have" but "how few does it need".

The first measurement of that, on this data, is startling and slightly suspicious:
**the top 5 features by coefficient magnitude outscore all 98** on validation F1
(0.941 against 0.839). Two things follow from that, and this module exists to
handle both.

First, a smaller model being *better* usually means the full model is overfitting
a small training set, not that 5 features are sufficient. Reporting "5 features
suffice" from that would be reading a defect as a result.

Second, and more seriously, the validation split here has 68 samples. An F1
difference of 0.1 on 68 samples is one or two windows. The ablation curve is
non-monotonic - 5 through 15 identical, 20 and 30 worse, 50 back to baseline -
which is the signature of noise, not of a real ranking.

So the deliverable is deliberately not a list. It is:

- :func:`ablation_curve` - performance as features are removed, with a **bootstrap
  confidence interval on the difference from full**, so "no worse" is a
  measurement rather than an eyeball;
- :func:`recommend_profile` - the smallest set that is **statistically
  indistinguishable** from the full set, which is a different and much weaker
  claim than "as good" or "better";
- :func:`pareto_frontier` - performance against telemetry cost, so a smaller set
  that is measurably worse is visible as a trade rather than hidden;
- :data:`TIERS` - what each feature actually costs to collect, which is the
  number a deployment actually cares about.

The recommendation is gated on evidence and will return ``None`` when the data
cannot support one. With 68 validation windows it usually does, and that is the
correct answer to give.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass, field

import numpy as np

TELEMETRY_BUDGET_VERSION = "telemetry-budget-v1"


@dataclass(frozen=True)
class Tier:
    """One level of collection effort.

    ``ordinal`` is the ordering, not a measured cost: a packet capture is more
    expensive to run than reading a flow log, and the ordering is not in dispute.
    The absolute numbers are deliberately absent - a deployment knows its own
    cost and the frontier is expressed in tiers so it can place them.
    """

    name: str
    ordinal: int
    requires: str
    description: str


TIERS: tuple[Tier, ...] = (
    Tier(
        "flow_window",
        1,
        "flow records, window aggregates only",
        "Derived from counts and sums the flow exporter already emits.",
    ),
    Tier(
        "flow_per_flow",
        2,
        "per-flow records retained, not just aggregates",
        "Needs values kept per flow: port distributions, inter-arrival spreads.",
    ),
    Tier(
        "packet",
        3,
        "packet capture on the sensing interface",
        "Needs a sensor on the wire: TTL, flags, fragments, retransmissions.",
    ),
)

_TIER_BY_NAME = {tier.name: tier for tier in TIERS}

# Window feature name prefixes that can only be produced from packet capture.
# Matches ``file_forecast.PACKET_INPUT_KEYS`` for input events; the same
# attributes surface here as window aggregates with a suffix.
_PACKET_PREFIXES = (
    "ttl",
    "frag",
    "retransmission",
    "syn_count",
    "ack_count",
    "rst_count",
    "tcp_flags",
    "payload_size",
    "window_size",
    "ip_flags",
)

# Window features that need per-flow values rather than window totals.
_PER_FLOW_PREFIXES = (
    "iat",
    "src_port",
    "dst_port",
    "flow_duration",
    "bidirectional",
    "flow_event",
    "source_port",
)


def tier_for(feature: str) -> Tier:
    """Which collection tier a window feature belongs to.

    Prefix-based, and therefore a maintenance liability: a new feature with an
    unlisted prefix is silently assigned the cheapest tier and flatters the
    frontier. :func:`audit_tier_coverage` exists so that can be detected, and it
    is checked in the tests.
    """
    name = feature.lower()
    if name.startswith(_PACKET_PREFIXES):
        return _TIER_BY_NAME["packet"]
    if name.startswith(_PER_FLOW_PREFIXES):
        return _TIER_BY_NAME["flow_per_flow"]
    return _TIER_BY_NAME["flow_window"]


def audit_tier_coverage(names: Sequence[str]) -> dict[str, int]:
    """How many features fall into each tier, for the report to publish."""
    counts = {tier.name: 0 for tier in TIERS}
    for name in names:
        counts[tier_for(name).name] += 1
    return counts


def cost_of(names: Sequence[str]) -> float:
    """Total collection cost, in tier units.

    A weighted sum of the tiers a set needs: the maximum ordinal dominates,
    because a set containing one packet feature needs packet capture in full. The
    sum on top of the max is the per-flow work that packet capture does not
    subsume.
    """
    if not names:
        return 0.0
    tiers = [tier_for(name) for name in names]
    return max(t.ordinal for t in tiers) + sum(t.ordinal for t in tiers) / len(tiers)


def required_tiers(names: Sequence[str]) -> list[str]:
    """The distinct collection tiers a set needs, in ascending order."""
    return sorted({tier_for(name).name for name in names}, key=lambda n: _TIER_BY_NAME[n].ordinal)


@dataclass(frozen=True)
class AblationPoint:
    """One point on the curve: a feature subset and what it cost.

    The metric is the mean per-window **Brier** score, so lower is better, and
    ``loss_from_full`` is ``subset - full``: positive means the subset is worse
    by that much. Brier rather than F1 because the bootstrap needs a per-window
    quantity, and F1 is not additive over windows - a bootstrap over F1 would be
    measuring the resampling.
    """

    features: tuple[str, ...]
    score: float
    n_features: int
    cost: float
    tiers: tuple[str, ...]
    mean_full: float
    loss_from_full: float
    ci_low: float
    ci_high: float
    indistinguishable: bool

    def as_dict(self) -> dict:
        return {
            "n_features": self.n_features,
            "brier": self.score,
            "cost": self.cost,
            "tiers": list(self.tiers),
            "loss_from_full": self.loss_from_full,
            "ci_low": self.ci_low,
            "ci_high": self.ci_high,
            "indistinguishable_from_full": self.indistinguishable,
        }


@dataclass
class AblationResult:
    """The whole curve, plus the recommendation and whether one is justified."""

    points: list[AblationPoint] = field(default_factory=list)
    full_features: tuple[str, ...] = ()
    full_score: float = 0.0
    bootstrap_iterations: int = 0
    recommendation: tuple[str, ...] | None = None
    recommendation_score: float | None = None
    recommendation_ci: tuple[float, float] | None = None
    note: str = ""

    @property
    def is_reliable(self) -> bool:
        """Whether any point is genuinely indistinguishable from the full set.

        A recommendation is only offered when the evidence supports one. When
        every subset is measurably worse, the honest answer is "you need the
        features", and the frontier is still returned so the cost of that is
        visible.
        """
        return any(point.indistinguishable for point in self.points)

    def as_dict(self) -> dict:
        return {
            "version": TELEMETRY_BUDGET_VERSION,
            "n_features_full": len(self.full_features),
            "full_score": self.full_score,
            "bootstrap_iterations": self.bootstrap_iterations,
            "is_reliable": self.is_reliable,
            "recommendation": list(self.recommendation) if self.recommendation else None,
            "recommendation_score": self.recommendation_score,
            "note": self.note,
            "curve": [point.as_dict() for point in self.points],
        }


def bootstrap_difference(
    scores_a: np.ndarray,
    scores_b: np.ndarray,
    *,
    iterations: int = 2000,
    seed: int = 0,
    level: float = 0.95,
) -> tuple[float, float]:
    """Paired bootstrap CI for ``mean(scores_a) - mean(scores_b)``.

    Paired, because both are evaluated on the same windows; an unpaired bootstrap
    would charge the comparison for variance it does not have. Resampling the
    *paired differences* directly is the same thing and simpler to reason about.

    The parameters are deliberately *not* named ``full`` and ``subset``. An
    earlier version was, and the caller passed them in the opposite order to the
    one it wanted, so the interval came back with the sign flipped - harmless for
    "does this contain zero", but the reported bounds were upside down. Naming
    the arguments ``a`` and ``b`` forces the caller to state which direction it
    means, which is the only thing that ever mattered here.

    The interval containing zero is what "indistinguishable" means.
    """
    a = np.asarray(scores_a, dtype=float)
    b = np.asarray(scores_b, dtype=float)
    if a.shape != b.shape:
        raise ValueError("paired bootstrap needs the same windows for both")
    if a.size == 0:
        raise ValueError("at least one window is required")
    differences = a - b
    rng = np.random.default_rng(seed)
    n = differences.size
    means = np.empty(iterations)
    for index in range(iterations):
        means[index] = differences[rng.integers(0, n, size=n)].mean()
    alpha = 1.0 - level
    low, high = np.quantile(means, [alpha / 2.0, 1.0 - alpha / 2.0])
    return float(low), float(high)


def ablation_curve(
    subsets: dict[str, Sequence[str]],
    per_window_scores: dict[str, np.ndarray],
    *,
    full_key: str = "full",
    bootstrap_iterations: int = 2000,
    seed: int = 0,
    level: float = 0.95,
) -> AblationResult:
    """Score each feature subset and place it on a cost-performance frontier.

    ``per_window_scores`` maps a subset key to the score of *each* window, because
    the bootstrap needs the paired per-window values, not just their mean. A
    subset whose vector is missing or misaligned is rejected rather than compared
    against a mean, since that would silently drop the pairing that makes the
    interval narrow.
    """
    if full_key not in per_window_scores:
        raise ValueError(f"per_window_scores must contain '{full_key}'")
    full_vector = np.asarray(per_window_scores[full_key], dtype=float)
    result = AblationResult(full_score=float(full_vector.mean()))
    result.full_features = tuple(subsets[full_key])

    for key in sorted(subsets, key=lambda k: len(subsets[k])):
        if key == full_key:
            continue
        vector = np.asarray(per_window_scores.get(key, []), dtype=float)
        if vector.shape != full_vector.shape:
            raise ValueError(
                f"subset '{key}' has {vector.size} window scores but the full set has "
                f"{full_vector.size}; the bootstrap needs them paired"
            )
        # Brier: lower is better, so the loss of dropping features is
        # subset - full, and positive means the subset is worse. The interval
        # is in that same direction, so its sign agrees with loss_from_full.
        low, high = bootstrap_difference(
            vector, full_vector, iterations=bootstrap_iterations, seed=seed, level=level
        )
        features = tuple(subsets[key])
        loss = float(vector.mean() - full_vector.mean())
        result.points.append(
            AblationPoint(
                features=features,
                score=float(vector.mean()),
                n_features=len(features),
                cost=cost_of(features),
                tiers=tuple(required_tiers(features)),
                mean_full=result.full_score,
                loss_from_full=loss,
                ci_low=low,
                ci_high=high,
                # "No detectable loss", not "no loss": the interval straddling
                # zero means the data cannot tell the two apart.
                indistinguishable=low <= 0.0 <= high,
            )
        )

    result.bootstrap_iterations = bootstrap_iterations
    best = [p for p in result.points if p.indistinguishable]
    if best:
        chosen = min(best, key=lambda p: (p.n_features, p.cost))
        result.recommendation = chosen.features
        result.recommendation_score = chosen.score
        result.recommendation_ci = (chosen.ci_low, chosen.ci_high)
        result.note = (
            f"{len(chosen.features)} of {len(result.full_features)} features are "
            f"statistically indistinguishable from the full set "
            f"(95% CI on the difference: {chosen.ci_low:+.4f} to {chosen.ci_high:+.4f}). "
            "That is 'no measurable loss', not 'equally good'."
        )
    else:
        result.note = (
            "no tested subset is indistinguishable from the full set at this "
            "confidence level, so no smaller profile is recommended; the curve "
            "still shows what each reduction costs"
        )
    return result


def rank_by_weight(names: Sequence[str], weights: Sequence[float], k: int) -> list[str]:
    """The ``k`` highest-magnitude weights, as a first cut at a small subset.

    Deliberately naive. Coefficient magnitude ignores collinearity, so this is a
    *candidate* generator and never the answer - the curve and the bootstrap are
    what decide.
    """
    if k > len(names):
        raise ValueError("cannot take more features than exist")
    magnitudes = np.abs(np.asarray(weights, dtype=float))
    order = np.argsort(-magnitudes)[:k]
    return [names[i] for i in order]


def pareto_frontier(points: Sequence[AblationPoint]) -> list[AblationPoint]:
    """The points worth considering: best score per unit cost, no dominated ones.

    A point is dominated when another is at least as accurate and no more
    expensive. Showing only the frontier is what makes the trade-off legible;
    the dominated points are still in :class:`AblationResult` for anyone who
    wants them.
    """
    ordered = sorted(points, key=lambda p: (p.cost, -p.score))
    frontier: list[AblationPoint] = []
    best_score = -math.inf
    for point in ordered:
        if point.score > best_score:
            frontier.append(point)
            best_score = point.score
    return frontier


def describe_profile(names: Sequence[str]) -> dict:
    """A deployable description of what a feature set actually requires."""
    return {
        "n_features": len(names),
        "cost_units": cost_of(names),
        "required_tiers": required_tiers(names),
        "tier_counts": audit_tier_coverage(names),
        "features": list(names),
    }


__all__ = [
    "TELEMETRY_BUDGET_VERSION",
    "TIERS",
    "AblationPoint",
    "AblationResult",
    "Tier",
    "ablation_curve",
    "audit_tier_coverage",
    "bootstrap_difference",
    "cost_of",
    "describe_profile",
    "pareto_frontier",
    "rank_by_weight",
    "required_tiers",
    "tier_for",
]
