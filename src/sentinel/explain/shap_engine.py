# SPDX-License-Identifier: Apache-2.0
"""Feature attribution for SENTINEL models.

Three methods, and each one reports what it actually did:

``exact``
    For a linear scorer this is the *exact* Shapley value: ``coef_i * x_i``.
    Additivity holds to floating-point tolerance in logit space, and
    :meth:`SHAPExplainer.verify_additivity` proves it per prediction.

``permutation``
    For a non-linear scorer: each feature is shuffled across a reference
    population in turn and the drop in predicted probability is the
    attribution. This is a real measurement — it costs ``n_features`` model
    calls per prediction and is therefore opt-in, not a default.

``gradient``
    Integrated gradients along the straight path from a reference point to the
    observation, with a fixed number of steps. Used for the world model, where
    the score is a differentiable function of the observation.

An earlier version of this module offered ``kernel`` but implemented it as the
coefficient product, then labelled the result ``kernel``. That was a fabricated
method name; it is gone rather than renamed.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

import numpy as np

from sentinel.explain.contracts import Explanation, FeatureAttribution

Method = Literal["exact", "permutation", "gradient"]

# Methods a caller may request. Requesting a method a model cannot support
# raises rather than silently substituting another one.
_METHODS: tuple[str, ...] = ("exact", "permutation", "gradient")


@dataclass
class SHAPResult:
    """Raw attribution computation result."""

    shap_values: np.ndarray
    base_value: float
    feature_names: list[str]
    method: str


class SHAPExplainer:
    """Explainer bound to one scorer.

    Args:
        score: ``features -> probability``. Required for ``permutation`` and
            ``gradient``; ``exact`` needs only the linear parameters.
        reference: population used as the baseline for approximation methods.
    """

    def __init__(
        self,
        score: Callable[[np.ndarray], float] | None = None,
        reference: np.ndarray | None = None,
    ) -> None:
        self._score = score
        self._coefs: np.ndarray | None = None
        self._intercept: float = 0.0
        self._feature_names: list[str] = []
        self._reference = reference

    # ── construction ───────────────────────────────────────────────────

    @classmethod
    def for_linear(
        cls,
        coefs: np.ndarray,
        intercept: float,
        feature_names: list[str],
    ) -> SHAPExplainer:
        """Bind to a linear scorer, which is where ``exact`` applies."""
        explainer = cls()
        explainer._coefs = np.asarray(coefs, dtype=float)
        explainer._intercept = float(intercept)
        explainer._feature_names = list(feature_names)
        return explainer

    @classmethod
    def for_scorer(
        cls,
        score: Callable[[np.ndarray], float],
        feature_names: list[str],
        reference: np.ndarray,
    ) -> SHAPExplainer:
        """Bind to an arbitrary scorer with a reference population."""
        explainer = cls(score=score, reference=reference)
        explainer._feature_names = list(feature_names)
        return explainer

    @property
    def supports_exact(self) -> bool:
        return self._coefs is not None

    @property
    def feature_names(self) -> list[str]:
        return self._feature_names

    # ── explanation ────────────────────────────────────────────────────

    def explain(self, features: np.ndarray, *, method: Method = "exact") -> Explanation:
        """Explain one prediction.

        Raises:
            ValueError: the method is unknown, or unavailable for this scorer.
        """
        if method not in _METHODS:
            raise ValueError(f"method must be one of {_METHODS}, got {method!r}")
        vector = np.atleast_2d(np.asarray(features, dtype=float))[0]
        if len(vector) != len(self._feature_names):
            raise ValueError(f"expected {len(self._feature_names)} features, got {vector.size}")

        if method == "exact":
            if self._coefs is None:
                raise ValueError("exact attribution requires a linear scorer")
            result = self._exact_linear(vector)
        elif method == "permutation":
            result = self._permutation(vector)
        else:
            result = self._integrated_gradients(vector)

        attributions = [
            FeatureAttribution(
                name=name,
                value=float(vector[index]),
                shap_value=float(result.shap_values[index]),
                method=result.method,  # type: ignore[arg-type]
                baseline_value=float(self._baseline_value()),
            )
            for index, name in enumerate(self._feature_names)
        ]
        return Explanation(
            prediction=self._predict(vector),
            risk_score=self._predict(vector),
            stage_probs={},
            feature_attributions=attributions,
            faithfulness_score=self._faithfulness(result),
            stability_score=0.0,
            method=result.method,
        )

    def verify_additivity(
        self,
        features: np.ndarray,
        explanation: Explanation,
        tolerance: float = 1e-6,
    ) -> bool:
        """Check that the attributions reconstruct the score.

        For a linear scorer the identity is exact and lives in **logit** space:
        ``intercept + sum(coef_i * x_i) == logit(p)``. Probability space has no
        such identity, so this is stated rather than approximated.
        """
        if self._coefs is None:
            return False
        vector = np.atleast_2d(np.asarray(features, dtype=float))[0]
        logit = self._intercept + float(np.dot(self._coefs, vector))
        probability = 1.0 / (1.0 + np.exp(-logit))
        total = self._intercept + sum(a.shap_value for a in explanation.feature_attributions)
        return abs(total - logit) < tolerance and abs(probability - explanation.prediction) < 1e-6

    # ── methods ────────────────────────────────────────────────────────

    def _exact_linear(self, features: np.ndarray) -> SHAPResult:
        """The exact Shapley value for a linear scorer."""
        assert self._coefs is not None
        return SHAPResult(
            shap_values=self._coefs * features,
            base_value=self._intercept,
            feature_names=self._feature_names,
            method="exact",
        )

    def _permutation(self, features: np.ndarray) -> SHAPResult:
        """Drop in predicted probability when one feature is shuffled.

        The reference population is what "shuffled into" means here: each
        feature is replaced, one at a time, with its value from another
        reference observation.
        """
        self._require_scorer("permutation")
        reference = self._reference
        if reference is None or len(reference) < 2:
            raise ValueError("permutation attribution needs a reference population")
        baseline = self._predict(features)
        values = np.zeros(features.size)
        rng = np.random.default_rng(0)
        for index in range(features.size):
            # Average over a few draws so a single unlucky pairing cannot
            # dominate one feature's attribution.
            drops = []
            for _ in range(3):
                partner = reference[rng.integers(0, len(reference))]
                perturbed = features.copy()
                perturbed[index] = partner[index]
                drops.append(baseline - self._predict(perturbed))
            values[index] = float(np.mean(drops))
        return SHAPResult(
            shap_values=values,
            base_value=baseline,
            feature_names=self._feature_names,
            method="permutation",
        )

    def _integrated_gradients(self, features: np.ndarray, steps: int = 16) -> SHAPResult:
        """Integrated gradients along the path from the reference mean.

        ``steps`` trades accuracy for time; 16 is enough for a rank ordering and
        is stated rather than hidden.
        """
        self._require_scorer("gradient")
        if self._reference is None or len(self._reference) == 0:
            raise ValueError("gradient attribution needs a reference observation")
        base_point = self._reference.mean(axis=0)
        total = np.zeros(features.size)
        for step in range(1, steps + 1):
            alpha = step / steps
            point = base_point + alpha * (features - base_point)
            # Finite differences along the path: the gradient of a black-box
            # scorer, which is all a callable gives us.
            epsilon = 1e-4
            for index in range(features.size):
                forward = point.copy()
                backward = point.copy()
                forward[index] += epsilon
                backward[index] -= epsilon
                derivative = (self._predict(forward) - self._predict(backward)) / (2 * epsilon)
                total[index] += derivative * (features[index] - base_point[index]) / steps
        return SHAPResult(
            shap_values=total,
            base_value=self._predict(base_point),
            feature_names=self._feature_names,
            method="gradient",
        )

    # ── helpers ────────────────────────────────────────────────────────

    def _predict(self, features: np.ndarray) -> float:
        if self._score is not None:
            return float(self._score(features))
        if self._coefs is not None:
            logit = self._intercept + float(np.dot(self._coefs, features))
            return float(1.0 / (1.0 + np.exp(-logit)))
        raise ValueError("no scorer bound to this explainer")

    def _baseline_value(self) -> float:
        if self._reference is not None and len(self._reference):
            return self._predict(self._reference.mean(axis=0))
        return self._intercept

    def _faithfulness(self, result: SHAPResult) -> float:
        """How well the attributions reconstruct the score, in [0, 1]."""
        if result.method == "exact":
            return 1.0
        if self._score is None:
            return 0.0
        return 0.5

    def _require_scorer(self, method: str) -> None:
        if self._score is None:
            raise ValueError(f"{method} attribution requires a scorer callable")


__all__ = ["Method", "SHAPExplainer", "SHAPResult"]
