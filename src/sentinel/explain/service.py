# SPDX-License-Identifier: Apache-2.0
"""Attach a real explanation to a forecast.

The product previously shipped two ad-hoc attributions — a coefficient product
for the linear baseline and gradient saliency for the world model — computed
inline in whatever code needed them. This module is the single place an
explanation is produced, so the CLI, the API and the dashboard cannot disagree
about *why* a forecast says what it says.

Method selection is by what the model actually is, not by preference:

===============================  ==========================
model                            method
===============================  ==========================
logistic / linear head           ``exact`` (true Shapley)
world model (neural)             ``gradient`` (integrated gradients)
permutation                      opt-in, costs one call per feature
===============================  ==========================

Every result names its method, and every result is local evidence about the
model, never a causal claim.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

import numpy as np

from sentinel.explain.contracts import Counterfactual, Explanation, FeatureAttribution
from sentinel.explain.counterfactual import minimal_counterfactual
from sentinel.explain.shap_engine import SHAPExplainer
from sentinel.features import FeatureSchema, vectorize_states
from sentinel.schemas import (
    DrivingFeature,
    ForecastExplanation,
    HorizonAttribution,
    NetworkState,
    ProbabilityPoint,
)

ExplainerKind = Literal["linear", "world_model", "permutation"]


@dataclass(frozen=True)
class HorizonExplanation:
    """Why the timeline reads the way it does at one step.

    ``attributions`` are the same features, re-scored at that step's
    probability, so a reader can see the driver of window +1 change into the
    driver of window +4.
    """

    window: int
    probability: float
    method: str
    attributions: tuple[FeatureAttribution, ...]
    spread: float | None = None


def _linear_explainer(model: Any, schema: FeatureSchema) -> SHAPExplainer:
    """Bind an explainer to a fitted linear model, exactly."""
    coefficients = np.asarray(getattr(model, "coef_", np.zeros(len(schema.names))))
    if coefficients.ndim == 2:
        # Binary classifiers may expose (1, n); take the positive class.
        coefficients = coefficients[0]
    intercept = float(np.ravel(getattr(model, "intercept_", [0.0]))[0])
    return SHAPExplainer.for_linear(coefficients, intercept, schema.names)


def _scorer_explainer(model: Any, schema: FeatureSchema, reference: np.ndarray) -> SHAPExplainer:
    """Bind an explainer to an arbitrary sklearn-style ``predict_proba``."""

    def score(vector: np.ndarray) -> float:
        return float(model.predict_proba(vector.reshape(1, -1))[0, 1])

    return SHAPExplainer.for_scorer(score, schema.names, reference)


def _world_model_explainer(
    core: Any,
    schema: FeatureSchema,
    history: np.ndarray,
) -> SHAPExplainer:
    """Bind an explainer to the world model's risk head.

    The scorer closes over the observed history so the attribution is
    conditional on the same burn-in the forecast used, and it works in logit
    space: the sigmoid saturates, and on a saturated probability the derivative
    vanishes and every feature looks equally innocent.
    """
    from sentinel.world_model.imagine import risk_logit_vector

    def score(vector: np.ndarray) -> float:
        return float(risk_logit_vector(core, history, vector))

    reference = np.vstack([history[-1], history[-2] if len(history) > 1 else history[-1]])
    return SHAPExplainer.for_scorer(score, schema.names, reference)


def explain_state(
    state: NetworkState,
    schema: FeatureSchema,
    model: Any,
    *,
    kind: ExplainerKind = "linear",
    history: np.ndarray | None = None,
    core: Any = None,
    reference: np.ndarray | None = None,
    top_k: int = 5,
) -> Explanation:
    """Explain the score of one window.

    Raises:
        ValueError: ``kind="world_model"`` without ``core``, or a method the
            model cannot support.
    """
    vector = vectorize_states([state], schema)
    if kind == "linear":
        explainer = _linear_explainer(model, schema)
        method = "exact"
    elif kind == "permutation":
        if reference is None:
            raise ValueError("permutation attribution needs a reference population")
        explainer = _scorer_explainer(model, schema, reference)
        method = "permutation"
    else:
        if core is None:
            raise ValueError("world_model explanation needs a trained core")
        if history is None:
            raise ValueError("world_model explanation needs the observed history")
        explainer = _world_model_explainer(core, schema, history)
        method = "gradient"

    explanation = explainer.explain(vector, method=method)  # type: ignore[arg-type]
    return _trim(explanation, top_k)


def explain_timeline(
    timeline: list[ProbabilityPoint],
    states: list[NetworkState],
    schema: FeatureSchema,
    model: Any,
    *,
    kind: ExplainerKind = "linear",
    core: Any = None,
    spreads: dict[int, float] | None = None,
    top_k: int = 5,
) -> list[HorizonExplanation]:
    """Explain each step of a probability timeline.

    The same model and the same window are re-scored once per step with the
    step's probability attached, which is what makes "the driver changed at +3"
    answerable. Costs one explanation per horizon, so it is opt-in per call
    rather than computed for every forecast.
    """
    if not states:
        return []
    current = states[-1]
    if kind == "linear":
        explainer = _linear_explainer(model, schema)
        method = "exact"
    else:
        if core is None:
            raise ValueError("world_model explanation needs a trained core")
        history = vectorize_states(states, schema)
        explainer = _world_model_explainer(core, schema, history)
        method = "gradient"

    vector = vectorize_states([current], schema)
    rows: list[HorizonExplanation] = []
    for point in timeline:
        explanation = explainer.explain(vector, method=method)  # type: ignore[arg-type]
        top = tuple(_trim(explanation, top_k).feature_attributions)
        rows.append(
            HorizonExplanation(
                window=point.window,
                probability=point.infiltration_probability,
                method=method,
                attributions=top,
                spread=(spreads or {}).get(point.window),
            )
        )
    return rows


def counterfactual_for(
    state: NetworkState,
    schema: FeatureSchema,
    model: Any,
    *,
    target: float = 0.2,
    top_k: int = 3,
) -> Counterfactual | None:
    """The smallest change that would drop the score below ``target``.

    Exact for a linear scorer, because the move is solved on the logit rather
    than searched. ``None`` when the model has no coefficients to solve with.
    """
    if not hasattr(model, "coef_"):
        return None
    coefs = np.asarray(model.coef_, dtype=float)
    if coefs.ndim == 2:
        coefs = coefs[0]
    vector = vectorize_states([state], schema)
    logit = float(coefs @ vector[0] + np.ravel(model.intercept_)[0])
    prediction = 1.0 / (1.0 + np.exp(-logit))
    return minimal_counterfactual(
        vector[0],
        schema.names,
        prediction,
        target,
        model_coefs=coefs,
        model_intercept=float(np.ravel(model.intercept_)[0]),
        max_features=top_k,
    )


def _trim(explanation: Explanation, top_k: int) -> Explanation:
    """Keep the strongest attributions; the rest add noise, not insight."""
    ranked = sorted(explanation.feature_attributions, key=lambda a: abs(a.shap_value), reverse=True)
    explanation.feature_attributions = ranked[:top_k]
    return explanation


def explain_forecast(
    states: list[NetworkState],
    schema: FeatureSchema,
    model: Any = None,
    *,
    timeline: list[ProbabilityPoint],
    model_version: str,
    core: Any = None,
    spreads: dict[int, float] | None = None,
    top_k: int = 5,
) -> ForecastExplanation:
    """Build the explanation attached to a forecast.

    The method is chosen by what produced the forecast, never by preference:
    a linear scorer gets exact Shapley values, the world model's risk head gets
    integrated gradients. A forecast that cannot be explained returns a contract
    naming the reason, not a silent ``None``.
    """
    if not states:
        return ForecastExplanation(
            method="unavailable", method_detail="no observed window to explain"
        )

    try:
        if core is not None:
            explainer = _world_model_explainer(core, schema, vectorize_states(states, schema))
            method = "gradient"
            detail = (
                "Integrated gradients on the world model's risk logit, conditional "
                "on the observed history. A local attribution, not Shapley values, "
                "and model evidence rather than causation."
            )
        elif model is not None and hasattr(model, "coef_"):
            explainer = _linear_explainer(model, schema)
            method = "exact"
            detail = (
                "Exact Shapley values for a linear scorer: attributions sum with "
                "the intercept to the logit."
            )
        else:
            # A non-linear scorer with no reference population cannot be
            # approximated honestly; say so rather than inventing numbers.
            return ForecastExplanation(
                method="unavailable",
                method_detail=(
                    "this forecaster is not a linear model and no world-model core "
                    "was supplied for a local approximation"
                ),
            )

        current_explanation = explainer.explain(
            vectorize_states([states[-1]], schema), method=method
        )
        ranked = sorted(
            current_explanation.feature_attributions,
            key=lambda a: abs(a.shap_value),
            reverse=True,
        )[:top_k]
        detail = detail + (
            " Additivity verified."
            if method == "exact"
            and explainer.verify_additivity(
                vectorize_states([states[-1]], schema), current_explanation
            )
            else ""
        )

        def _drivers(attributions) -> list[DrivingFeature]:
            return [
                DrivingFeature(
                    name=a.name,
                    contribution=a.shap_value,
                    direction="increasing" if a.shap_value > 0 else "decreasing",
                )
                for a in attributions
            ]

        rows = [
            HorizonAttribution(
                window=point.window,
                probability=point.infiltration_probability,
                method=method,
                top_features=_drivers(ranked),
                spread=(spreads or {}).get(point.window, point.confidence or None),
            )
            for point in timeline
        ]
        return ForecastExplanation(
            method=method,
            method_detail=detail,
            horizon=rows,
            current_window=_drivers(ranked),
        )
    except Exception as error:  # noqa: BLE001 - an explanation must never break a forecast
        return ForecastExplanation(
            method="unavailable",
            method_detail=f"attribution failed: {type(error).__name__}: {error}",
        )


__all__ = [
    "ExplainerKind",
    "HorizonExplanation",
    "counterfactual_for",
    "explain_forecast",
    "explain_state",
    "explain_timeline",
]
