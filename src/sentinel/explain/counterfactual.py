# SPDX-License-Identifier: Apache-2.0
"""Counterfactual explanations for feature-level insights."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from sentinel.explain.contracts import Counterfactual, FeatureAttribution


@dataclass
class CounterfactualResult:
    """Result of counterfactual computation."""

    original: float
    target: float
    modified_features: list[tuple[int, float, float]]  # (idx, old_val, new_val)
    predicted_impact: float
    feasible: bool


def minimal_counterfactual(
    features: np.ndarray,
    feature_names: list[str],
    prediction: float,
    target_probability: float,
    model_coefs: np.ndarray | None = None,
    model_intercept: float = 0.0,
    max_features: int = 3,
    feature_ranges: dict[str, tuple[float, float]] | None = None,
) -> Counterfactual:
    """Find minimal feature change to reach target probability.

    For logistic regression, this is exact: we find the smallest perturbation
    to the top-k features (by SHAP value) that brings the prediction below
    the target.

    Args:
        features: (n_features,) input features.
        feature_names: List of feature names.
        prediction: Current model prediction.
        target_probability: Desired probability after change.
        model_coefs: Model coefficients (for exact linear).
        model_intercept: Model intercept.
        max_features: Maximum number of features to modify.
        feature_ranges: Optional {name: (min, max)} constraints.

    Returns:
        Counterfactual with modified features and predicted impact.
    """
    if prediction <= target_probability:
        return Counterfactual(
            original=prediction,
            target=target_probability,
            features=[],
            predicted_impact=prediction,
        )

    # For logistic regression with exact linear
    if model_coefs is not None:
        return _counterfactual_logistic(
            features,
            feature_names,
            prediction,
            target_probability,
            model_coefs,
            model_intercept,
            max_features,
            feature_ranges,
        )

    # Fallback: greedy feature reduction
    return _counterfactual_greedy(
        features,
        feature_names,
        prediction,
        target_probability,
        max_features,
    )


def _counterfactual_logistic(
    features: np.ndarray,
    feature_names: list[str],
    prediction: float,
    target: float,
    coefs: np.ndarray,
    intercept: float,
    max_features: int,
    feature_ranges: dict[str, tuple[float, float]] | None,
) -> Counterfactual:
    """Exact counterfactual for logistic regression."""
    # Current logit
    current_logit = np.dot(coefs, features) + intercept
    target_logit = np.log(target / (1 - target + 1e-10))

    # Need to reduce logit by this much
    logit_gap = current_logit - target_logit

    # Sort features by absolute coefficient (most impactful first)
    feature_importance = np.abs(coefs) * np.abs(features)
    top_indices = np.argsort(feature_importance)[::-1][:max_features]

    modified = []
    remaining_gap = logit_gap

    for idx in top_indices:
        if remaining_gap <= 0:
            break

        coef = coefs[idx]
        val = features[idx]

        # How much can we reduce this feature?
        if feature_ranges and feature_names[idx] in feature_ranges:
            min_val = feature_ranges[feature_names[idx]][0]
        else:
            min_val = 0.0  # Assume features are non-negative

        # Reduction possible
        reduction = val - min_val
        logit_reduction = coef * reduction

        if logit_reduction <= 0:
            # This feature can't help reduce the logit
            continue

        # Use minimum needed
        actual_reduction = min(reduction, remaining_gap / coef if coef > 0 else reduction)
        new_val = val - actual_reduction
        remaining_gap -= coef * actual_reduction

        modified.append((idx, val, new_val))

    # Compute predicted impact
    new_logit = current_logit - (logit_gap - remaining_gap)
    new_pred = 1.0 / (1.0 + np.exp(-new_logit))

    # Build feature attributions
    fa_list = []
    for idx, old_val, new_val in modified:
        fa_list.append(
            FeatureAttribution(
                name=feature_names[idx],
                value=old_val,
                shap_value=float(coefs[idx] * old_val),
                method="exact",
                baseline_value=new_val,
            )
        )

    return Counterfactual(
        original=prediction,
        target=target,
        features=fa_list,
        predicted_impact=float(new_pred),
    )


def _counterfactual_greedy(
    features: np.ndarray,
    feature_names: list[str],
    prediction: float,
    target: float,
    max_features: int,
) -> Counterfactual:
    """Greedy counterfactual fallback."""
    # Sort by feature value (highest first)
    top_indices = np.argsort(features)[::-1][:max_features]

    modified = []
    current_pred = prediction

    for idx in top_indices:
        if current_pred <= target:
            break

        val = features[idx]
        # Try reducing to 0
        new_val = 0.0
        reduction_ratio = 1.0 - (new_val / val) if val > 0 else 0.0

        # Estimate impact (simplified)
        impact = reduction_ratio * 0.1  # Rough estimate
        new_pred = max(0.0, current_pred - impact)

        modified.append((idx, val, new_val))
        current_pred = new_pred

    fa_list = []
    for idx, old_val, new_val in modified:
        fa_list.append(
            FeatureAttribution(
                name=feature_names[idx],
                value=old_val,
                shap_value=float(old_val / len(features)),
                method="kernel",
                baseline_value=new_val,
            )
        )

    return Counterfactual(
        original=prediction,
        target=target,
        features=fa_list,
        predicted_impact=current_pred,
    )
