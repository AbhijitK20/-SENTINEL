# SPDX-License-Identifier: Apache-2.0
"""Recursive K-step rollout: a next-state transition model with forecast heads.

This module closes the documented gap between multi-horizon nowcasting and
genuine forward simulation. Instead of asking each horizon ``will there be an
infiltration K windows ahead?``, it learns

    S(t+1) = f(S(t), S(t-1), ..., S(t-m+1))

on training scenarios and then *rolls the model forward*: the predicted next
state becomes the input to the next prediction step. Infiltration probability
at every rolled window comes from the fitted baseline classifier applied to
the simulated state, so the timeline is a by-product of state simulation.

Honesty rules preserved:

- The transition model is fitted on training-scenario windows only.
- The forecast's ``model_version`` is ``forecast-inference-v1+transition-rollout``
  so rollout output is never confused with observed-evidence forecasts.
- Recursive error accumulation is real: ``RolloutDiagnostics`` reports per-step
  drift so it is visible instead of hidden.
- The private API of ``sentinel.predict`` is not used; this module imports
  only public helpers.

Design note: the transition function is a linear ridge map from concatenated
history windows to the next window's features. It is deterministic (no PyTorch
required), cheap to fit, easy to audit, and is kept as the **linear baseline**
the learned world model is measured against — including the parts where it loses.

Two properties of that fit are recorded on the model rather than hidden:

- Inputs are standardized before the ridge penalty, because raw flow counters
  span three orders of magnitude and would otherwise let one column own the fit.
- The fitted map is projected to a non-expansive spectral norm, and
  ``stability_clip`` records how much had to be scaled away.

``transition-rollout-v3`` replaced the one-step fit with a genuine multi-step
one. v2 fitted the one-step least-squares optimum and stabilised it afterwards,
on the stated grounds that a K-step objective "is not a linear least-squares
problem". That reasoning was wrong in the way that mattered: unrolling is
polynomial in the weights, but for a *linear* map the K-step prediction is a
fixed linear function of the concatenated history, so the joint objective is
smooth and differentiable in the parameters. v3 minimises it directly, by Adam on
the exact gradient, and records ``multistep_objective`` alongside the
``one_step_objective`` of the fit it started from - so the improvement is a
stored measurement rather than a claim. Because those fields are load-bearing,
a v2 artifact fails to load rather than being silently mis-applied.
"""

from __future__ import annotations

from datetime import timedelta

import numpy as np
from pydantic import BaseModel, ConfigDict, Field, model_validator

from sentinel.features import FeatureSchema, vectorize_states
from sentinel.predict import (
    DECISION_THRESHOLD,
    FORECAST_VERSION,
    forecast_warnings,
    lead_time_from_timeline,
    predicted_stage_from_timeline,
)
from sentinel.schemas import Forecast, NetworkState, ProbabilityPoint
from sentinel.world_model.imagine import OpenLoopError

ROLLOUT_MODEL_VERSION = "transition-rollout-v3"


class RolloutTransitionModel(BaseModel):
    """Serializable linear next-state transition model.

    Inputs are standardized before the ridge fit and mapped back on prediction:
    raw flow counters span three orders of magnitude (``bytes_sum`` in the
    thousands next to a 0/1 flag share), so an unstandardized fit lets one
    column own the penalty and the recursion diverges. ``input_means`` and
    ``input_scales`` are the training statistics that make the fit comparable
    across features.
    """

    model_config = ConfigDict(extra="forbid")

    # Required, not defaulted: a v2 artifact carries no multi-step fields, and
    # silently filling in the new version would ship it as a v3 map. Load-bearing
    # strings fail loudly instead.
    model_version: str
    history_length: int = Field(ge=1)
    feature_names: list[str] = Field(min_length=1)
    coefficients: list[list[float]]  # [history_length * width, width]
    intercept: list[float]
    residual_scale: list[float]  # per-feature training residual std
    input_means: list[float]
    input_scales: list[float]
    training_windows: int = Field(ge=1)
    spectral_norm: float = Field(ge=0.0)
    stability_clip: float = Field(default=1.0, gt=0.0)
    # The multi-step fit is scored against the one-step optimum it replaced,
    # both measured after the stability projection, so "this is better than the
    # obvious fit" is a stored measurement about the maps that actually ship.
    fit_steps: int = Field(default=1, ge=1)
    multistep_objective: float = Field(default=0.0, ge=0.0)
    one_step_objective: float = Field(default=0.0, ge=0.0)
    # Spectral norm *before* the projection. `spectral_norm` is always the limit
    # after projection, so it says nothing; these two are what reveal how
    # expansive the least-squares fit wanted to be, and therefore how much of it
    # the projection had to throw away.
    fitted_spectral_norm: float = Field(default=0.0, ge=0.0)
    one_step_fitted_spectral_norm: float = Field(default=0.0, ge=0.0)

    @model_validator(mode="after")
    def _check_version(self) -> RolloutTransitionModel:
        if self.model_version != ROLLOUT_MODEL_VERSION:
            raise ValueError(
                f"transition model version {self.model_version!r} cannot be loaded by "
                f"{ROLLOUT_MODEL_VERSION!r}: the multi-step fit fields are absent, so "
                "the artifact would be silently mis-applied. Refit it."
            )
        return self


class RolloutDiagnostics(BaseModel):
    """Per-step simulation drift from a rollout run."""

    model_config = ConfigDict(extra="forbid")

    steps: list[int] = Field(min_length=1)
    step_delta: list[float]  # mean |simulated next - current last window| per step
    simulated_windows: int = Field(ge=1)


def fit_transition_model(
    labelled_states: list,
    *,
    history_length: int,
    scenario_ids: list[str] | None = None,
    ridge: float = 1.0,
    stability_limit: float = 0.98,
    fit_steps: int = 3,
    feature_names: list[str] | None = None,
) -> RolloutTransitionModel:
    """Fit the linear next-state map on labelled states from given scenarios.

    Callers pass training scenarios via ``scenario_ids`` to keep the fit
    leakage-safe. Each sample maps a contiguous history of ``history_length``
    windows to the next window's state features.

    ``feature_names`` pins the feature space. It should be the fitted
    ``FeatureSchema.names``, which is the same space every other model in the
    pipeline uses. **It became necessary on 2026-09-29**: ``state_builder`` now
    omits a window feature whose telemetry the window does not carry (an absent
    ``frag_df_share`` means "no packet evidence", not "measured zero"), so two
    windows from the same scenario can legitimately have different key sets and
    the old all-states-must-agree check rejected them with
    ``inconsistent feature sets across states``. Reading through a pinned name
    list with ``.get(name, 0.0)`` is exactly what ``vectorize_states`` does, so
    the transition model is no longer in a different feature space from the
    models it is compared against.

    Without ``feature_names`` the strict check is kept, because a genuine
    mismatch there means the caller has no authoritative feature order and
    silently filling would misalign the fit.
    """
    if history_length < 1:
        raise ValueError("history_length must be positive")
    if not labelled_states:
        raise ValueError("at least one labelled state is required")
    if scenario_ids is None:
        allowed = {item.scenario_id for item in labelled_states}
    else:
        allowed = set(scenario_ids)
        missing = allowed - {item.scenario_id for item in labelled_states}
        if missing:
            raise ValueError(f"scenario ids not present in labelled states: {sorted(missing)}")

    by_scenario: dict[str, list] = {}
    for item in labelled_states:
        if item.scenario_id in allowed:
            by_scenario.setdefault(item.scenario_id, []).append(item)

    if feature_names is None:
        resolved: list[str] | None = None
        for scenario_id in sorted(by_scenario):
            states = sorted(by_scenario[scenario_id], key=lambda item: item.state.window_start)
            for history in states:
                current = sorted(history.state.features)
                if resolved is None:
                    resolved = current
                elif current != resolved:
                    raise ValueError(
                        "inconsistent feature sets across states; pass the fitted "
                        "schema's feature_names"
                    )
        if resolved is None:
            raise ValueError("not enough contiguous history to fit the transition model")
        names = resolved
    else:
        names = list(feature_names)

    if fit_steps < 1:
        raise ValueError("fit_steps must be positive")

    # Multi-step targets: each sample needs `fit_steps` real future windows, so
    # only the interior of each scenario contributes. Still training data only.
    step_targets: list[list[np.ndarray]] = [[] for _ in range(fit_steps)]
    kept_rows: list[np.ndarray] = []
    for scenario_id in sorted(by_scenario):
        states = sorted(by_scenario[scenario_id], key=lambda item: item.state.window_start)
        for index in range(history_length - 1, len(states) - fit_steps):
            history = states[index - history_length + 1 : index + 1]
            kept_rows.append(
                np.concatenate(
                    [
                        np.fromiter(
                            (s.state.features.get(n, 0.0) for n in names),
                            dtype=float,
                            count=len(names),
                        )
                        for s in history
                    ]
                )
            )
            for step in range(fit_steps):
                step_targets[step].append(
                    np.fromiter(
                        (states[index + 1 + step].state.features.get(n, 0.0) for n in names),
                        dtype=float,
                    )
                )
    if not kept_rows:
        raise ValueError(
            f"not enough contiguous history to fit a {fit_steps}-step transition model"
        )
    Xm = np.stack(kept_rows)
    Ym = [np.stack(rows) for rows in step_targets]

    x_mean = Xm.mean(axis=0)
    x_scale = Xm.std(axis=0)
    x_scale[x_scale == 0.0] = 1.0
    Xs = (Xm - x_mean) / x_scale
    y_mean = np.mean([y.mean(axis=0) for y in Ym], axis=0)
    Ys = [(y - y_mean) for y in Ym]

    # Two candidates, both fitted in the standardized space:
    #   one  - the v2 fit: the one-step ridge optimum
    #   multi- the v3 fit: the K-step objective minimised directly
    one_weights = _ridge(Xs, Ys[0], ridge).T.astype(float)
    one_bias = np.zeros(len(names), dtype=float)
    multi_weights, multi_bias = _multistep_ridge(Xs, Ys, ridge, fit_steps)

    # Stability projection, applied to both so the comparison is like-for-like.
    # Minimising error at +1..+K does not make a map safe to recurse: the
    # objective is only evaluated up to K, and the fitted map can still be
    # expansive past that. `stability_clip` records what the projection cost.
    one_weights, one_bias, one_fitted, one_clip = _project(one_weights, one_bias, stability_limit)
    multi_weights, multi_bias, multi_fitted, clip = _project(
        multi_weights, multi_bias, stability_limit
    )

    # Costs are measured *after* projection, on the maps that actually ship.
    one_step_cost = _multistep_cost(Xs, Ys, fit_steps, one_weights, one_bias)
    final_cost = _multistep_cost(Xs, Ys, fit_steps, multi_weights, multi_bias)

    coefficients = multi_weights.T  # (d, width)
    intercept = y_mean - (x_mean / x_scale) @ coefficients + multi_bias

    residuals = Ym[0] - (Xm @ coefficients + intercept)
    residual_scale = residuals.std(axis=0)
    residual_scale[residual_scale == 0.0] = 1.0

    return RolloutTransitionModel(
        model_version=ROLLOUT_MODEL_VERSION,
        history_length=history_length,
        feature_names=names,
        coefficients=coefficients.tolist(),
        intercept=intercept.tolist(),
        residual_scale=residual_scale.tolist(),
        input_means=x_mean.tolist(),
        input_scales=x_scale.tolist(),
        training_windows=len(kept_rows),
        spectral_norm=float(np.linalg.norm(multi_weights, 2)),
        stability_clip=clip,
        fit_steps=fit_steps,
        multistep_objective=final_cost,
        one_step_objective=one_step_cost,
        fitted_spectral_norm=multi_fitted,
        one_step_fitted_spectral_norm=one_fitted,
    )


def _project(
    weights: np.ndarray, bias: np.ndarray, stability_limit: float
) -> tuple[np.ndarray, np.ndarray, float, float]:
    """Scale a map to a non-expansive spectral norm.

    Returns the projected weights, bias, the *pre*-projection norm, and the
    clip factor. The pre-projection norm is the informative number: it is how
    expansive the fit wanted to be, and ``limit / pre_norm`` is how much of the
    fit the projection had to discard.
    """
    fitted = float(np.linalg.norm(weights, 2))
    if stability_limit > 0 and fitted > stability_limit:
        clip = stability_limit / fitted
        return weights * clip, bias * clip, fitted, clip
    return weights, bias, fitted, 1.0


def _multistep_cost(
    history: np.ndarray,
    targets: list[np.ndarray],
    steps: int,
    weights: np.ndarray,
    bias: np.ndarray,
) -> float:
    """Sum of squared error at steps 1..K for a candidate map."""
    width = targets[0].shape[1]
    current = history
    total = 0.0
    for step in range(steps):
        state = current @ weights.T + bias
        total += float(np.sum((state - targets[step]) ** 2))
        current = np.concatenate([current[:, width:], state], axis=1)
    return total


def _multistep_ridge(
    history: np.ndarray,
    targets: list[np.ndarray],
    ridge: float,
    steps: int,
    iterations: int = 400,
) -> tuple[np.ndarray, np.ndarray, float, float]:
    """Fit the transition map to minimise error at steps 1..K jointly.

    The previous version of this module claimed a multi-step objective was not a
    linear least-squares problem, because unrolling a map is polynomial in the
    weights. That is true of the weights and irrelevant to the solve: for a
    *linear* map, ``S(t+k) = A^k S(t) + (I + A + ... + A^{k-1})b`` is a fixed
    linear function of the concatenated history, so the joint objective is smooth
    and differentiable in ``(A, b)``. It is therefore minimised directly, by
    Adam on the exact gradient, instead of approximating it with the one-step
    optimum and stabilising afterwards.

    Returns ``(coefficients, intercept)`` in the standardized space.
    """
    n, d = history.shape
    width = targets[0].shape[1]
    weight = 1.0 / (n * width * steps)

    def unroll(weights: np.ndarray, bias: np.ndarray) -> tuple[list[np.ndarray], list[np.ndarray]]:
        """Simulate K steps, returning the per-step inputs and predictions.

        The flattened history is ``history_length`` windows wide. After one step
        the prediction is a *single* window, so the next step's history is the
        old history with its oldest window dropped and the predicted window
        appended - not another shift of a single window.
        """
        sources: list[np.ndarray] = []
        simulated: list[np.ndarray] = []
        current_history = history
        for _ in range(steps):
            sources.append(current_history)
            state = current_history @ weights.T + bias
            simulated.append(state)
            current_history = np.concatenate([current_history[:, width:], state], axis=1)
        return sources, simulated

    # Start from the one-step optimum: a sane point, and the map the caller
    # fits separately as the like-for-like comparison.
    a = _ridge(history, targets[0], ridge).T.astype(float)  # (width, d)
    b = np.zeros(width, dtype=float)

    m_a, v_a = np.zeros_like(a), np.zeros_like(a)
    m_b, v_b = np.zeros_like(b), np.zeros_like(b)
    beta1, beta2, eps = 0.9, 0.999, 1e-8
    for iteration in range(1, iterations + 1):
        sources, simulated = unroll(a, b)
        grad_a = np.zeros_like(a)
        grad_b = np.zeros_like(b)
        grad_history_next = np.zeros((n, d))
        for index in range(steps - 1, -1, -1):
            grad_state = 2.0 * (simulated[index] - targets[index])
            if index + 1 < steps:
                # The next step's history is [old[..., width:], this state].
                grad_state = grad_state + grad_history_next[:, -width:]
            grad_history = grad_state @ a
            if index + 1 < steps:
                # H[k+1] = concat(H[k][:, width:], state): the surviving columns
                # of H[k] land in H[k+1]'s leading columns.
                grad_history[:, width:] += grad_history_next[:, : d - width]
            grad_a += grad_state.T @ sources[index]
            grad_b += grad_state.sum(axis=0)
            grad_history_next = grad_history
        grad_a = grad_a * weight + 2.0 * ridge * a
        grad_b = grad_b * weight
        m_a = beta1 * m_a + (1 - beta1) * grad_a
        v_a = beta2 * v_a + (1 - beta2) * grad_a * grad_a
        m_b = beta1 * m_b + (1 - beta1) * grad_b
        v_b = beta2 * v_b + (1 - beta2) * grad_b * grad_b
        step_size = 0.01 / (1.0 + 0.005 * iteration)
        correction1 = 1 - beta1**iteration
        correction2 = 1 - beta2**iteration
        a = a - step_size * (m_a / correction1) / (np.sqrt(v_a / correction2) + eps)
        b = b - step_size * (m_b / correction1) / (np.sqrt(v_b / correction2) + eps)

    return a, b


def _ridge(design: np.ndarray, targets: np.ndarray, ridge: float) -> np.ndarray:
    return np.linalg.solve(design.T @ design + ridge * np.eye(design.shape[1]), design.T @ targets)


def apply_transition(transition_model: RolloutTransitionModel, history: np.ndarray) -> np.ndarray:
    """Predict the next window's raw features from a raw history matrix.

    The model is linear in its standardized inputs; the standardization is
    applied here so callers only deal in raw feature values.
    """
    means = np.asarray(transition_model.input_means)
    scales = np.asarray(transition_model.input_scales)
    standardized = (history.reshape(-1) - means) / scales
    return standardized @ np.asarray(transition_model.coefficients) + np.asarray(
        transition_model.intercept
    )


def save_transition_model(model: RolloutTransitionModel, output_path: str) -> str:
    """Persist the transition model as JSON and return the path."""
    from pathlib import Path

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(model.model_dump_json(indent=2), encoding="utf-8")
    return str(out)


def load_transition_model(path: str) -> RolloutTransitionModel:
    """Load a transition model previously written by save_transition_model."""
    from pathlib import Path

    return RolloutTransitionModel.model_validate_json(Path(path).read_text(encoding="utf-8"))


def rollout_forecast(
    states: list[NetworkState] | tuple[NetworkState, ...],
    transition_model: RolloutTransitionModel,
    baseline_model: object,
    schema: FeatureSchema,
    *,
    max_horizon: int,
    threshold: float = DECISION_THRESHOLD,
) -> tuple[Forecast, RolloutDiagnostics]:
    """Roll the transition model forward K steps and score simulated states.

    Returns ``(Forecast, RolloutDiagnostics)``. The probability at each step is
    the baseline classifier applied to the simulated state, standardized with
    the training schema. Timeline warnings note the recursive-rollout mode.
    """
    if max_horizon < 1:
        raise ValueError("max_horizon must be positive")
    ordered = sorted(states, key=lambda state: state.window_start)
    if len(ordered) < transition_model.history_length:
        raise ValueError(
            f"rollout needs at least {transition_model.history_length} history windows"
        )

    names = transition_model.feature_names

    def _raw(window_states: list[NetworkState]) -> np.ndarray:
        return np.stack(
            [
                np.fromiter((s.features.get(n, 0.0) for n in names), dtype=float, count=len(names))
                for s in window_states
            ]
        )

    history = _raw(list(ordered[-transition_model.history_length :]))

    timeline: list[ProbabilityPoint] = []
    step_delta: list[float] = []
    steps: list[int] = []
    current = history.copy()
    anchor_end = ordered[-1].window_end

    for step in range(1, max_horizon + 1):
        next_raw = apply_transition(transition_model, current)
        step_delta.append(float(np.mean(np.abs(next_raw - current[-1]))))
        steps.append(step)

        simulated_state = NetworkState(
            window_start=anchor_end + (step - 1) * timedelta(seconds=1),
            window_end=anchor_end + step * timedelta(seconds=1),
            features={name: float(value) for name, value in zip(names, next_raw, strict=False)},
            entities=[],
            coverage={},
            source_ids=[],
        )

        standardized = vectorize_states([simulated_state], schema)
        proba = float(baseline_model.predict_proba(standardized)[:, 1][0])
        timeline.append(
            ProbabilityPoint(
                window=step,
                infiltration_probability=float(np.clip(proba, 0.0, 1.0)),
                confidence=0.0,
            )
        )
        current = np.vstack([current[1:], next_raw.reshape(1, -1)])

    forecast = Forecast(
        input_window_start=ordered[0].window_start,
        input_window_end=ordered[-1].window_end,
        horizon_windows=len(timeline),
        model_version=f"{FORECAST_VERSION}+transition-rollout",
        probability_timeline=timeline,
        predicted_stage=predicted_stage_from_timeline(
            timeline, timeline[0].infiltration_probability
        ),
        affected_entities=sorted({entity for state in ordered for entity in state.entities})[:10],
        driving_features=[],
        supporting_events=[event_id for state in ordered[-3:] for event_id in state.source_ids][
            :10
        ],
        coverage={
            "flow": any(state.coverage.get("flow", False) for state in ordered),
            "packet": any(state.coverage.get("packet", False) for state in ordered),
        },
        warnings=[
            "Timeline produced by recursive state rollout (transition-rollout); "
            "probabilities are classifier scores on simulated states, not observed windows.",
            *_stability_warnings(transition_model),
        ],
    )
    # Attach lead time and threshold-aware warnings.
    forecast = forecast.model_copy(
        update={
            "lead_time": lead_time_from_timeline(timeline, threshold),
            "warnings": forecast.warnings
            + forecast_warnings(_WarningsStub(), ordered, timeline, threshold),
        }
    )
    diagnostics = RolloutDiagnostics(
        steps=steps,
        step_delta=step_delta,
        simulated_windows=max_horizon,
    )
    return forecast, diagnostics


def open_loop_error(
    transition_model: RolloutTransitionModel,
    history: list[NetworkState],
    realized: list[NetworkState],
    schema: FeatureSchema,
) -> OpenLoopError:
    """Per-step open-loop state error of the linear transition model.

    Same measurement as ``sentinel.world_model.imagine.open_loop_error`` and the
    same persistence baseline, so the linear and learned transition models can be
    compared on identical windows. Errors are computed on standardized features
    because the world model works in that space; the simulation itself runs on
    raw values, which is what the ridge coefficients were fitted on."""
    if len(history) < transition_model.history_length:
        raise ValueError(
            f"need at least {transition_model.history_length} history windows, got {len(history)}"
        )
    if not realized:
        raise ValueError("at least one realized window is required")

    names = transition_model.feature_names
    matrix = np.stack(
        [
            np.fromiter((s.features.get(n, 0.0) for n in names), dtype=float, count=len(names))
            for s in history[-transition_model.history_length :]
        ]
    )
    target = vectorize_states(list(realized), schema)
    means = np.asarray(schema.means)
    scales = np.asarray(schema.scales)
    keep = [names.index(n) for n in schema.names if n in set(names)]
    if not keep:
        raise ValueError("transition features do not overlap the feature schema")

    simulated: list[np.ndarray] = []
    current = matrix
    for _ in range(len(realized)):
        nxt = apply_transition(transition_model, current)
        simulated.append(nxt)
        current = np.vstack([current[1:], nxt.reshape(1, -1)])

    predicted = (np.stack(simulated)[:, keep] - means[keep]) / scales[keep]
    goal = target[:, keep]
    persistence = np.repeat(matrix[-1][keep][None, :], len(goal), axis=0)
    persistence = (persistence - means[keep]) / scales[keep]
    return OpenLoopError(
        steps=list(range(1, len(goal) + 1)),
        model_mae=[float(v) for v in np.abs(predicted - goal).mean(axis=1)],
        persistence_mae=[float(v) for v in np.abs(persistence - goal).mean(axis=1)],
        windows=1,
    )


class _WarningsStub:
    """Minimal artifacts-like view for shared warning logic (no temporal result)."""

    temporal_result = None


# A clip below this means the stability projection discarded essentially the
# whole fitted map, and the "simulation" is close to a constant predictor. That
# is a real, measured property of the linear transition model on this data, and
# it has to travel with the forecast: a reader comparing this against the world
# model needs to know the linear side is not a like-for-like competitor.
CRUSHED_CLIP = 1e-3


def _stability_warnings(transition_model: RolloutTransitionModel) -> list[str]:
    if transition_model.stability_clip >= CRUSHED_CLIP:
        return []
    return [
        f"Stability projection discarded {1.0 / transition_model.stability_clip:.3g}x of "
        f"the fitted transition map (pre-projection spectral norm "
        f"{transition_model.fitted_spectral_norm:.4g} against a limit of "
        f"{transition_model.spectral_norm:.2g}), so this rollout is close to a "
        f"constant predictor. Treat it as a stability reference, not a working "
        f"simulator, and do not read a comparison against the world model as "
        f"like-for-like."
    ]


__all__ = [
    "ROLLOUT_MODEL_VERSION",
    "RolloutDiagnostics",
    "RolloutTransitionModel",
    "fit_transition_model",
    "load_transition_model",
    "open_loop_error",
    "rollout_forecast",
    "save_transition_model",
]
