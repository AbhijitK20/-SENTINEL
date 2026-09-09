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
- The private API of ``trajectory.predict`` is not used; this module imports
  only public helpers.

Design note: the transition function is a linear ridge map from concatenated
history windows to the next window's features. It is deterministic (no PyTorch
required), cheap to fit, easy to audit, and sufficient to demonstrate the
recursive-rollout mechanism on replay data.
"""

from __future__ import annotations

from datetime import timedelta

import numpy as np
from pydantic import BaseModel, ConfigDict, Field

from trajectory.features import FeatureSchema, vectorize_states
from trajectory.predict import (
    DECISION_THRESHOLD,
    FORECAST_VERSION,
    forecast_warnings,
    lead_time_from_timeline,
    predicted_stage_from_timeline,
)
from trajectory.schemas import Forecast, NetworkState, ProbabilityPoint

ROLLOUT_MODEL_VERSION = "transition-rollout-v1"


class RolloutTransitionModel(BaseModel):
    """Serializable linear next-state transition model."""

    model_config = ConfigDict(extra="forbid")

    model_version: str = ROLLOUT_MODEL_VERSION
    history_length: int = Field(ge=1)
    feature_names: list[str] = Field(min_length=1)
    coefficients: list[list[float]]  # [history_length * width, width]
    intercept: list[float]
    residual_scale: list[float]  # per-feature training residual std
    training_windows: int = Field(ge=1)


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
) -> RolloutTransitionModel:
    """Fit the linear next-state map on labelled states from given scenarios.

    Callers pass training scenarios via ``scenario_ids`` to keep the fit
    leakage-safe. Each sample maps a contiguous history of ``history_length``
    windows to the next window's state features.
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

    X_rows: list[np.ndarray] = []
    Y_rows: list[np.ndarray] = []
    feature_names: list[str] | None = None
    for scenario_id in sorted(by_scenario):
        states = sorted(by_scenario[scenario_id], key=lambda item: item.state.window_start)
        for index in range(history_length - 1, len(states) - 1):
            history = states[index - history_length + 1 : index + 1]
            target = states[index + 1]
            names = sorted(history[-1].state.features)
            if feature_names is None:
                feature_names = names
            elif names != feature_names:
                raise ValueError(
                    "inconsistent feature sets across states; refit the feature schema first"
                )
            X_rows.append(
                np.concatenate(
                    [
                        np.fromiter(
                            (s.state.features[n] for n in names), dtype=float, count=len(names)
                        )
                        for s in history
                    ]
                )
            )
            Y_rows.append(np.fromiter((target.state.features[n] for n in names), dtype=float))

    if feature_names is None or not X_rows:
        raise ValueError("not enough contiguous history to fit the transition model")

    X = np.stack(X_rows)
    Y = np.stack(Y_rows)

    # Ridge closure with mean-centering: intercept absorbs the means.
    x_mean = X.mean(axis=0)
    y_mean = Y.mean(axis=0)
    Xc = X - x_mean
    Yc = Y - y_mean
    reg = ridge * np.eye(Xc.shape[1])
    coefficients = np.linalg.solve(Xc.T @ Xc + reg, Xc.T @ Yc)
    intercept = y_mean - x_mean @ coefficients

    residuals = Y - (X @ coefficients + intercept)
    residual_scale = residuals.std(axis=0)
    residual_scale[residual_scale == 0.0] = 1.0

    return RolloutTransitionModel(
        history_length=history_length,
        feature_names=feature_names,
        coefficients=coefficients.tolist(),
        intercept=intercept.tolist(),
        residual_scale=residual_scale.tolist(),
        training_windows=len(X_rows),
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
        next_raw = current.reshape(-1) @ np.asarray(transition_model.coefficients) + np.asarray(
            transition_model.intercept
        )
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


class _WarningsStub:
    """Minimal artifacts-like view for shared warning logic (no temporal result)."""

    temporal_result = None


__all__ = [
    "ROLLOUT_MODEL_VERSION",
    "RolloutDiagnostics",
    "RolloutTransitionModel",
    "fit_transition_model",
    "load_transition_model",
    "rollout_forecast",
    "save_transition_model",
]
