# SPDX-License-Identifier: Apache-2.0
"""Imagine — open-loop forward simulation with the RSSM prior.

Observed history is burned in through the posterior (that evidence is real), and
then the model is rolled forward for ``k`` steps **without observations**:
``z`` is sampled from the prior ``p(z | h)`` and the previous step's *decoded*
observation is fed back as the next core input. Nothing from the real future can
enter, which is what makes this a simulation rather than a decoder applied to
fresh inputs.

Two measurements come out of this module:

* :func:`imagine` — the imagined futures, with between-sample spread as the
  uncertainty. Open-loop KL is *unobservable* by construction (there is no
  posterior to compare against without the observation), so the honest
  uncertainty is the dispersion of the sampled trajectories, and that is what is
  reported. The previous implementation returned zeros here.
* :func:`open_loop_error` — how far the imagined states drift from the states
  that actually happened, per step, against a persistence baseline. This is the
  metric that separates a learned transition model from a classifier.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Literal

import numpy as np
import torch
from pydantic import BaseModel, ConfigDict, Field

from sentinel.features import FeatureSchema, vectorize_states
from sentinel.predict import (
    DECISION_THRESHOLD,
    FORECAST_VERSION,
    lead_time_from_timeline,
)
from sentinel.schemas import (
    DrivingFeature,
    Forecast,
    NetworkState,
    PredictedStage,
    ProbabilityPoint,
    StageMapping,
)
from sentinel.stage_mapping import map_stage

IMAGINATION_VERSION = "rssm-imagination-v1"

_UNCERTAINTY_CEILING = 0.25  # risk spread (0..0.5) mapped to confidence (1..0)


@dataclass(frozen=True)
class ImaginedRollout:
    """Sampled imagined futures from one observed state.

    Tensors are ``(n_samples, k, ...)``: each sample is an independent draw of
    the stochastic latent, so the spread across samples is the model's own
    uncertainty about the future.
    """

    observations: torch.Tensor  # (n_samples, k, obs_dim) decoded imagined states
    risks: torch.Tensor  # (n_samples, k) P(infiltration)
    stages: torch.Tensor  # (n_samples, k, num_stages)
    latent_spread: torch.Tensor  # (k,) mean per-step distance between sampled latents


@dataclass(frozen=True)
class OpenLoopError(BaseModel):
    """Per-step imagined-vs-realized state error over a set of windows."""

    model_config = ConfigDict(extra="forbid")

    steps: list[int] = Field(min_length=1)
    model_mae: list[float] = Field(min_length=1)
    persistence_mae: list[float] = Field(min_length=1)
    windows: int = Field(ge=1)

    @property
    def mean_skill(self) -> float:
        """1 - model error / persistence error, averaged over steps.

        Zero means the model is no better than repeating the last observed
        window; negative means it is worse.
        """
        if not self.model_mae or not self.persistence_mae:
            return 0.0
        skills = [
            1.0 - (m / p) if p > 0 else 0.0
            for m, p in zip(self.model_mae, self.persistence_mae, strict=True)
        ]
        return float(np.mean(skills))


def imagine(
    core,
    history: np.ndarray | torch.Tensor,
    k: int,
    n_samples: int = 64,
    *,
    temperature: float = 1.0,
    seed: int | None = None,
) -> ImaginedRollout:
    """Burn in on ``history`` then imagine ``k`` steps from the prior.

    Args:
        history: ``(seq_len, obs_dim)`` standardized observations, oldest first.
        k: number of open-loop steps.
        n_samples: independent latent draws; their spread is the uncertainty.
        temperature: scales the latent sampling noise (1.0 = as trained).
        seed: makes the imagination reproducible.
    """
    if k < 1:
        raise ValueError("k must be positive")
    if n_samples < 1:
        raise ValueError("n_samples must be positive")
    if len(history) < 1:
        raise ValueError("history must contain at least one observation")

    observations = torch.as_tensor(np.asarray(history, dtype=np.float32))
    if observations.ndim != 2:
        raise ValueError("history must be a 2-D (seq_len, obs_dim) array")

    was_training = core.training
    core.eval()
    if seed is not None:
        torch.manual_seed(seed)
    with torch.no_grad():
        state = core.initial_state(1)
        for step in range(observations.size(0)):
            _recon, _risk, _stage, state, _encoded = core.forward_step(
                observations[step].unsqueeze(0), state
            )

        batched = _expand_state(state, n_samples)
        imagined: list[torch.Tensor] = []
        risks: list[torch.Tensor] = []
        stages: list[torch.Tensor] = []
        latents: list[torch.Tensor] = []
        previous: torch.Tensor | None = None
        for _step in range(k):
            recon, risk_logits, stage_logits, batched = core.imagine_step(
                batched, previous, temperature=temperature
            )
            imagined.append(recon)
            risks.append(torch.sigmoid(risk_logits).squeeze(-1))
            stages.append(torch.softmax(stage_logits, dim=-1))
            latents.append(batched.z)
            previous = recon

        latent = torch.stack(latents, dim=1)
        rollout = ImaginedRollout(
            observations=torch.stack(imagined, dim=1),
            risks=torch.stack(risks, dim=1),
            stages=torch.stack(stages, dim=1),
            latent_spread=latent.std(dim=0).mean(dim=-1),
        )
    if was_training:
        core.train()
    return rollout


def _expand_state(state, batch_size: int):
    """Repeat a batch-1 state into ``batch_size`` independent trajectories."""
    return replace(
        state,
        h=state.h.expand(batch_size, -1).contiguous(),
        z=state.z.expand(batch_size, -1).contiguous(),
        c=None if state.c is None else state.c.expand(batch_size, -1).contiguous(),
        memory=None
        if state.memory is None
        else state.memory.expand(batch_size, -1, -1).contiguous(),
    )


def rollout_summary(rollout: ImaginedRollout, threshold: float) -> dict[str, float]:
    """Aggregate an imagined rollout into scalars an analyst can read."""
    risks = rollout.risks
    peak = risks.max(dim=1).values
    return {
        "mean_risk": float(risks.mean()),
        "final_risk": float(risks[:, -1].mean()),
        "risk_spread": float(risks.std(dim=0).mean()),
        "crossing_rate": float((peak >= threshold).float().mean()),
        "latent_spread": float(rollout.latent_spread.mean()),
    }


def open_loop_error(
    core,
    history: np.ndarray,
    realized: np.ndarray,
    *,
    n_samples: int = 32,
    seed: int = 0,
) -> OpenLoopError:
    """Per-step imagined-vs-realized error for one window.

    ``history`` is ``(seq_len, obs_dim)`` observed, ``realized`` is
    ``(k, obs_dim)`` what actually happened next. The persistence baseline
    predicts ``S_t`` for every future step, which is the bar a learned
    transition model has to clear to be worth anything.
    """
    rollout = imagine(core, history, k=len(realized), n_samples=n_samples, seed=seed)
    predicted = rollout.observations.mean(dim=0).numpy()
    target = np.asarray(realized, dtype=np.float32)
    model_mae = np.abs(predicted - target).mean(axis=1)
    persistence = np.repeat(np.asarray(history[-1:], dtype=np.float32), len(target), axis=0)
    persistence_mae = np.abs(persistence - target).mean(axis=1)
    return OpenLoopError(
        steps=list(range(1, len(target) + 1)),
        model_mae=[float(v) for v in model_mae],
        persistence_mae=[float(v) for v in persistence_mae],
        windows=1,
    )


def aggregate_open_loop(errors: list[OpenLoopError]) -> OpenLoopError:
    """Average per-step errors across windows."""
    if not errors:
        raise ValueError("at least one window is required")
    steps = errors[0].steps
    return OpenLoopError(
        steps=steps,
        model_mae=[float(np.mean([e.model_mae[i] for e in errors])) for i in range(len(steps))],
        persistence_mae=[
            float(np.mean([e.persistence_mae[i] for e in errors])) for i in range(len(steps))
        ],
        windows=len(errors),
    )


def risk_saliency(core, history: np.ndarray, feature_names: list[str]) -> list[DrivingFeature]:
    """Gradient x input attribution of the risk head at the last observed window.

    This is gradient saliency, not SHAP: it is a first-order local attribution of
    the *model's* risk logit and says nothing about causal contribution. Both the
    ranking and the reported value come from the newest window, so the order
    always matches the numbers.
    """
    observations = torch.as_tensor(np.asarray(history, dtype=np.float32)).requires_grad_(True)
    state = core.initial_state(1)
    for step in range(observations.size(0)):
        _recon, risk_logits, _stage, state, _encoded = core.forward_step(
            observations[step].unsqueeze(0), state
        )
    gradient = torch.autograd.grad(risk_logits.sum(), observations)[0]
    contributions = (gradient[-1] * observations[-1].detach()).numpy()
    ranked = np.argsort(np.abs(contributions))[::-1][:5]
    result = []
    for index in ranked:
        signed = float(contributions[index])
        result.append(
            DrivingFeature(
                name=feature_names[index],
                contribution=signed,
                direction=_direction(signed),
            )
        )
    return result


def imagination_forecast(
    states: list[NetworkState] | tuple[NetworkState, ...],
    core,
    schema: FeatureSchema,
    stage_vocabulary: list[str],
    *,
    max_horizon: int,
    threshold: float = DECISION_THRESHOLD,
    n_samples: int = 64,
    seed: int = 0,
) -> tuple[Forecast, dict[str, float]]:
    """Forecast by K-step open-loop simulation, as a ``Forecast`` contract.

    The timeline is the mean infiltration probability across imagined samples;
    ``ProbabilityPoint.confidence`` is between-sample agreement, so it is the
    first confidence in this codebase that is not a copied PR-AUC.
    """
    if max_horizon < 1:
        raise ValueError("max_horizon must be positive")
    ordered = sorted(states, key=lambda state: state.window_start)
    if not ordered:
        raise ValueError("at least one network state is required")

    history = vectorize_states(ordered, schema)
    rollout = imagine(core, history, k=max_horizon, n_samples=n_samples, seed=seed)
    mean_risk = rollout.risks.mean(dim=0).numpy()
    spread = rollout.risks.std(dim=0).numpy()
    mean_stage = rollout.stages.mean(dim=0).numpy()

    timeline = [
        ProbabilityPoint(
            window=step + 1,
            infiltration_probability=float(np.clip(mean_risk[step], 0.0, 1.0)),
            confidence=float(np.clip(1.0 - spread[step] / (2 * _UNCERTAINTY_CEILING), 0.0, 1.0)),
        )
        for step in range(max_horizon)
    ]
    peak_index = int(np.argmax(mean_risk))
    stage_name = stage_vocabulary[int(np.argmax(mean_stage[peak_index]))]
    stage_probability = float(mean_stage[peak_index].max())

    mapping: StageMapping | None = map_stage(
        ordered, infiltration_probability=float(mean_risk[peak_index])
    )
    forecast = Forecast(
        input_window_start=ordered[0].window_start,
        input_window_end=ordered[-1].window_end,
        horizon_windows=max_horizon,
        model_version=f"{FORECAST_VERSION}+{IMAGINATION_VERSION}",
        probability_timeline=timeline,
        predicted_stage=PredictedStage(
            name=stage_name,
            probability=stage_probability,
            confidence=_stage_confidence(stage_probability),
        ),
        stage_mapping=mapping,
        lead_time=lead_time_from_timeline(timeline, threshold),
        affected_entities=sorted({e for state in ordered[-3:] for e in state.entities})[:10],
        driving_features=risk_saliency(core, history, schema.names),
        supporting_events=list(
            dict.fromkeys(eid for state in ordered[-3:] for eid in state.source_ids)
        )[:10],
        coverage={
            "flow": any(state.coverage.get("flow", False) for state in ordered),
            "packet": any(state.coverage.get("packet", False) for state in ordered),
        },
        warnings=[
            f"Timeline produced by open-loop imagination ({IMAGINATION_VERSION}) from "
            f"{len(ordered)} observed windows: probabilities are the mean over "
            f"{n_samples} prior samples, not observations of future traffic.",
            "Recursion is open-loop: imagined states feed the next step, so error "
            "accumulates with horizon by construction.",
        ],
    )
    diagnostics = rollout_summary(rollout, threshold)
    diagnostics["threshold"] = threshold
    diagnostics["samples"] = float(n_samples)
    return forecast, diagnostics


def _direction(value: float) -> Literal["increasing", "decreasing", "mixed", "unknown"]:
    if value > 1e-6:
        return "increasing"
    if value < -1e-6:
        return "decreasing"
    return "unknown"


def _stage_confidence(probability: float) -> Literal["low", "medium", "high", "unknown"]:
    if probability >= 0.8:
        return "high"
    if probability >= 0.6:
        return "medium"
    if probability > 0:
        return "low"
    return "unknown"


__all__ = [
    "IMAGINATION_VERSION",
    "ImaginedRollout",
    "OpenLoopError",
    "aggregate_open_loop",
    "imagine",
    "imagination_forecast",
    "open_loop_error",
    "risk_saliency",
    "rollout_summary",
]
