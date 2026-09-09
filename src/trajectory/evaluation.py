"""Walk-forward replay evaluation: forecast-versus-reality and measured lead time.

For every labelled state in a scenario, the evaluator produces the forecast
that was available *at that moment* (using only that state's history) and then
compares it with the label that was actually realized inside the forecast
horizon. The output rows answer the demo question directly:

    At window T, what did the model predict — and what actually happened next?

The measured lead time is defined once, here:

    lead_windows = the number of windows between the first forecast whose
    infiltration probability crosses the decision threshold and the first
    window whose realized future (within the horizon) is infiltration —
    counted only when the forecast crossed the threshold no later than the
    realized onset. A forecast that crosses after the onset, or never, earns
    no lead credit; false early warnings are counted separately.

This is the measured counterpart to the predicted ``LeadTimeEstimate`` inside
a single ``Forecast``; it is computed against labels, so it is only meaningful
on data with trustworthy labels (currently the synthetic replay).
"""

from __future__ import annotations

from collections.abc import Callable

from pydantic import BaseModel, ConfigDict, Field

from trajectory.baseline import SPLIT_NAMES
from trajectory.predict import DECISION_THRESHOLD, LoadedArtifacts, forecast
from trajectory.schemas import Forecast, NetworkState
from trajectory.targets import LabelledState

REPLAY_EVALUATION_VERSION = "replay-evaluation-v1"


class ReplayRow(BaseModel):
    """One forecast-versus-reality observation at one input window."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    input_window_end: str = Field(min_length=1)
    history_length: int = Field(ge=1)
    peak_probability: float = Field(ge=0.0, le=1.0)
    threshold_crossed: bool
    predicted_stage: str = Field(min_length=1)
    realized_future_infiltration: bool
    realized_future_stage: str = Field(min_length=1)
    lead_windows: int | None = Field(default=None, ge=0)
    correct_direction: bool


class ReplayScenarioSummary(BaseModel):
    """Per-scenario aggregation of replay rows."""

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    rows: int = Field(ge=1)
    threshold_crossings: int = Field(ge=0)
    realized_onsets: int = Field(ge=0)
    true_positive_forecasts: int = Field(ge=0)
    false_early_warnings: int = Field(ge=0)
    direction_accuracy: float = Field(ge=0.0, le=1.0)
    median_lead_windows: float | None = None


class ReplayEvaluation(BaseModel):
    """Full walk-forward replay evaluation result."""

    model_config = ConfigDict(extra="forbid")

    evaluation_version: str = REPLAY_EVALUATION_VERSION
    decision_threshold: float
    horizon: int = Field(ge=1)
    scenarios_evaluated: int = Field(ge=0)
    rows: list[ReplayRow]
    summaries: list[ReplayScenarioSummary]
    measured_median_lead_windows: float | None = None
    forecast_crossing_rate: float = Field(ge=0.0, le=1.0)
    false_early_warning_rate: float = Field(ge=0.0, le=1.0)
    warnings: list[str] = Field(default_factory=list)


def evaluate_replay(
    labelled_states: list[LabelledState],
    artifacts: LoadedArtifacts,
    *,
    horizon: int,
    threshold: float | None = None,
    split_filter: str | None = "test",
    max_history: int | None = None,
    min_history: int = 2,
    forecast_fn: Callable[..., Forecast] | None = None,
) -> ReplayEvaluation:
    """Walk forward through each scenario and score every forecast.

    ``split_filter`` restricts evaluation to one split ("test" by default)
    using the artifacts' recorded split manifest; pass ``None`` to evaluate
    every state. ``max_history`` truncates the history fed to the temporal
    models, which were trained with a fixed sequence length.

    ``forecast_fn`` replaces the default per-horizon forecaster, enabling
    honest like-for-like comparison (e.g. recursive rollout) on identical
    windows. It receives ``(states, artifacts)`` plus the keyword arguments
    ``max_horizon`` and ``threshold``.
    """
    if horizon < 1:
        raise ValueError("horizon must be positive")
    # Resolution order: explicit argument, calibrated threshold stored with
    # the artifacts, then the shipped 0.5 default.
    if threshold is None:
        threshold = artifacts.calibrated_threshold or DECISION_THRESHOLD
    if not 0 < threshold < 1:
        raise ValueError("threshold must be strictly between zero and one")
    if not labelled_states:
        raise ValueError("at least one labelled state is required")

    allowed_scenarios = _allowed_scenarios(artifacts, split_filter)
    by_scenario: dict[str, list[LabelledState]] = {}
    for item in labelled_states:
        if allowed_scenarios is None or item.scenario_id in allowed_scenarios:
            by_scenario.setdefault(item.scenario_id, []).append(item)
    if not by_scenario:
        raise ValueError("no labelled states remain after split filtering")

    rows: list[ReplayRow] = []
    warnings: list[str] = []
    effective_forecast_fn = forecast_fn or forecast
    for scenario_id in sorted(by_scenario):
        states = sorted(by_scenario[scenario_id], key=lambda item: item.state.window_start)
        for index in range(len(states) - horizon):
            history = states[: index + 1]
            if len(history) < min_history:
                continue
            window_states: list[NetworkState] = [item.state for item in history]
            if max_history is not None:
                window_states = window_states[-max_history:]

            result = effective_forecast_fn(
                window_states, artifacts, max_horizon=horizon, threshold=threshold
            )
            peak = max(result.probability_timeline, key=lambda p: p.infiltration_probability)
            crossed = peak.infiltration_probability >= threshold

            future = states[index + 1 : index + 1 + horizon]
            realized_infiltration = any(item.label.infiltration for item in future)
            realized_stage = future[-1].label.attack_stage

            lead = _lead_credit(
                result.probability_timeline, threshold, [i.label.infiltration for i in future]
            )

            rows.append(
                ReplayRow(
                    scenario_id=scenario_id,
                    input_window_end=history[-1].state.window_end.isoformat(),
                    history_length=len(history),
                    peak_probability=peak.infiltration_probability,
                    threshold_crossed=crossed,
                    predicted_stage=result.predicted_stage.name,
                    realized_future_infiltration=realized_infiltration,
                    realized_future_stage=realized_stage,
                    lead_windows=lead,
                    correct_direction=(crossed == realized_infiltration),
                )
            )

    if not rows:
        raise ValueError("not enough states to evaluate; lower min_history or horizon")

    if artifacts.temporal_result is not None and not artifacts.temporal_models:
        warnings.append(
            "Temporal per-horizon weights were unavailable; timeline probabilities "
            "are the documented baseline decay surrogate."
        )

    summary_ids = sorted({r.scenario_id for r in rows})
    summaries = [_summarize(scenario_id, rows) for scenario_id in summary_ids]
    leads = [r.lead_windows for r in rows if r.lead_windows is not None]
    crossings = sum(1 for r in rows if r.threshold_crossed)
    false_early = sum(1 for r in rows if r.threshold_crossed and not r.realized_future_infiltration)

    return ReplayEvaluation(
        evaluation_version=REPLAY_EVALUATION_VERSION,
        decision_threshold=threshold,
        horizon=horizon,
        scenarios_evaluated=len(summaries),
        rows=rows,
        summaries=summaries,
        measured_median_lead_windows=_median(leads),
        forecast_crossing_rate=crossings / len(rows),
        false_early_warning_rate=false_early / len(rows),
        warnings=warnings,
    )


def _lead_credit(timeline, threshold: float, realized_infiltration: list[bool]) -> int | None:
    """Windows of lead, or None when no creditable lead exists.

    Credit requires the forecast to cross the threshold at or before the first
    realized infiltration window within the horizon. Crossing after the onset
    (or with no onset) earns no credit; the crossing itself is still visible in
    the row via ``threshold_crossed``.
    """
    onset = next((i for i, flag in enumerate(realized_infiltration) if flag), None)
    crossing = next(
        (p.window - 1 for p in timeline if p.infiltration_probability >= threshold), None
    )
    if crossing is None:
        return None
    if onset is None or crossing > onset:
        return None
    return onset - crossing


def _summarize(scenario_id: str, rows: list[ReplayRow]) -> ReplayScenarioSummary:
    scenario_rows = [r for r in rows if r.scenario_id == scenario_id]
    leads = [r.lead_windows for r in scenario_rows if r.lead_windows is not None]
    return ReplayScenarioSummary(
        scenario_id=scenario_id,
        rows=len(scenario_rows),
        threshold_crossings=sum(1 for r in scenario_rows if r.threshold_crossed),
        realized_onsets=sum(1 for r in scenario_rows if r.realized_future_infiltration),
        true_positive_forecasts=sum(
            1 for r in scenario_rows if r.threshold_crossed and r.realized_future_infiltration
        ),
        false_early_warnings=sum(
            1 for r in scenario_rows if r.threshold_crossed and not r.realized_future_infiltration
        ),
        direction_accuracy=(
            sum(1 for r in scenario_rows if r.correct_direction) / len(scenario_rows)
        ),
        median_lead_windows=_median(leads),
    )


def _median(values: list[int]) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _allowed_scenarios(artifacts: LoadedArtifacts, split_filter: str | None) -> set[str] | None:
    if split_filter is None:
        return None
    if split_filter not in SPLIT_NAMES:
        raise ValueError(f"split_filter must be one of {SPLIT_NAMES} or None")
    manifest = artifacts.baseline_result.split_manifest
    scenarios = getattr(manifest, f"{split_filter}_scenarios")
    return set(scenarios)


__all__ = [
    "REPLAY_EVALUATION_VERSION",
    "ReplayEvaluation",
    "ReplayRow",
    "ReplayScenarioSummary",
    "evaluate_replay",
]
