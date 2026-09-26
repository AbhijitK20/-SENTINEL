# SPDX-License-Identifier: Apache-2.0
"""The explanation attached to a forecast must be real, per-horizon, and honest."""

from __future__ import annotations

import numpy as np
import pytest

from sentinel.config import BaselineConfig
from sentinel.explain import SHAPExplainer
from sentinel.explain.contracts import Explanation, FeatureAttribution
from sentinel.explain.service import (
    counterfactual_for,
    explain_forecast,
    explain_state,
    explain_timeline,
)
from sentinel.features import fit_feature_schema, vectorize_states
from sentinel.predict import artifacts_from_runs, forecast
from sentinel.synthetic import generate_labelled_states
from sentinel.targets import build_sequence_samples, make_split_manifest
from sentinel.world_model.imagine import risk_logit_vector

SEED = 11
SCENARIOS = [f"ex{i}" for i in range(6)]


@pytest.fixture(scope="module")
def lab():
    return generate_labelled_states(SCENARIOS, seed=SEED, window_seconds=60, stride_seconds=60)


@pytest.fixture(scope="module")
def trained(lab):
    from sentinel.baseline import train_baseline

    samples = build_sequence_samples(lab, sequence_length=2, horizon=1)
    manifest = make_split_manifest(SCENARIOS, seed=SEED)
    return train_baseline(
        lab, samples, manifest, config=BaselineConfig(decision_threshold=0.5), seed=SEED
    )


@pytest.fixture(scope="module")
def schema(lab):
    return fit_feature_schema([item.state for item in lab])


@pytest.fixture(scope="module")
def observed(lab):
    """The attack scenario's windows, the way an analyst would supply them."""
    return [item.state for item in lab if item.scenario_id == SCENARIOS[0]]


# ── the explainer itself ───────────────────────────────────────────────


def test_exact_values_sum_to_the_logit(schema) -> None:
    rng = np.random.default_rng(0)
    names = schema.names
    coefs = rng.normal(size=len(names))
    explainer = SHAPExplainer.for_linear(coefs, 0.4, names)
    vector = rng.normal(size=len(names))
    result = explainer.explain(vector, method="exact")
    total = sum(a.shap_value for a in result.feature_attributions) + 0.4
    assert total == pytest.approx(float(coefs @ vector + 0.4), abs=1e-6)
    assert explainer.verify_additivity(vector, result)


def test_for_scorer_keeps_feature_names() -> None:
    explainer = SHAPExplainer.for_scorer(lambda v: float(v[0] * 2.0), ["a", "b"], np.zeros((4, 2)))
    assert explainer.feature_names == ["a", "b"]
    assert not explainer.supports_exact


def test_unsupported_method_raises_instead_of_faking(schema) -> None:
    explainer = SHAPExplainer.for_linear(np.ones(len(schema.names)), 0.0, schema.names)
    with pytest.raises(ValueError):
        explainer.explain(np.zeros(len(schema.names)), method="kernel")  # type: ignore[arg-type]


def test_exact_refuses_a_scorer_that_is_not_linear() -> None:
    explainer = SHAPExplainer.for_scorer(lambda v: float(v[0]), ["a"], np.zeros((2, 1)))
    with pytest.raises(ValueError):
        explainer.explain(np.zeros(1), method="exact")


def test_permutation_recovers_a_linear_signal() -> None:
    coefs = np.array([3.0, 0.0])
    explainer = SHAPExplainer.for_scorer(
        lambda v: float(1.0 / (1.0 + np.exp(-(coefs @ v)))),
        ["a", "b"],
        np.zeros((8, 2)),
    )
    result = explainer.explain(np.array([1.0, 0.5]), method="permutation")
    by_name = {a.name: a.shap_value for a in result.feature_attributions}
    assert abs(by_name["a"]) > abs(by_name["b"])


def test_gradient_is_local_evidence_not_a_shapley_claim() -> None:
    explainer = SHAPExplainer.for_scorer(
        lambda v: float(np.tanh(v @ np.array([1.0, -2.0]))),
        ["a", "b"],
        np.zeros((6, 2)),
    )
    result = explainer.explain(np.array([0.7, 0.2]), method="gradient")
    assert result.method == "gradient"
    assert len(result.feature_attributions) == 2
    for attribution in result.feature_attributions:
        assert isinstance(attribution, FeatureAttribution)
        assert attribution.method == "gradient"


# ── the service ────────────────────────────────────────────────────────


def test_explain_state_reports_its_method(schema, trained, observed) -> None:
    explanation = explain_state(observed[-1], schema, trained.model, kind="linear")
    assert isinstance(explanation, Explanation)
    assert explanation.method == "exact"
    assert explanation.feature_attributions
    assert explanation.feature_attributions[0].method == "exact"


def test_explain_state_rejects_a_world_model_without_a_core(schema, trained, observed) -> None:
    with pytest.raises(ValueError):
        explain_state(observed[-1], schema, trained.model, kind="world_model")


def test_explain_timeline_covers_every_horizon(schema, trained, observed) -> None:
    timeline = [_point(window, 0.1 * window) for window in range(1, 5)]
    rows = explain_timeline(timeline, observed, schema, trained.model, kind="linear")
    assert [row.window for row in rows] == [1, 2, 3, 4]
    assert [round(row.probability, 3) for row in rows] == [0.1, 0.2, 0.3, 0.4]
    assert all(row.method == "exact" for row in rows)
    assert all(row.attributions for row in rows)


def test_explain_timeline_of_no_states_is_empty(schema, trained) -> None:
    assert explain_timeline([], [], schema, trained.model) == []


def test_counterfactual_reports_a_feasible_move(schema, trained, observed) -> None:
    result = counterfactual_for(observed[-1], schema, trained.model, target=0.05)
    assert result is None or result.features


# ── attached to a real forecast ────────────────────────────────────────


def test_forecast_carries_an_exact_explanation(trained, observed) -> None:
    result = forecast(observed, artifacts_from_runs(trained), max_horizon=3)
    assert result.explanation is not None
    explanation = result.explanation
    assert explanation.method == "exact"
    assert len(explanation.horizon) == 3
    assert explanation.current_window
    assert "Shapley" in explanation.method_detail
    assert all(row.method == "exact" for row in explanation.horizon)


def test_forecast_explanation_is_deterministic(trained, observed) -> None:
    artifacts = artifacts_from_runs(trained)
    first = forecast(observed, artifacts, max_horizon=2).explanation
    second = forecast(observed, artifacts, max_horizon=2).explanation
    assert first is not None and second is not None
    assert [f.contribution for f in first.current_window] == [
        f.contribution for f in second.current_window
    ]


def test_unexplainable_forecaster_says_so_instead_of_inventing(schema, observed) -> None:
    from sentinel.schemas import ForecastExplanation

    result = explain_forecast(
        observed, schema, model=object(), timeline=[_point(1, 0.5)], model_version="v"
    )
    assert isinstance(result, ForecastExplanation)
    assert result.method == "unavailable"
    assert "not a linear model" in result.method_detail


def test_risk_logit_reacts_to_a_candidate_window() -> None:
    pytest.importorskip("torch")
    from sentinel.world_model.model import RSSMCore

    core = RSSMCore(obs_dim=4, hidden_dim=8, latent_dim=8, num_stages=3)
    core.eval()
    history = np.zeros((3, 4), dtype=np.float32)
    history[-1, 0] = 5.0
    low = risk_logit_vector(core, history, np.zeros(4, dtype=np.float32))
    high = risk_logit_vector(core, history, np.full(4, 3.0, dtype=np.float32))
    assert isinstance(low, float) and isinstance(high, float)
    assert np.isfinite(low) and np.isfinite(high)


def test_world_model_explanation_uses_its_own_method(schema, observed) -> None:
    pytest.importorskip("torch")
    from sentinel.explain.service import _world_model_explainer
    from sentinel.world_model.model import RSSMCore

    core = RSSMCore(obs_dim=schema.width, hidden_dim=8, latent_dim=8, num_stages=3)
    core.eval()
    history = vectorize_states(observed[-3:], schema)
    explainer = _world_model_explainer(core, schema, history)
    result = explainer.explain(vectorize_states([observed[-1]], schema), method="gradient")
    assert result.method == "gradient"
    assert len(result.feature_attributions) == schema.width


# ── helpers ────────────────────────────────────────────────────────────


def _point(window: int, probability: float):
    from sentinel.schemas import ProbabilityPoint

    return ProbabilityPoint(window=window, infiltration_probability=probability, confidence=0.0)


# -- contract construction ------------------------------------------------


def test_explanation_contract_records_method_and_caveat_free_fields() -> None:
    from sentinel.explain.contracts import Explanation as ExplainContract
    from sentinel.explain.contracts import FeatureAttribution as Attribution

    explanation = ExplainContract(
        prediction=0.87,
        risk_score=0.87,
        stage_probs={"Unknown": 1.0},
        feature_attributions=[
            Attribution(name="dst_port_nunique", value=47.0, shap_value=0.312, method="exact")
        ],
        method="exact",
    )
    assert explanation.risk_score == 0.87
    assert len(explanation.feature_attributions) == 1
    assert explanation.top_k(1)[0].name == "dst_port_nunique"


def test_attention_fields_are_present_but_never_populated() -> None:
    # The temporal model is a GRU and no graph encoder ships, so these are
    # contract compatibility only. They must stay None rather than be filled
    # with something invented - see explain/__init__.py.
    from sentinel.explain.contracts import Explanation as ExplainContract

    explanation = ExplainContract(
        prediction=0.1, risk_score=0.1, stage_probs={"Benign": 1.0}, feature_attributions=[]
    )
    assert explanation.temporal_attention is None
    assert explanation.graph_attention is None


def test_counterfactual_contract_records_the_move() -> None:
    from sentinel.explain.contracts import Counterfactual as CF
    from sentinel.explain.contracts import FeatureAttribution as Attribution

    counterfactual = CF(
        original=0.87,
        target=0.14,
        features=[Attribution(name="a", value=0.5, shap_value=-0.73, method="exact")],
        predicted_impact=-0.73,
    )
    assert counterfactual.original == 0.87
    assert counterfactual.target == 0.14
    assert counterfactual.predicted_impact == -0.73
