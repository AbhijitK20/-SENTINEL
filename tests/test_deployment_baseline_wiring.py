# SPDX-License-Identifier: Apache-2.0
"""Pin how `DeploymentBaseline` is actually wired, so the gap stays visible.

`run_all_detectors` accepts a `deployment_baseline` and forwards it into
`DetectorContext`. The lateral and exfiltration rules both branch on it. In the
shipped product it is always `None`: the only caller that supplies one is
`scripts/measure_real_detectors.py`, a measurement script. Neither
`sentinel.live`, nor `sentinel.api.app`, nor the dashboard passes it.

That means every lateral and exfiltration window in production takes the
`baseline is None` path and appends a warning telling the operator to fit one.
The warning is therefore not a rare diagnostic — it is the normal state, and the
rules are running on absolute synthetic bands while saying so.

Wiring it properly is not a small change. It needs a persisted representation of
a fitted baseline, a trigger that collects a clean reference period from real
traffic, and a configuration surface for the resulting artifact. That is new
architecture rather than a correctness fix, so it is recorded here instead.

If someone does wire it, two things must happen together or this test should
fail loudly:

1. the rules stop taking the `baseline is None` branch, and
2. this file is updated, because the warnings it asserts will no longer appear.
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from sentinel import api, live
from sentinel.detectors import (
    DeploymentBaseline,
    DetectorContext,
    DetectorSet,
    detect_lateral,
    fit_deployment_baseline,
    run_all_detectors,
)
from sentinel.schemas import NetworkState

REPO = Path(__file__).resolve().parent.parent
START = datetime(2026, 1, 1, tzinfo=UTC)


def _state(**features: float) -> NetworkState:
    return NetworkState(
        window_start=START,
        window_end=START + timedelta(seconds=60),
        features=features,
    )


def test_a_baseline_can_be_fitted_and_scores() -> None:
    """The component itself works; the gap is reachability, not correctness."""
    baseline = fit_deployment_baseline([120.0, 140.0, 110.0, 160.0, 130.0])

    assert isinstance(baseline, DeploymentBaseline)
    assert baseline.robust_sigma(1000.0) > 3.0, (
        "a rate far above the reference median must be many sigmas out"
    )
    assert baseline.robust_sigma(125.0) < 1.0


def _edges(destination: str, nbytes: float) -> list[NetworkState]:
    """Windows that put a known amount of traffic on one internal edge."""
    from sentinel.schemas import UnifiedEvent
    from sentinel.state_builder import build_network_states

    # One window per minute on the same internal edge, so the history has the
    # known edges the rule needs and is longer than MIN_HISTORY.
    events = [
        UnifiedEvent(
            event_id=f"e{i}",
            timestamp=START + timedelta(minutes=i),
            source_entity="host-01",
            destination_entity=destination,
            event_type="flow",
            features={"bytes": nbytes, "protocol": 6.0, "destination_port": 445.0},
            source_format="other",
            provenance="test",
        )
        for i in range(8)
    ]
    return list(build_network_states(events, window_seconds=60, stride_seconds=60))


def test_a_fitted_baseline_reaches_the_detector_when_passed() -> None:
    """The plumbing exists end to end once a caller supplies one.

    The states carry a real ``edge_summary``; with an empty one the lateral rule
    has no known edges and both branches return 0.0, which would make this test
    pass for the wrong reason.
    """
    quiet = _edges("host-02", 1_000.0)
    busy = _edges("host-02", 400_000.0)
    baseline = fit_deployment_baseline([120.0, 140.0, 110.0, 160.0, 130.0])

    def lateral_rate(state, history, **kwargs) -> float:
        return next(
            f
            for f in run_all_detectors(state, history, **kwargs)
            if f.attack_type == "lateral_movement"
        ).probability

    # A quiet rate is inside the reference band; a busy one is far outside it.
    quiet_rate = lateral_rate(
        quiet[0], tuple(quiet[:1] + quiet[1:] * 0), deployment_baseline=baseline
    )
    busy_rate = lateral_rate(busy[0], tuple(quiet), deployment_baseline=baseline)
    busy_fallback = lateral_rate(busy[0], tuple(quiet))

    assert busy_rate > quiet_rate, (
        f"a baseline-scoped rate ({busy_rate:.3f}) did not exceed a quiet one "
        f"({quiet_rate:.3f}); the baseline is not reaching the rule"
    )
    assert busy_rate != busy_fallback or quiet_rate != busy_fallback, (
        "supplying a baseline changed no score at all"
    )


@pytest.mark.parametrize("module", [api.app, live])
def test_the_product_paths_do_not_supply_a_baseline_yet(module) -> None:
    """The documented gap, asserted so it cannot be forgotten silently."""
    source = inspect.getsource(module)
    assert "deployment_baseline" not in source, (
        f"{module.__name__} now supplies a deployment_baseline. That is the intended "
        "direction, but the warnings asserted in this file will no longer be emitted "
        "and this test must be updated in the same change."
    )


def test_the_only_supplier_is_a_measurement_script() -> None:
    """No production path builds one; only the measurement script does."""
    suppliers = []
    for path in sorted((REPO / "src").rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == (
                "fit_deployment_baseline"
            ):
                suppliers.append(path.relative_to(REPO).as_posix())
    for path in sorted((REPO / "scripts").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "fit_deployment_baseline" in text:
            suppliers.append(path.relative_to(REPO).as_posix())

    assert all(s.startswith("scripts/") for s in suppliers), (
        f"a production module now fits a deployment baseline: {suppliers}"
    )


def test_lateral_says_plainly_that_it_has_no_baseline() -> None:
    """The warning is the only signal a user gets, so its wording is load-bearing."""
    state = _state(bytes=900_000.0, flow_event_count=10.0)
    history = tuple(_state(bytes=1.0, flow_event_count=10.0) for _ in range(5))
    finding = detect_lateral(DetectorContext(state=state, history=history), DetectorSet())

    assert any("no deployment baseline fitted" in w for w in finding.warnings), (
        "lateral must state that it is running on a synthetic absolute band"
    )
    assert any("over-fires" in w for w in finding.warnings)


def test_exfil_says_plainly_that_it_cannot_alert_without_a_baseline() -> None:
    state = _state(bytes=900_000.0)
    history = tuple(_state(bytes=1.0) for _ in range(5))
    findings = run_all_detectors(state, history)
    exfil = next(f for f in findings if f.attack_type == "exfiltration")

    assert exfil.probability <= 0.5, (
        "without a baseline a heavy-tailed volume z-score must not cross the alert band"
    )
    assert any("no deployment baseline fitted" in w for w in exfil.warnings)
