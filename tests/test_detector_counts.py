# SPDX-License-Identifier: Apache-2.0
"""Window aggregates that are counts must not be re-multiplied by a count.

`state_builder` aggregates `failed_auth` with `Agg.SUM`, so
`state.features["failed_auth"]` is a total for the window. `detect_credential`
named it `mean_failed`, multiplied by the flow count, and labelled the product a
per-minute rate — counting every failure once per flow. Measured on the
committed fixture before the fix, two failed-auth events produced
`failed_auth_per_min = 26.0` and saturated the finding at probability 1.0.

`malware_process_executions` has no policy entry, so it falls through to the
generic sum at `state_builder.py:216`, and `detect_malware` had the identical
defect.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.detectors import (
    FAILED_AUTH_PER_MIN_ALERT,
    FAILED_AUTH_PER_MIN_WARN,
    DetectorContext,
    DetectorSet,
    detect_credential,
    detect_malware,
)
from sentinel.schemas import NetworkState

START = datetime(2026, 1, 1, tzinfo=UTC)


def state(**features: float) -> NetworkState:
    return NetworkState(
        window_start=START,
        window_end=START + timedelta(seconds=60),
        features=features,
    )


def credential_finding(**features: float):
    base = {"flow_event_count": 20.0}
    base.update(features)
    return detect_credential(DetectorContext(state=state(**base)), DetectorSet())


def test_failed_auth_is_read_as_a_window_count_not_a_per_flow_mean() -> None:
    """Two failures in a 60 s window is 2.0/min, not 26.0/min.

    The fixture deliberately carries 20 flows: the old code multiplied the total
    by that and produced 2 * 20 * 1 = 40/min (the run that measured 26.0 used a
    shorter history-derived window). The correct value is independent of the
    flow count entirely.
    """
    finding = credential_finding(failed_auth=2.0)
    evidence = {e.name: e.observed_value for e in finding.evidence}
    assert evidence["failed_auth_per_min"] == pytest.approx(2.0), (
        f"reported {evidence['failed_auth_per_min']}/min for 2 failures in a 60 s "
        "window; the count must not be multiplied by the flow count"
    )


def test_failed_auth_rate_is_independent_of_flow_count() -> None:
    """The bug scaled with window size; the fix must not."""
    few = credential_finding(failed_auth=3.0, flow_event_count=2.0)
    many = credential_finding(failed_auth=3.0, flow_event_count=500.0)
    a = {e.name: e.observed_value for e in few.evidence}["failed_auth_per_min"]
    b = {e.name: e.observed_value for e in many.evidence}["failed_auth_per_min"]

    assert a == pytest.approx(b), (
        f"rate changed with flow count ({a} vs {b}/min); a window total converted to "
        "a rate must depend only on the window length"
    )


def test_a_single_failed_auth_does_not_saturate_the_finding() -> None:
    """One failure in a 60 s window is below the alert band, not a certainty.

    This is the observed failure mode: every window containing a single failed
    auth reported probability 1.0 / is_alert True.
    """
    finding = credential_finding(failed_auth=1.0)
    rate = {e.name: e.observed_value for e in finding.evidence}["failed_auth_per_min"]

    assert rate < FAILED_AUTH_PER_MIN_ALERT, f"{rate}/min should be under the alert band"
    assert finding.probability < 1.0
    assert not finding.is_alert, (
        "a single failed authentication alerted; the old inflation made any non-zero "
        "count cross the band"
    )


def test_the_alert_band_is_reachable_at_its_documented_value() -> None:
    """The band is a per-minute rate, so a rate at the band must alert."""
    at_band = credential_finding(failed_auth=FAILED_AUTH_PER_MIN_ALERT)
    above = credential_finding(failed_auth=FAILED_AUTH_PER_MIN_ALERT * 4)
    below = credential_finding(failed_auth=FAILED_AUTH_PER_MIN_WARN * 0.5)

    assert above.is_alert, f"{FAILED_AUTH_PER_MIN_ALERT * 4}/min must alert"
    assert not below.is_alert, f"{FAILED_AUTH_PER_MIN_WARN * 0.5}/min must not alert"
    assert at_band.probability > below.probability


def test_windows_longer_than_sixty_seconds_scale_correctly() -> None:
    """The 60 s factor is the window length, not a constant."""
    st = NetworkState(
        window_start=START,
        window_end=START + timedelta(seconds=300),
        features={"failed_auth": 10.0, "flow_event_count": 20.0},
    )
    finding = detect_credential(DetectorContext(state=st), DetectorSet())
    rate = {e.name: e.observed_value for e in finding.evidence}["failed_auth_per_min"]

    assert rate == pytest.approx(2.0), f"10 failures in 300 s is 2/min, got {rate}"


def test_malware_executions_are_a_count_not_mean_times_event_count() -> None:
    """`malware_process_executions` is summed, so the band is on the total."""
    st = state(malware_process_executions=6.0, event_count=40.0)
    finding = detect_malware(DetectorContext(state=st), DetectorSet())
    evidence = {e.name: e.observed_value for e in finding.evidence}

    assert evidence["process_executions"] == pytest.approx(6.0), (
        f"reported {evidence['process_executions']} executions for a window total of 6; "
        "the old code multiplied by event_count"
    )
    assert finding.is_alert, "6 executions is above the 2/5 band and must alert"


def test_malware_still_reports_disabled_without_endpoint_telemetry() -> None:
    """The fix must not turn a disabled detector into a silent zero."""
    st = state(event_count=40.0)
    finding = detect_malware(DetectorContext(state=st), DetectorSet())

    assert finding.probability == 0.0
    assert any("disabled" in w for w in finding.warnings)
