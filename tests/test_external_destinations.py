# SPDX-License-Identifier: Apache-2.0
"""An "external" destination must be recognised as one, not spelled as a placeholder.

`external_destination_count` was computed as::

    sum(1 for entity in entities if entity.startswith(("external", "1.2.3.4")))

which matches a literal entity named `external-something` or the one hard-coded
address `1.2.3.4`. Across every window of the committed corpus the count was
identically `0.0`, so the Exfiltration rule in `stage_mapping.py` — which
requires a positive count — was unreachable on every shipped dataset, and would
have been equally wrong on a real capture.

These tests pin both directions: an off-net destination must be counted, and an
on-net one must not.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from sentinel.schemas import UnifiedEvent
from sentinel.stage_mapping import STAGE_RULES
from sentinel.state_builder import build_network_states, is_external_destination

START = datetime(2026, 1, 1, tzinfo=UTC)


def _event(index: int, destination: str, nbytes: float) -> UnifiedEvent:
    return UnifiedEvent(
        event_id=f"e{index}",
        timestamp=START + timedelta(seconds=index),
        source_entity="host-01",
        destination_entity=destination,
        event_type="flow",
        features={"bytes": nbytes, "protocol": 6.0, "destination_port": 443.0},
        source_format="other",
        provenance="test",
    )


def _state(destinations: list[str], nbytes: float = 200_000.0):
    events = [_event(i, d, nbytes) for i, d in enumerate(destinations)]
    return build_network_states(events, window_seconds=60, stride_seconds=60)[0]


@pytest.mark.parametrize(
    "entity",
    [
        "8.8.8.8",
        "1.2.3.4",
        "evil.com",
        "malicious.example.org",
        "203.0.113.7",
        "172.32.0.1",  # first address past RFC1918 172.16/12, so public
        "external-gateway",
        "EXTERNAL-THING",
    ],
)
def test_off_net_destinations_are_external(entity: str) -> None:
    assert is_external_destination(entity) is True


@pytest.mark.parametrize(
    "entity",
    [
        "host-01",
        "host-08",
        "auth-service",
        "server-03",
        "file-server",
        "web-proxy",
        "10.0.0.5",
        "192.168.1.1",
        "172.16.4.4",
        "172.31.255.255",  # last address inside RFC1918 172.16/12
        "127.0.0.1",
        "169.254.1.1",
        "localhost",
    ],
)
def test_on_net_destinations_are_not_external(entity: str) -> None:
    assert is_external_destination(entity) is False


def test_an_external_destination_is_counted() -> None:
    state = _state(["host-02", "auth-service", "evil.com"])
    assert state.features["external_destination_count"] == 1.0


def test_an_internal_only_window_counts_zero() -> None:
    state = _state(["host-02", "host-03", "auth-service", "10.1.1.1"])
    assert state.features["external_destination_count"] == 0.0


def test_multiple_external_destinations_are_all_counted() -> None:
    state = _state(["evil.com", "8.8.8.8", "host-01", "10.0.0.1"])
    assert state.features["external_destination_count"] == 2.0


def test_the_exfiltration_stage_becomes_reachable_with_an_external_destination() -> None:
    """The rule that was dead, proven live.

    It requires bytes > 100_000 *and* a positive external count. Before the fix
    the second condition could not be satisfied by any real input.
    """
    internal = _state(["host-02", "auth-service"])
    external = _state(["host-02", "evil.com"])

    def fired(state) -> bool:
        return any(
            rule.stage == "Exfiltration" and rule.evaluate(state) is not None
            for rule in STAGE_RULES
        )

    assert not fired(internal), "an all-internal window must not map to Exfiltration"
    assert fired(external), (
        "Exfiltration did not fire for 200 kB to an external destination; the rule is "
        "still unreachable"
    )


def test_the_exfiltration_rule_still_requires_volume() -> None:
    """The fix must not turn a stray external connection into exfiltration."""
    state = _state(["host-02", "evil.com"], nbytes=500.0)

    def fired(state) -> bool:
        return any(
            rule.stage == "Exfiltration" and rule.evaluate(state) is not None
            for rule in STAGE_RULES
        )

    assert not fired(state), "500 bytes to an external host is not exfiltration"


def test_blank_entities_are_not_external() -> None:
    assert is_external_destination("") is False
    assert is_external_destination("   ") is False
