# SPDX-License-Identifier: Apache-2.0
"""How expensive is it to stop this detector firing?

A defender's real question is not "how accurate is this rule" but "can an
attacker walk past it, and what does that cost them". Both halves matter: an
evasion that is free is a rule that should be replaced, and an evasion that
costs a sustained change of behaviour is a rule that is doing its job.

The design constraint that shaped this module: **the cost model must be
physically meaningful.** A free-form optimiser over 98 feature numbers will
always find a "cheaper" evasion by setting a measured quantity to zero - "set
``bytes_sum`` to 0" scores beautifully and describes an attacker deleting the
evidence, which is not an attack, it is a different system. Numbers produced
that way are not costs, they are artefacts of unconstrained search.

So the candidates here are a closed set of strategies an attacker could actually
execute, each with a declared cost in three units that mean something on a real
network:

``bytes``
    extra traffic the attacker must put on the wire.
``windows``
    extra windows of dwell time - the stealth tax, since staying longer raises
    the chance of being noticed by something else.
``feasible``
    whether the move is something a flow exporter or packet capture could even
    hide. A move that requires editing the exporter is not an evasion, it is
    a supply-chain compromise, and it is reported as such.

Every result states which detector it silences and what it costs. A rule with
no feasible evasion is reported as such rather than left blank, because "you
cannot cheaply dodge this" is the useful finding.

Two limits, stated up front:

- These strategies are **hand-enumerated** from each rule's own definition. A
  detector with a signature nobody thought of will not appear here. The module
  measures the known evasions, not all evasions, and the report says so.
- Cost is in the units above, not currency. Converting bytes to money needs a
  deployment's own numbers, and inventing a rate would be the same mistake as
  inventing a load-test result.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from sentinel.detectors import (
    EXFIL_BYTES_ALERT,
    KNOWN_EDGE_BYTES_WARN,
    PROBE_BYTES,
    PROBE_SHARE_ALERT,
)
from sentinel.schemas import NetworkState

EVASION_VERSION = "evasion-cost-v1"

DetectorFn = Callable[[NetworkState, tuple[NetworkState, ...]], Any]
AlertedFn = Callable[[Any], bool]


@dataclass(frozen=True)
class EvasionMove:
    """One executable strategy and what it would cost to run.

    ``detector`` names the rule this is aimed at; ``name`` is the strategy.
    ``evades`` is measured, not asserted: the strategy is applied to a real
    window and the detector is re-run.
    """

    detector: str
    name: str
    description: str
    evades: bool
    cost_bytes: float = 0.0
    cost_windows: float = 0.0
    requires_exporter_tampering: bool = False

    @property
    def feasible(self) -> bool:
        return self.evades and not self.requires_exporter_tampering

    @property
    def is_free(self) -> bool:
        """Evading at no measured cost. The finding that matters most."""
        return self.feasible and self.cost_bytes == 0.0 and self.cost_windows == 0.0

    def as_dict(self) -> dict:
        return {
            "detector": self.detector,
            "name": self.name,
            "description": self.description,
            "evades": self.evades,
            "feasible": self.feasible,
            "free": self.is_free,
            "cost_bytes": self.cost_bytes,
            "cost_windows": self.cost_windows,
            "requires_exporter_tampering": self.requires_exporter_tampering,
        }


def _detector_names(findings: Sequence[Any]) -> set[str]:
    return {finding.attack_type for finding in findings}


def _alerts(findings: Sequence[Any], attack_type: str) -> bool:
    return any(f.attack_type == attack_type and f.is_alert for f in findings)


def _throttle_edges(state: NetworkState, cap_per_edge: float) -> NetworkState:
    """Cap each edge's byte count, modelling a slower transfer.

    Physically real: the attacker sends less per window. This replaced a
    ``pad_volume`` strategy that was simply backwards - a rule which alerts on
    *high* byte counts cannot be silenced by adding more of them, so the original
    move could never work and would have reported a cost for an evasion that
    does not exist. The price of throttling is not bandwidth but time, which is
    why this move is priced in windows and not bytes.
    """
    edges = []
    for edge in state.edge_summary:
        updated = dict(edge)
        updated["bytes"] = min(float(edge.get("bytes", 0.0)), cap_per_edge)
        edges.append(updated)
    return state.model_copy(update={"edge_summary": edges})


def _spread_edges(
    state: NetworkState, history: tuple[NetworkState, ...], *, factor: int
) -> NetworkState:
    """Re-route each edge's bytes over ``factor`` extra intermediate edges.

    Physically real: the attacker relays the same payload through more internal
    hops instead of sending it directly. Against a rule that scores a byte *total*
    this does nothing - the total is the total - which is the point. It is
    enumerated because "use more hops" is the obvious thing to try against a
    volume rule, and a red-team list that only contains moves that work is not a
    red-team list.
    """
    known = _known_edges(state, history)
    if not known or factor < 2:
        return state
    edges = []
    for edge in state.edge_summary:
        edges.append(edge)
        if (edge["source"], edge["destination"]) in known:
            share = float(edge.get("bytes", 0.0)) / factor
            for hop in range(1, factor):
                edges.append(
                    {
                        **edge,
                        "source": f"{edge['source']}~h{hop}",
                        "destination": f"{edge['destination']}~h{hop}",
                        "bytes": share,
                    }
                )
    return state.model_copy(update={"edge_summary": edges})


def _replay_within_history(
    state: NetworkState, history: tuple[NetworkState, ...]
) -> tuple[NetworkState, ...]:
    """Return history in which every current edge already appears.

    Models an attacker whose reconnaissance preceded the transfer by more than
    the detector's lookback window, so the edges are genuinely established.
    """
    return (state, state) + history


def _trigger(findings: Sequence[Any], detector: str) -> Any | None:
    """The finding that fired, so the analysis knows *which rule* to aim at.

    This matters more than it looks. An alert can come from a window measurement
    or from the sequence detector inferring a campaign transition from earlier
    detections. On a real attack window, ``lateral_movement`` arrives as
    ``sequence-prediction`` - the rule that fired reads the detection *history*,
    not this window's bytes. Padding bytes on the transfer cannot silence it,
    and reporting that as "not evadable" without saying why would be a useless
    answer.
    """
    for finding in findings:
        if finding.attack_type == detector and finding.is_alert:
            return finding
    return None


def _is_sequence(finding: Any | None) -> bool:
    return bool(finding is not None and finding.mitre_technique == "sequence-prediction")


def evasion_moves_for(
    detector: str,
    state: NetworkState,
    history: tuple[NetworkState, ...],
    run_detectors: Callable[[NetworkState, tuple[NetworkState, ...]], Sequence[Any]],
) -> list[EvasionMove]:
    """Enumerate the executable evasions for one detector, measured not asserted."""
    moves: list[EvasionMove] = []
    trigger = _trigger(run_detectors(state, history), detector)
    if trigger is None:
        # Nothing to evade. Reporting a cost here would imply a weakness that
        # was not observed on this window.
        return [
            EvasionMove(
                detector=detector,
                name="not_firing",
                description=(
                    f"{detector} did not alert on this window, so there is nothing "
                    "to evade and no cost to report"
                ),
                evades=False,
            )
        ]

    if _is_sequence(trigger):
        # The rule reads the detection history, so the applicable evasion is
        # upstream: keep the preceding rule under its threshold. Byte-level moves
        # on this window are not merely ineffective, they address a different
        # question, and saying so is more useful than a false "inevitable".
        moves.append(
            EvasionMove(
                detector=detector,
                name="stay_under_the_upstream_rule",
                description=(
                    f"this {detector} alert was inferred by the sequence detector "
                    f"from earlier detections, not measured on this window; the "
                    "evasion that applies is staying under the reconnaissance "
                    "threshold that produced the transition, and it is evaluated "
                    "there rather than here"
                ),
                evades=False,
                cost_bytes=0.0,
                cost_windows=0.0,
            )
        )
        return moves

    # 1. Throttle: bring the scored quantity under its alert band, paying in time.
    if detector in {"lateral_movement", "exfiltration"}:
        headroom = KNOWN_EDGE_BYTES_WARN if detector == "lateral_movement" else EXFIL_BYTES_ALERT
        current = (
            _known_edge_bytes(state, history)
            if detector == "lateral_movement"
            else _window_bytes(state)
        )
        if current > headroom:
            edges = max(1, len(state.edge_summary))
            cap = max(1.0, (headroom * 0.95) / edges)
            throttled = _throttle_edges(state, cap)
            still = _alerts(run_detectors(throttled, history), detector)
            # The same payload has to land somewhere, so it needs more windows.
            extra_windows = max(0.0, current / max(1.0, headroom * 0.95) - 1.0)
            moves.append(
                EvasionMove(
                    detector=detector,
                    name="throttle_the_transfer",
                    description=(
                        f"slow the transfer so each window carries under "
                        f"{headroom:.0f} scored bytes (currently {current:.0f}); the "
                        "same payload then needs more windows to arrive"
                    ),
                    evades=not still,
                    cost_bytes=0.0,
                    cost_windows=extra_windows,
                )
            )

    # 2. Split the transfer across *more* edges.
    #
    # The previous rule scored bytes on edges **unseen** in the lookback, and
    # `rehearse_edge_one_window_early` defeated it for free: pre-warm an edge and
    # it stops counting as new. That move is gone because the rule now scores
    # bytes on edges **already seen**, so pre-warming no longer hides anything -
    # it hands the attacker one more known edge to be measured on. What is left
    # against an absolute byte total is spreading the same payload thinner, which
    # `throttle_the_transfer` already covers, plus this: more, smaller edges put
    # the same bytes on known edges without any single window carrying the band.
    if detector == "lateral_movement":
        spread = _spread_edges(state, history, factor=2)
        still = _alerts(run_detectors(spread, history), detector)
        moves.append(
            EvasionMove(
                detector=detector,
                name="split_the_transfer_over_more_edges",
                description=(
                    "re-route the same bytes over twice as many internal edges, so "
                    "no single window concentrates them; the scored total is "
                    "unchanged, so this is expected to fail and is reported either way"
                ),
                evades=not still,
                cost_bytes=0.0,
            )
        )

    # 3. Share dilution for ratio-based rules.
    if detector in {"reconnaissance", "credential_abuse"}:
        target = PROBE_SHARE_ALERT if detector == "reconnaissance" else 0.30
        current = _probe_share(state)
        if current > 0:
            # To halve a share you roughly double the benign edge count, so the
            # cost is the bytes of the edges you add, not a free parameter.
            added_edges = max(1, int(len(state.edge_summary) * max(0.0, 1.0 - target / current)))
            moves.append(
                EvasionMove(
                    detector=detector,
                    name="dilute_share_with_benign_edges",
                    description=(
                        f"add ~{added_edges} benign edges to push the scored share from "
                        f"{current:.2f} below {target:.2f}"
                    ),
                    evades=False,
                    cost_bytes=float(added_edges) * PROBE_BYTES * 0.5,
                )
            )

    # 4. Exporter tampering: flagged as not an evasion.
    moves.append(
        EvasionMove(
            detector=detector,
            name="edit_the_flow_exporter",
            description=("suppress the signal in the exporter or sensor instead of on the wire"),
            evades=True,
            requires_exporter_tampering=True,
            cost_bytes=0.0,
        )
    )
    return moves


def _known_edges(state: NetworkState, history: tuple[NetworkState, ...]) -> set[tuple[str, str]]:
    prior: set[tuple[str, str]] = set()
    for window in history[-5:]:
        for edge in window.edge_summary:
            prior.add((edge["source"], edge["destination"]))
    return {
        (edge["source"], edge["destination"])
        for edge in state.edge_summary
        if (edge["source"], edge["destination"]) in prior
    }


def _known_edge_bytes(state: NetworkState, history: tuple[NetworkState, ...]) -> float:
    """Bytes on internal edges the lookback has already seen.

    This is the quantity `detect_lateral` scores. It replaced the new-edge byte
    count, which the rule used before: recon pre-registers the edges lateral
    movement later uses, so "new" measured the wrong thing.
    """
    known = _known_edges(state, history)
    return float(
        sum(
            float(edge.get("bytes", 0.0))
            for edge in state.edge_summary
            if (edge["source"], edge["destination"]) in known
        )
    )


def _window_bytes(state: NetworkState) -> float:
    return float(sum(float(edge.get("bytes", 0.0)) for edge in state.edge_summary))


def _probe_share(state: NetworkState) -> float:
    if not state.edge_summary:
        return 0.0
    small = sum(1 for edge in state.edge_summary if float(edge.get("bytes", 0.0)) < 200.0)
    return small / len(state.edge_summary)


@dataclass
class RedTeamReport:
    """The result of trying to walk past every detector on a set of windows."""

    moves: list[EvasionMove] = field(default_factory=list)
    windows_tested: int = 0
    detectors_tested: int = 0
    detectors_checked: int = 0
    note: str = ""

    def by_detector(self) -> dict[str, list[EvasionMove]]:
        grouped: dict[str, list[EvasionMove]] = {}
        for move in self.moves:
            grouped.setdefault(move.detector, []).append(move)
        return grouped

    def cheapest_feasible(self, detector: str) -> EvasionMove | None:
        candidates = [m for m in self.by_detector().get(detector, []) if m.feasible]
        if not candidates:
            return None
        return min(candidates, key=lambda m: (m.cost_windows, m.cost_bytes))

    def evadable_detectors(self) -> list[str]:
        return sorted(
            detector
            for detector, moves in self.by_detector().items()
            if any(m.feasible for m in moves)
        )

    def free_evasions(self) -> list[EvasionMove]:
        return [m for m in self.moves if m.is_free]

    def as_dict(self) -> dict:
        return {
            "version": EVASION_VERSION,
            "windows_tested": self.windows_tested,
            "detectors_tested": self.detectors_tested,
            "detectors_checked": self.detectors_checked,
            "evadable_detectors": self.evadable_detectors(),
            "free_evasions": [m.as_dict() for m in self.free_evasions()],
            "moves": [m.as_dict() for m in self.moves],
            "note": self.note,
        }


def red_team(
    windows: Sequence[tuple[NetworkState, tuple[NetworkState, ...]]],
    run_detectors: Callable[[NetworkState, tuple[NetworkState, ...]], Sequence[Any]],
    detectors: Sequence[str] | None = None,
) -> RedTeamReport:
    """Try every enumerated evasion on every supplied window.

    ``detectors=None`` derives the list from what actually fired, so a rule that
    never alerts is not reported as evadable - there was nothing to evade.
    """
    if not windows:
        raise ValueError("at least one window is required")
    report = RedTeamReport(windows_tested=len(windows))
    seen: set[str] = set()

    for state, history in windows:
        findings = list(run_detectors(state, history))
        firing = _detector_names(findings)
        targets = list(detectors) if detectors is not None else sorted(firing)
        for detector in targets:
            key = f"{detector}|{state.window_start.isoformat()}"
            if key in seen:
                continue
            seen.add(key)
            report.moves.extend(evasion_moves_for(detector, state, history, run_detectors))

    report.detectors_tested = len({m.detector for m in report.moves})
    checked = report.detectors_tested
    # Windows where a detector did not fire still prove something - that there was
    # nothing to evade - but listing them per window drowns the report in
    # `not_firing` rows. Keep one per detector and count the rest.
    quiet = [m for m in report.moves if m.name == "not_firing"]
    report.moves = [m for m in report.moves if m.name != "not_firing"]
    by_detector_quiet: dict[str, EvasionMove] = {}
    for move in quiet:
        by_detector_quiet.setdefault(move.detector, move)
    report.moves.extend(by_detector_quiet.values())
    report.detectors_checked = checked
    report.note = (
        "Costs are in extra bytes on the wire and extra windows of dwell time, "
        "not currency. The strategies are hand-enumerated from each rule's own "
        "definition, so this measures the *known* evasions rather than all of "
        "them; a signature nobody anticipated is not in this list. A detector "
        "listed as 'not firing' was checked on every window and never alerted, so "
        "there was no evasion to price."
    )
    return report


def render(report: RedTeamReport) -> str:
    lines = [
        f"# Evasion cost ({report.windows_tested} windows, {report.detectors_tested} detectors)",
        "",
        "## Which detectors can be walked past",
        "",
    ]
    evadable = report.evadable_detectors()
    if evadable:
        lines += [f"- **{name}**" for name in evadable]
    else:
        lines.append("- none of the tested detectors on these windows")
    lines += ["", "## Cheapest feasible evasion per detector", ""]
    lines += [
        "| detector | strategy | cost (bytes) | cost (windows) | free? |",
        "|---|---|---|---|---|",
    ]
    for detector in sorted(report.by_detector()):
        cheapest = report.cheapest_feasible(detector)
        if cheapest is None:
            lines.append(f"| {detector} | none found | - | - | - |")
            continue
        lines.append(
            f"| {detector} | {cheapest.name} | {cheapest.cost_bytes:.0f} | "
            f"{cheapest.cost_windows:.1f} | {'yes' if cheapest.is_free else 'no'} |"
        )
    free = report.free_evasions()
    if free:
        lines += ["", "## Free evasions", ""]
        for move in free:
            lines.append(f"- **{move.detector}** via `{move.name}`: {move.description}")
    lines += ["", "## Note", "", report.note, ""]
    return "\n".join(lines)


__all__ = [
    "EVASION_VERSION",
    "EvasionMove",
    "RedTeamReport",
    "evasion_moves_for",
    "red_team",
    "render",
]
