# SPDX-License-Identifier: Apache-2.0
"""Attack-type detectors over NetworkState windows.

Each detector inspects one window state and emits a normalized AttackFinding
(schema in schemas.py), so the fusion engine and dashboard need no
detector-specific code. Design rules:

- Baselines come from the provided benign history; thresholds are explicit
  constants, tuned on synthetic-recon-lateral-v2 and revisited with real data.
- A detector lacking the telemetry it needs (C2 needs DNS/TLS metadata) says so
  via warnings with probability 0.0 — it never fabricates a score.
- Findings are associations observed in telemetry, never proof of a technique.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from statistics import mean, median, pstdev

from pydantic import BaseModel, ConfigDict, Field

from sentinel.schemas import AssetRecord, AttackFinding, NetworkState, StageEvidence
from sentinel.threat_intel import ThreatIntelFeed, evaluate_hosts

DETECTOR_VERSION = "detectors-v1"
DEPLOYMENT_BASELINE_VERSION = "deployment-baseline-v1"

# Explicit thresholds, measured on synthetic-recon-lateral-v2 (30s windows):
# benign max rst_ratio 0.000 / probe_share 0.000 / failed_auth 0.0 per min /
# new-edge bytes 20k, vs recon min rst_ratio 0.476 / probe_share 0.364 /
# failed_auth 2.0 per min, lateral new-edge bytes up to 81k. Benign rate
# z-scores reach 2.85, so rate detectors map z/6 and stay quiet on benign.
#
# Re-measured against real CIC-IDS2017 (300s windows, 983 windows). Two
# constants did not survive; see research/ATTACK_DETECTION_REAL_DATA.md.
RST_RATIO_WARN = 0.10  # SYN+RST probe share of flows (recon signature)
RST_RATIO_ALERT = 0.30
# PROBE_SHARE_WARN/PROBE_SHARE_ALERT are gone. The low-byte edge share does not
# separate real traffic: benign windows sit at a median of 0.493 and attack
# windows at 0.500, with the distributions almost fully overlapping. The old
# 0.10/0.30 band put 692 of 698 real benign windows above the alert level and
# reconnaissance fired on 981 of 983 real windows. The value is still computed
# and reported as evidence; it is no longer a score. `_probe_score` and
# PROBE_BYTES stay for that evidence.
PROBE_BYTES = 200.0
PROBE_MIN_EDGES = 6.0  # a scan is many probe edges; a few tiny flows are not (evidence only)
# Flows required before an RST *share* is treated as a measurement rather than
# the ratio of two or three observations.
RST_RATIO_MIN_FLOWS = 8.0
FAILED_AUTH_PER_MIN_WARN = 1.0  # failed auths per minute, from the window count
FAILED_AUTH_PER_MIN_ALERT = 2.0
# Bytes per second on internal edges that history has already seen. The old
# 25k/50k band was on *new* edges, which this attack chain makes the wrong
# quantity - see `detect_lateral`.
#
# Expressed as a **rate**, not a per-window total, and re-fitted as one. The old
# band was an absolute byte count fitted on 30s windows (50k warn / 60k alert).
# That has two defects. It is not comparable across window lengths, and the
# console lets the operator choose the window, so a 300s window scored ten times
# higher for identical traffic purely because the window was longer. And a
# window-length-dependent number cannot be validated on a corpus windowed
# differently from the one it was fitted on.
#
# Re-fit by sweeping the known-edge byte *rate* for the best F1, keeping the
# original 5:6 warn:alert shape. `scripts/sweep_known_edge_band.py` runs that
# sweep and writes reports/generated/detector-sweep/.
#
# v2 (2026-09, seeds 17/42/7/99): 750 / 900 B/s. Benign sat at a median of
# 579 B/s and p95 934, lateral at median 2,490 and p95 5,743, so the classes
# separated on the rate and the rule reported precision 0.73-0.78, recall 1.00.
# **That separation was an artefact of the generator, not of the signal.**
# synthetic-recon-lateral-v2 capped every benign connection at 6 kB while the
# lateral phase moved 20-80 kB, so "bytes on a known edge" was a near-perfect
# label proxy; 97 of the 98 model features were decoration for the same reason.
#
# v3 (seeds 17/42/7/99): best mean F1 0.5443 at 1500 / 1800 B/s, minimum
# precision 0.4152 and minimum recall 0.5575. No band on this grid reaches the
# old floors of 0.70 / 0.80, and the sweep cannot manufacture one: the rule
# scores bytes on already-seen internal edges, and once ordinary internal
# traffic also transfers data over those edges the quantity stops being
# discriminative.
#
# The honest conclusion is that this rule needs a DeploymentBaseline for the
# deployment it runs in. Until one is fitted it reports evidence and warns;
# see docs/KNOWN_LIMITATIONS.md. Do not re-tune this band to restore the v2
# numbers without re-running the sweep and recording the result.
KNOWN_EDGE_BYTES_PER_SEC_WARN = 1500.0
KNOWN_EDGE_BYTES_PER_SEC_ALERT = 1800.0
EXFIL_BYTES_WARN = 75_000.0  # absolute window-bytes floor
EXFIL_BYTES_ALERT = 150_000.0
LATERAL_LOOKBACK = 5  # windows of recent history for new-edge detection
MIN_HISTORY = 3  # benign windows required before z-scores are trusted
Z_SCALE = 6.0  # z-score that maps to probability 1.0 (benign max z 2.85)
DDOS_CAP = 0.95  # flow telemetry cannot confirm packet-level DDoS

MITRE = {
    "ddos": "T1498",
    "reconnaissance": "T1046",
    "credential_abuse": "T1110",
    "lateral_movement": "T1021",
    "command_and_control": "T1071",
    "exfiltration": "T1048",
    "insider_threat": "T1078",
    "phishing": "T1566",
    "malware_activity": "T1059",
}


def severity_from_probability(probability: float) -> str:
    """Explicit probability-to-severity banding."""
    if probability >= 0.85:
        return "critical"
    if probability >= 0.65:
        return "high"
    if probability >= 0.40:
        return "medium"
    return "low"


def _confidence(probability: float) -> str:
    if probability >= 0.85:
        return "high"
    if probability >= 0.50:
        return "medium"
    return "low"


def _evidence(name: str, description: str, observed: float) -> StageEvidence:
    return StageEvidence(
        name=name,
        description=description,
        observed_value=observed,
        direction="unknown",
        confidence=0.9,
    )


def _band_score(value: float, warn: float, alert: float) -> float:
    """0 below warn, linear warn→alert, 1.0 at/above alert."""
    if value >= alert:
        return 1.0
    if value <= warn:
        return 0.0
    return (value - warn) / (alert - warn)


class DeploymentBaseline(BaseModel):
    """Benign reference statistics for one deployment, learned offline.

    This exists because an **absolute** byte band cannot work across networks.
    Tuned on synthetic traffic, the known-edge band fires on 952 of 983 real
    CIC-IDS2017 windows, including 96.7% of benign ones, because real benign
    volume is roughly 149x the synthetic figure. No recalibration of an absolute
    threshold fixes that.

    A **rolling history** z-score was measured and rejected: lateral movement is
    a sustained condition, so a baseline computed from recent traffic rises
    along with the attack and the score collapses (best achievable TPR-FPR
    +0.108 on the synthetic corpus, against F1 0.945 for the band it replaced).
    See `research/ATTACK_DETECTION_REAL_DATA.md`.

    The fix is to learn the baseline from a *separate* reference period that
    contains no attack, and freeze it. A sustained attack then cannot raise its
    own baseline, because the baseline is not computed from the live history.
    This is the same discipline the threshold already uses: fit on validation,
    freeze, ship.
    """

    model_config = ConfigDict(extra="forbid")

    baseline_version: str = DEPLOYMENT_BASELINE_VERSION
    #: Median, not mean: measured on real CIC-IDS2017 the benign known-edge rate
    #: is 281,385 B/s with a standard deviation of 848,745 B/s - three times the
    #: mean. A mean/std baseline puts a 3-sigma cut above essentially all real
    #: traffic, which "fixes" the false-alert rate only by also dropping
    #: detection to near zero. Median absolute deviation is immune to the
    #: handful of bulk-transfer windows that make the distribution heavy-tailed.
    median_bytes_per_sec: float
    mad_bytes_per_sec: float
    samples: int = Field(ge=1)
    reference_label: str = "benign"
    #: robust sigmas above the deployment median at which the score reaches 1.0
    alert_sigma: float = Field(default=6.0, gt=0.0)
    warn_sigma: float = Field(default=3.0, gt=0.0)

    def robust_sigma(self, known_edge_bytes_per_sec: float) -> float:
        """Modified z-score against the reference median, via median absolute deviation.

        The 0.6745 factor rescales MAD to a standard-deviation equivalent under
        normality, so the sigma thresholds mean the same thing here as a
        classical z-score would.
        """
        if self.mad_bytes_per_sec <= 0.0:
            # A reference period with no spread cannot express "unusual" in
            # deviations; any rise above the median is then fully anomalous.
            return (
                0.0 if known_edge_bytes_per_sec <= self.median_bytes_per_sec else self.alert_sigma
            )
        return (
            0.6745 * (known_edge_bytes_per_sec - self.median_bytes_per_sec) / self.mad_bytes_per_sec
        )

    def score(self, known_edge_bytes_per_sec: float) -> float:
        """0 at or below the warn sigma, linear to 1.0 at the alert sigma."""
        sigma = self.robust_sigma(known_edge_bytes_per_sec)
        if sigma >= self.alert_sigma:
            return 1.0
        if sigma <= self.warn_sigma:
            return 0.0
        return (sigma - self.warn_sigma) / (self.alert_sigma - self.warn_sigma)


def fit_deployment_baseline(
    known_edge_rates: Sequence[float],
    *,
    reference_label: str = "benign",
    alert_sigma: float = 6.0,
    warn_sigma: float = 3.0,
) -> DeploymentBaseline:
    """Learn the benign reference band from a reference period known to be clean.

    ``known_edge_rates`` must come from windows verified benign **and disjoint
    from the evaluation period**. Feeding it live history reproduces the rejected
    rolling z-score, because a sustained attack contaminates its own baseline.
    """
    values = sorted(float(v) for v in known_edge_rates)
    if not values:
        raise ValueError("cannot fit a deployment baseline without reference windows")
    if not all(v >= 0.0 for v in values):
        raise ValueError("known-edge byte rates must be non-negative")
    med = median(values)
    return DeploymentBaseline(
        median_bytes_per_sec=med,
        mad_bytes_per_sec=median([abs(v - med) for v in values]),
        samples=len(values),
        reference_label=reference_label,
        alert_sigma=alert_sigma,
        warn_sigma=warn_sigma,
    )


def _zscore(current: float, history_values: list[float]) -> float:
    """z-score vs benign history; 0.0 when history is too short or degenerate."""
    if len(history_values) < MIN_HISTORY:
        return 0.0
    spread = pstdev(history_values)
    if spread == 0.0:
        return 0.0 if current == mean(history_values) else Z_SCALE
    return (current - mean(history_values)) / spread


def _affected_assets(
    state: NetworkState,
    history: tuple[NetworkState, ...],
    registry: dict[str, AssetRecord] | None,
) -> list[str]:
    """New actors vs history, plus registry-critical assets present now."""
    seen: set[str] = set()
    for prior in history:
        seen.update(prior.entities)
    fresh = [entity for entity in state.entities if entity not in seen]
    if registry:
        fresh.extend(
            asset_id
            for asset_id in state.entities
            if asset_id in registry and registry[asset_id].criticality == "critical"
        )
    return sorted(set(fresh))


@dataclass(frozen=True)
class DetectorContext:
    """Inputs shared by all detectors for one window.

    ``history`` is prior window states (oldest first), excluding the current
    one; it supplies benign baselines.
    """

    state: NetworkState
    history: tuple[NetworkState, ...] = field(default_factory=tuple)
    asset_registry: dict[str, AssetRecord] | None = None
    threat_feed: ThreatIntelFeed | None = None
    #: Offline benign reference for this deployment. Absent means "not fitted",
    #: which rules report as a warning rather than guessing a scale.
    deployment_baseline: DeploymentBaseline | None = None


@dataclass(frozen=True)
class DetectorSet:
    """Per-type alert thresholds; attack tempo differs, so thresholds do too."""

    ddos: float = 0.80
    recon: float = 0.80
    credential: float = 0.70
    lateral: float = 0.70
    exfil: float = 0.80
    insider: float = 0.70
    phishing: float = 0.60
    malware: float = 0.60


COLD_START_WARNING = (
    "benign history is too short for baseline z-scores — early windows are "
    f"scored conservatively (need >={MIN_HISTORY} prior windows for full sensitivity)"
)


def _finding(
    attack_type: str,
    ctx: DetectorContext,
    probability: float,
    evidence: list[StageEvidence],
    warnings: list[str],
    threshold: float,
) -> AttackFinding:
    if len(ctx.history) < MIN_HISTORY and COLD_START_WARNING not in warnings:
        warnings.append(COLD_START_WARNING)
    return AttackFinding(
        attack_type=attack_type,  # type: ignore[arg-type]
        probability=round(min(1.0, max(0.0, probability)), 3),
        severity=severity_from_probability(probability),
        confidence=_confidence(probability),
        is_alert=probability >= threshold,
        window_start=ctx.state.window_start,
        window_end=ctx.state.window_end,
        mitre_technique=MITRE[attack_type],
        affected_assets=_affected_assets(ctx.state, ctx.history, ctx.asset_registry),
        evidence=evidence,
        warnings=warnings,
        model_version=DETECTOR_VERSION,
    )


def _window_seconds(state: NetworkState) -> float:
    return max(1e-9, (state.window_end - state.window_start).total_seconds())


def _intel_verdict(ctx: DetectorContext):
    """Threat-intel check over the window's entities (None when no feed)."""
    if ctx.threat_feed is None:
        return None
    hosts = sorted(set(ctx.state.entities))
    hosts += [edge["destination"] for edge in ctx.state.edge_summary]
    return evaluate_hosts(ctx.threat_feed, hosts)


def detect_ddos(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Volumetric flood pattern from flow telemetry (flows/s and bytes/s z-scores).

    Honest scope note: the synthetic dataset contains no volumetric-flood
    scenario, so this detector is validated for quiet-on-benign only; any
    elevated score is flagged accordingly.
    """
    state, warnings = ctx.state, []
    seconds = _window_seconds(state)
    fps = state.features.get("flow_event_count", 0.0) / seconds
    bps = state.features.get("bytes", 0.0) / seconds
    hist_fps = [
        prior.features.get("flow_event_count", 0.0) / _window_seconds(prior)
        for prior in ctx.history
    ]
    hist_bps = [prior.features.get("bytes", 0.0) / _window_seconds(prior) for prior in ctx.history]
    z = max(_zscore(fps, hist_fps), _zscore(bps, hist_bps))
    probability = min(DDOS_CAP, max(0.0, z) / Z_SCALE)
    evidence = [_evidence("flows_per_second", "flow rate vs benign baseline", round(fps, 2))]
    if z >= Z_SCALE * 0.5:
        evidence.append(
            _evidence("bytes_per_second", "byte rate vs benign baseline", round(bps, 0))
        )
    if probability > 0.0:
        warnings.append(
            "flow-level volumetric pattern — flood sub-type classification "
            "(SYN/UDP/HTTP) requires packet-level telemetry"
        )
    if probability >= thresholds.ddos:
        warnings.append(
            "no volumetric-flood scenario exists in the validation data — this "
            "detector is validated for quiet-on-benign only"
        )
    if seconds > 10.0:
        warnings.append("volumetric DDoS tempo is underserved by windows >10s")
    return _finding("ddos", ctx, probability, evidence, warnings, thresholds.ddos)


def detect_recon(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Scan pattern from the SYN+RST probe share, not from volume.

    Every TCP flow carries syn_count=1, so a SYN ratio is meaningless. The score
    is the SYN+RST probe share of flows.

    The low-byte edge share and fan-out are reported as evidence only, and that
    is the original design rather than a retreat from it. Scoring the low-byte
    share worked on the synthetic corpus it was fitted on, and stopped working on
    real traffic: re-measured on 698 real benign CIC-IDS2017 windows the share
    sits at a median of 0.493, against a median of 0.500 on the 285 real attack
    windows, with the two distributions almost fully overlapping. The old
    0.10/0.30 band therefore put 692 of 698 real benign windows above its alert
    level, and reconnaissance fired on 981 of 983 real windows. Real benign
    traffic is legitimately probe-shaped - health checks, keep-alives, DNS, CDN
    edges, mobile chatter - and no threshold separates it. Evidence, not score.

    Consequence, stated rather than hidden: on real flow telemetry this detector
    is close to silent, because real attack windows carry an RST share of 0.000
    too. That is the honest state of the signal available in flow features.
    Detecting a real port scan needs the packet-level view, which the pcap
    ingestion path provides and this flow-only rule does not.
    """
    state = ctx.state
    flows = max(1.0, state.features.get("flow_event_count", 0.0))
    rst_ratio = min(1.0, state.features.get("rst_count", 0.0) / flows)
    probability = _band_score(rst_ratio, RST_RATIO_WARN, RST_RATIO_ALERT)
    # A share estimated from three flows is not a measurement. Before the v3
    # generator, benign windows were uniformly small and quiet, so a 20% RST
    # share implied probes; v3 benign windows include real health checks and
    # misconfigured clients, and a three-flow window is then unstable in both
    # directions. Require a sample before scoring the ratio at all.
    if flows < RST_RATIO_MIN_FLOWS:
        probability = 0.0
        warnings = [
            f"only {flows:.0f} flow(s) in this window — too few to estimate a probe "
            f"share (need >={RST_RATIO_MIN_FLOWS:.0f}); reconnaissance scored 0.0 "
            "rather than from an unstable ratio"
        ]
    else:
        warnings = []
    evidence = [
        _evidence("rst_probe_ratio", "SYN+RST probe share of flows", round(rst_ratio, 3)),
        _evidence(
            "low_byte_probes", "share of low-byte probe edges", round(_probe_score(state), 3)
        ),
        _evidence("max_source_fanout", "unique destinations from one source", _max_fanout(state)),
    ]
    return _finding("reconnaissance", ctx, probability, evidence, warnings, thresholds.recon)


def _max_fanout(state: NetworkState) -> int:
    """Unique destinations touched by any single source in this window."""
    per_source: dict[str, set[str]] = {}
    for edge in state.edge_summary:
        per_source.setdefault(edge["source"], set()).add(edge["destination"])
    return max((len(dests) for dests in per_source.values()), default=0)


def _probe_score(state: NetworkState) -> float:
    """Share of edges whose mean flow size is a low-byte probe."""
    edges = state.edge_summary
    if not edges:
        return 0.0
    probes = sum(
        1 for edge in edges if edge["count"] > 0 and edge["bytes"] / edge["count"] < PROBE_BYTES
    )
    return probes / len(edges)


def detect_credential(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Authentication failure pressure as failed auths per minute.

    **The window feature is a count, not a per-flow mean.** The old code read it
    as a mean, multiplied by the flow count, and labelled the result a rate:

        per_min = state.features["failed_auth"] * flows * 60 / window_seconds

    but ``state_builder`` aggregates it with ``Agg.SUM`` (``AGGREGATION_POLICY``
    maps ``failed_auth`` to ``failed_auth_sum``), so the multiplication counted
    every failure once per flow in the window. Measured on the fixture before
    this fix, a window containing **2** failed-auth events reported
    ``failed_auth_per_min = 26.0`` and saturated the finding at
    ``probability = 1.0``; any window with a single failure cleared the alert
    band. The band (1.0 warn, 2.0 alert) is a per-minute rate, and the window is
    already the time unit, so the flow count does not belong in the numerator.
    """
    state = ctx.state
    failures = state.features.get("failed_auth", 0.0)
    per_min = failures * 60.0 / _window_seconds(state)
    probability = _band_score(per_min, FAILED_AUTH_PER_MIN_WARN, FAILED_AUTH_PER_MIN_ALERT)
    warnings = []
    if per_min > 0.0:
        warnings.append(
            "flow telemetry exposes only aggregate failed-auth counts; per-edge "
            "auth-outcome telemetry would separate targeted brute force from "
            "benign lockouts"
        )
    evidence = [_evidence("failed_auth_per_min", "failed auths per minute", round(per_min, 2))]
    return _finding("credential_abuse", ctx, probability, evidence, warnings, thresholds.credential)


def detect_lateral(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Sustained volume on internal edges that history has already seen.

    **This rule used to score the opposite thing and measured the wrong
    quantity.** It scored bytes across internal edges *unseen* in the last
    ``LATERAL_LOOKBACK`` windows, on the premise that lateral movement shows up as
    new connections. Two measurements killed that premise:

    - Sprint 6 red-teamed the byte-count rule and found it evadable for free: send
      the same payload more slowly, every window stays under the band, cost 0
      bytes and 0.8 windows of dwell time.
    - The detector benchmark scored it at precision 0.194, recall 0.259, F1 0.222
      against 29 false positives - a narrow absolute band that is easy to sit
      under in both directions.

    Replacing the count with a *share* of window bytes, which is scale-invariant
    and therefore survives throttling, made it **worse**, not better: F1 0.123.
    The reason is the generator's own attack chain. Reconnaissance probes
    pre-register the internal edges that lateral movement later uses, so by the
    lateral phase most internal edges are *known*, while benign browsing keeps
    discovering genuinely new ones. Measured: benign new-edge share p50 0.185,
    lateral p50 0.048 - the quantity the old rule scored moved the wrong way.

    So the premise, not the threshold, was the bug. Volume on **known** internal
    edges separates the classes almost completely. Measured on the test split
    under the corrected harness:

        old rule (new-edge bytes):  precision 1.000  recall 0.185  F1 0.312
        new rule (known-edge bytes): precision 0.929  recall 0.963  F1 0.945

    The old rule was precise and nearly blind - it saw 5 of 27 lateral windows -
    and the precision 0.194 previously published for it was an artefact of the
    benchmark bug described in `scripts/run_detector_benchmark.py`, which counted
    the sequence detector's predictions as detections and put 29 of its own false
    alarms in this rule's bucket.

    Honest limit: this is still an absolute byte count, so throttling still
    evades it. `make bench-evasion` measures the current price: 14 of 16 attacking
    windows, about 0.50 extra windows of dwell time and no extra bandwidth, down
    from 0.80 before. The `rehearse_edge_one_window_early` evasion that defeated
    the old rule for free no longer works, because pre-warming an edge now hands
    the attacker one more known edge to be measured on.
    """
    lookback = ctx.history[-LATERAL_LOOKBACK:]
    prior_edges: set[tuple[str, str]] = set()
    for prior in lookback:
        prior_edges.update((edge["source"], edge["destination"]) for edge in prior.edge_summary)
    known_edges = [
        edge
        for edge in ctx.state.edge_summary
        if (edge["source"], edge["destination"]) in prior_edges
    ]
    known_bytes = sum(edge["bytes"] for edge in known_edges)
    known_bytes_per_sec = known_bytes / _window_seconds(ctx.state)
    new_edges = sum(
        1
        for edge in ctx.state.edge_summary
        if (edge["source"], edge["destination"]) not in prior_edges
    )
    # Cold start: with no baseline there are no known edges, so the score is
    # necessarily zero rather than accidentally high. Stated rather than capped,
    # because the new rule cannot fire on an empty history at all.
    cold = len(ctx.history) < MIN_HISTORY
    baseline = ctx.deployment_baseline
    warnings: list[str] = []
    if cold:
        probability = 0.0
        warnings.append(
            "benign history is too short to establish which internal edges are "
            "known — lateral movement is scored zero until a baseline exists"
        )
        sigma: float | None = None
    elif baseline is None:
        # No reference period for this deployment. The absolute band below is
        # tuned on synthetic volume and misfires badly on real networks, so it is
        # used only as a last resort and the gap is stated rather than hidden.
        probability = _band_score(
            known_bytes_per_sec,
            KNOWN_EDGE_BYTES_PER_SEC_WARN,
            KNOWN_EDGE_BYTES_PER_SEC_ALERT,
        )
        warnings.append(
            "no deployment baseline fitted — falling back to the synthetic absolute "
            f"band ({KNOWN_EDGE_BYTES_PER_SEC_WARN:g}-{KNOWN_EDGE_BYTES_PER_SEC_ALERT:g} B/s). "
            "On real traffic this band over-fires; fit a DeploymentBaseline from a clean "
            "reference period for this network."
        )
        sigma = None
    else:
        probability = baseline.score(known_bytes_per_sec)
        sigma = baseline.robust_sigma(known_bytes_per_sec)
    evidence = [
        _evidence(
            "known_internal_edges", "internal edges already seen in history", len(known_edges)
        ),
        _evidence("known_edge_bytes", "bytes on known internal edges", round(known_bytes, 0)),
        _evidence(
            "known_edge_bytes_per_sec",
            "known-edge byte rate, comparable across window lengths",
            round(known_bytes_per_sec, 1),
        ),
        _evidence("new_internal_edges", "internal edges unseen in history", new_edges),
    ]
    if baseline is not None:
        evidence.append(
            _evidence(
                "deployment_baseline_sigma",
                "robust sigmas above this deployment's own benign reference median",
                None if sigma is None else round(sigma, 2),
            )
        )
    return _finding("lateral_movement", ctx, probability, evidence, warnings, thresholds.lateral)


def detect_exfil(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Transfer-volume spike vs benign history (zone-aware once a registry exists).

    **A volume z-score is not trustworthy without a real baseline, and this rule
    now says so instead of guessing.** Window transfer volume is heavy-tailed:
    backups, exports and file pulls sit two orders of magnitude above a browse
    window. A z-score over the 3-6 windows the product actually supplies
    (``live.py`` passes ``history=3``) treats "a backup just ran" as an
    anomaly whenever the preceding minutes happened to be quiet, and silent
    whenever one of them was large. The synthetic data before ``v3`` never
    produced a large benign window, so this never showed up.

    So the z-score is reported as evidence and the rule stays sub-alert until a
    ``DeploymentBaseline`` is fitted for the network in question. This is the
    same posture ``detect_lateral`` takes when ``baseline is None``, applied to
    the second of the two volume rules that shared the flaw. An explicit
    threat-intel match still raises the finding, because that signal does not
    depend on a baseline.
    """
    state, warnings = ctx.state, []
    if ctx.asset_registry is None:
        warnings.append(
            "no asset registry — exfiltration scored on total transfer volume; "
            "external-zone routing unknown"
        )
    window_bytes = state.features.get("bytes", 0.0)
    z = _zscore(window_bytes, [prior.features.get("bytes", 0.0) for prior in ctx.history])
    z_part = min(1.0, max(0.0, z) / (Z_SCALE + 4.0))
    # The absolute floor is a cold-start aid only: with a benign baseline the
    # z-score decides, because busy-but-benign minutes can exceed the floor.
    floor = _band_score(window_bytes, EXFIL_BYTES_WARN, EXFIL_BYTES_ALERT)
    verdict = _intel_verdict(ctx)
    baseline = ctx.deployment_baseline
    if baseline is not None:
        probability = max(z_part, baseline.score(window_bytes / _window_seconds(ctx.state)))
    elif len(ctx.history) < MIN_HISTORY:
        probability = min(max(z_part, floor), 0.5)  # sub-alert without a baseline
        warnings.append(
            f"benign history is too short for a bytes baseline "
            f"(need >={MIN_HISTORY} windows) — absolute volume floor used, "
            "score capped sub-alert"
        )
    else:
        # Enough history for a z-score, but no per-network reference period, and
        # the volume distribution is heavy-tailed. Report the anomaly; do not
        # alert on it.
        probability = min(max(z_part, floor), 0.5)
        warnings.append(
            "no deployment baseline fitted — window volume is heavy-tailed, so a "
            "z-score over this many windows cannot separate a backup from a "
            "transfer. Score capped sub-alert; fit a DeploymentBaseline from a "
            "clean reference period for this network to enable alerting."
        )
    evidence = [
        _evidence("window_bytes", "total bytes transferred in window", round(window_bytes, 0))
    ]
    if z != 0.0:
        evidence.append(_evidence("bytes_zscore", "bytes vs benign baseline", round(z, 2)))
    if verdict is not None and verdict.known_malicious:
        probability = min(1.0, max(probability, 0.9))
        evidence.append(
            _evidence("intel_matches", "destinations on threat-intel lists", len(verdict.matches))
        )
        warnings.append(
            f"transfer involves hosts on feed '{verdict.feed}' — raised to reflect "
            "known-malicious destination"
        )
        if verdict.warning:
            warnings.append(verdict.warning)
    return _finding("exfiltration", ctx, probability, evidence, warnings, thresholds.exfil)


def detect_insider(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Behavioral deviation: transfer volume far outside this actor's baseline.

    Data-staging or hoarding shows as window bytes far above the recent
    benign baseline (same z-signal as exfiltration, scored at the stricter
    insider threshold). Time-of-day context is recorded as evidence but not
    scored: the synthetic baseline runs at a single UTC hour, so an off-hours
    signal there would be an artifact, not a finding.
    """
    state = ctx.state
    window_bytes = state.features.get("bytes", 0.0)
    z = _zscore(window_bytes, [prior.features.get("bytes", 0.0) for prior in ctx.history])
    probability = min(0.90, max(0.0, z) / Z_SCALE)
    hour = state.window_start.hour
    evidence = [
        _evidence("bytes_zscore", "transfer volume vs actor baseline", round(z, 2)),
        _evidence("window_hour_utc", "window start hour (UTC)", float(hour)),
    ]
    warnings = [
        "behavioral-baseline heuristic — insider threat needs identity and "
        "access telemetry for confirmation"
    ]
    if len(ctx.history) < MIN_HISTORY:
        probability = min(probability, 0.5)
        warnings.append(COLD_START_WARNING)
    return _finding("insider_threat", ctx, probability, evidence, warnings, thresholds.insider)


def detect_phishing(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """DNS-visible phishing/tunneling indicators; honest when DNS is absent.

    Email telemetry (headers, SPF/DKIM, click events) is the real phishing
    path and is not available here; with DNS proxy telemetry present, high-
    entropy long domains and flagged tunnel markers are the observable
    surrogate. Without any DNS features the detector reports disabled.
    """
    state = ctx.state
    features = state.features
    has_dns = "domain_length" in features or "dns_tunnel_marker" in features
    if not has_dns:
        return _finding(
            "phishing",
            ctx,
            0.0,
            [],
            [
                "phishing detection needs email telemetry (headers, URL reputation, "
                "click events); no DNS features in this window — detector disabled"
            ],
            thresholds.phishing,
        )
    domain_len = features.get("domain_length", 0.0)
    tunnel_share = features.get("dns_tunnel_marker", 0.0)
    probability = max(
        _band_score(domain_len, 25.0, 45.0),
        _band_score(tunnel_share, 0.10, 0.30),
    )
    evidence = [
        _evidence("mean_domain_length", "mean queried-domain length", round(domain_len, 1)),
        _evidence(
            "tunnel_marker_share", "share of DNS events flagged as tunnels", round(tunnel_share, 3)
        ),
    ]
    return _finding(
        "phishing",
        ctx,
        probability,
        evidence,
        ["DNS surrogate only — email telemetry required for confirmed phishing"],
        thresholds.phishing,
    )


def detect_c2_beacon(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """C2 scoring from sensor beacon scores or threat-intel matches.

    Two honest paths to a score: a sensor-supplied ``c2_beacon_score``, or a
    destination present in a loaded threat-intel feed (known-malicious host).
    With neither, the detector stays at 0.0 and says why.
    """
    state = ctx.state
    score = state.features.get("c2_beacon_score")
    verdict = _intel_verdict(ctx)
    if verdict is not None and verdict.known_malicious:
        probability = 0.85
        evidence = [
            _evidence("intel_matches", "destinations on threat-intel lists", len(verdict.matches))
        ]
        warnings = [
            f"matched threat-intel feed '{verdict.feed}' — list evidence, not proof of beaconing"
        ]
        if verdict.warning:
            warnings.append(verdict.warning)
        return _finding(
            "command_and_control", ctx, probability, evidence, warnings, thresholds.exfil
        )
    if score is None:
        return _finding(
            "command_and_control",
            ctx,
            0.0,
            [],
            [
                "C2 detection requires DNS/TLS metadata (beacon intervals, JA3/JA4, "
                "rare domains) not present in flow telemetry — finding disabled"
            ],
            thresholds.exfil,  # unused; probability never crosses any threshold
        )
    probability = _band_score(score, 0.30, 0.60)
    evidence = [_evidence("c2_beacon_score", "sensor-computed beaconing score", round(score, 3))]
    return _finding(
        "command_and_control",
        ctx,
        probability,
        evidence,
        ["beacon score is sensor-supplied — validate the sensor before trusting it"],
        thresholds.exfil,
    )


def detect_malware(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Endpoint process-execution burst from EDR-style event features.

    Sensors emit ``malware_process_executions`` per process-start event; the
    window total crosses the alert band at five or more executions. Without
    endpoint telemetry the detector reports disabled — flow data cannot see
    processes.

    The band is a plain count, and the feature is already a count:
    ``malware_process_executions`` has no entry in ``AGGREGATION_POLICY``, so
    ``state_builder`` sums it. The previous code named it ``mean_exec`` and
    multiplied by ``event_count``, reporting a per-window total inflated by the
    window's event count. Same defect as ``detect_credential``.
    """
    state = ctx.state
    total_exec = state.features.get("malware_process_executions")
    if total_exec is None:
        return _finding(
            "malware_activity",
            ctx,
            0.0,
            [],
            [
                "malware detection needs endpoint/process telemetry; flow features "
                "cannot observe process execution — finding disabled"
            ],
            thresholds.malware,
        )
    executions = total_exec
    probability = _band_score(executions, 2.0, 5.0)
    evidence = [
        _evidence("process_executions", "process-start events in window", round(executions, 0))
    ]
    return _finding(
        "malware_activity",
        ctx,
        probability,
        evidence,
        ["execution burst is a heuristic — confirm with file-hash reputation"],
        thresholds.malware,
    )


def _shannon_entropy(data: list[float]) -> float:
    """Shannon entropy of a value distribution (0.0 = uniform, log2(n) = max)."""
    import math
    from collections import Counter

    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def detect_entropy_anomaly(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Shannon entropy anomaly on byte-size distribution.

    Flags unusual byte-size patterns that z-score detectors miss.
    Endpoint-name entropy is not computed here because current
    NetworkState.edge_summary does not contain DNS query labels;
    byte-size distribution entropy is the only validated signal.
    """
    state, warnings = ctx.state, []

    # Byte-size distribution entropy
    byte_values = [
        edge.get("bytes", 0.0) for edge in state.edge_summary if edge.get("bytes", 0) > 0
    ]
    byte_entropy = _shannon_entropy(byte_values)

    # Baseline comparison
    hist_byte_entropy = []
    for prior in ctx.history:
        prior_bytes = [e.get("bytes", 0.0) for e in prior.edge_summary if e.get("bytes", 0) > 0]
        hist_byte_entropy.append(_shannon_entropy(prior_bytes))

    byte_z = _zscore(byte_entropy, hist_byte_entropy)

    # Anomaly = deviation from baseline
    probability = min(0.9, abs(byte_z) / (Z_SCALE * 0.8))

    evidence = [
        _evidence(
            "byte_entropy",
            "Shannon entropy of byte size distribution",
            round(byte_entropy, 3),
        ),
    ]

    warnings_list = list(warnings)
    if len(ctx.history) < MIN_HISTORY:
        warnings_list.append(COLD_START_WARNING)

    if abs(byte_z) > 1.5:
        direction = "increasing" if byte_z > 0 else "decreasing"
        evidence.append(
            StageEvidence(
                name="entropy_deviation",
                description=f"Byte entropy z-score: {byte_z:.2f} ({direction})",
                observed_value=round(byte_z, 2),
                direction=direction,
                confidence=0.8,
            )
        )

    return _finding(
        "reconnaissance",  # entropy anomaly is a recon/C2 indicator
        ctx,
        probability,
        evidence,
        warnings_list,
        thresholds.recon,
    )


def run_all_detectors(
    state: NetworkState,
    history: tuple[NetworkState, ...],
    thresholds: DetectorSet | None = None,
    asset_registry: dict[str, AssetRecord] | None = None,
    threat_feed: ThreatIntelFeed | None = None,
    deployment_baseline: DeploymentBaseline | None = None,
) -> tuple[AttackFinding, ...]:
    """Run every detector over one window state and return all findings.

    Includes both window-based detectors (ddos, recon, credential, lateral,
    c2, exfil, insider, phishing, malware) AND the sequence-prediction
    detector that fires on detection history patterns.
    """
    from sentinel.sequence_detector import detect_sequence_prediction

    active = thresholds or DetectorSet()
    ctx = DetectorContext(
        state=state,
        history=history,
        asset_registry=asset_registry,
        threat_feed=threat_feed,
        deployment_baseline=deployment_baseline,
    )
    findings: list[AttackFinding] = [
        detect_ddos(ctx, active),
        detect_recon(ctx, active),
        detect_credential(ctx, active),
        detect_lateral(ctx, active),
        detect_c2_beacon(ctx, active),
        detect_exfil(ctx, active),
        detect_insider(ctx, active),
        detect_phishing(ctx, active),
        detect_malware(ctx, active),
        detect_entropy_anomaly(ctx, active),
    ]

    # Sequence prediction: fires based on detection history, not current window
    # This is the key improvement — provides lead time by predicting what's
    # likely to happen next based on the sequence of past detections.
    recent_alerts = [f for f in findings if f.is_alert]
    if recent_alerts:
        prediction = detect_sequence_prediction(
            recent_alerts,
            lookahead=2,
            min_probability=0.30,
        )
        if prediction is not None:
            findings.append(prediction)

    return tuple(findings)
