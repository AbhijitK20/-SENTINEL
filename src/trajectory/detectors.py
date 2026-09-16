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

from dataclasses import dataclass, field
from statistics import mean, pstdev

from trajectory.schemas import AssetRecord, AttackFinding, NetworkState, StageEvidence
from trajectory.threat_intel import ThreatIntelFeed, evaluate_hosts

DETECTOR_VERSION = "detectors-v1"

# Explicit thresholds, measured on synthetic-recon-lateral-v2 (30s windows):
# benign max rst_ratio 0.000 / probe_share 0.000 / failed_auth 0.0 per min /
# new-edge bytes 20k, vs recon min rst_ratio 0.476 / probe_share 0.364 /
# failed_auth 2.0 per min, lateral new-edge bytes up to 81k. Benign rate
# z-scores reach 2.85, so rate detectors map z/6 and stay quiet on benign.
RST_RATIO_WARN = 0.10  # SYN+RST probe share of flows (recon signature)
RST_RATIO_ALERT = 0.30
PROBE_SHARE_WARN = 0.10  # share of low-byte (<PROBE_BYTES) edges
PROBE_SHARE_ALERT = 0.30
PROBE_BYTES = 200.0
PROBE_MIN_EDGES = 6.0  # a scan is many probe edges; a few tiny flows are not
FAILED_AUTH_PER_MIN_WARN = 1.0  # failed auths per minute, from mean x flows
FAILED_AUTH_PER_MIN_ALERT = 2.0
NEW_EDGE_BYTES_WARN = 25_000.0  # bytes on internal edges unseen in history
NEW_EDGE_BYTES_ALERT = 50_000.0
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
    """Scan pattern from probe behaviour, not fan-out volume.

    Every TCP flow carries syn_count=1, so a SYN ratio is meaningless; the
    measured separators are the SYN+RST probe share (benign 0.000, recon min
    0.476) and the low-byte edge share (benign 0.000, recon min 0.364).
    Fan-out is reported as evidence only.
    """
    state = ctx.state
    flows = max(1.0, state.features.get("flow_event_count", 0.0))
    rst_ratio = min(1.0, state.features.get("rst_count", 0.0) / flows)
    probe_share = _probe_score(state)
    # Low-byte probe share must be gated by edge count: benign chatter and
    # tiny keep-alives also fall under PROBE_BYTES, but a scan fans out across
    # many edges. One or two small flows are chatter, not reconnaissance.
    probe_gate = min(1.0, len(state.edge_summary) / PROBE_MIN_EDGES)
    probe_part = _band_score(probe_share, PROBE_SHARE_WARN, PROBE_SHARE_ALERT) * probe_gate
    probability = max(
        _band_score(rst_ratio, RST_RATIO_WARN, RST_RATIO_ALERT),
        probe_part,
    )
    evidence = [
        _evidence("rst_probe_ratio", "SYN+RST probe share of flows", round(rst_ratio, 3)),
        _evidence("low_byte_probes", "share of low-byte probe edges", round(probe_share, 3)),
        _evidence("max_source_fanout", "unique destinations from one source", _max_fanout(state)),
    ]
    return _finding("reconnaissance", ctx, probability, evidence, [], thresholds.recon)


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

    The window feature is a mean per flow; multiplying by flow count converts
    it to a rate (benign 0.0/min, recon-phase min 2.0/min on validation data).
    """
    state = ctx.state
    mean_failed = state.features.get("failed_auth", 0.0)
    flows = state.features.get("flow_event_count", 0.0)
    per_min = mean_failed * flows * 60.0 / _window_seconds(state)
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
    """Volume moving across internal edges unseen in recent history.

    Edges are compared against a bounded lookback (LATERAL_LOOKBACK windows),
    not all history: recon-phase probes pre-register the very edges lateral
    movement later uses, so unbounded history suppresses the signal. New-edge
    counts overlap between benign browsing and lateral hops (benign max 4,
    lateral max 5 on validation data), so the count is evidence only; the
    score keys on bytes across new edges (benign max 20k, lateral up to 81k).
    """
    lookback = ctx.history[-LATERAL_LOOKBACK:]
    prior_edges: set[tuple[str, str]] = set()
    for prior in lookback:
        prior_edges.update((edge["source"], edge["destination"]) for edge in prior.edge_summary)
    new_edges = [
        edge
        for edge in ctx.state.edge_summary
        if (edge["source"], edge["destination"]) not in prior_edges
    ]
    new_bytes = sum(edge["bytes"] for edge in new_edges)
    probability = _band_score(new_bytes, NEW_EDGE_BYTES_WARN, NEW_EDGE_BYTES_ALERT)
    warnings: list[str] = []
    # "New edge" is defined against history: with no baseline every edge looks
    # new, so cold-start windows are capped sub-alert (busy benign minutes
    # would otherwise alert).
    if len(ctx.history) < MIN_HISTORY:
        probability = min(probability, 0.5)
        warnings.append(
            "benign history is too short for a new-edge baseline — lateral "
            "movement is scored conservatively until a baseline exists"
        )
    evidence = [
        _evidence("new_internal_edges", "internal edges unseen in history", len(new_edges)),
        _evidence("new_edge_bytes", "bytes on new internal edges", round(new_bytes, 0)),
    ]
    return _finding("lateral_movement", ctx, probability, evidence, warnings, thresholds.lateral)


def detect_exfil(ctx: DetectorContext, thresholds: DetectorSet) -> AttackFinding:
    """Transfer-volume spike vs benign history (zone-aware once a registry exists)."""
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
    if len(ctx.history) < MIN_HISTORY:
        probability = min(max(z_part, floor), 0.5)  # sub-alert without a baseline
        warnings.append(
            f"benign history is too short for a bytes baseline "
            f"(need >={MIN_HISTORY} windows) — absolute volume floor used, "
            "score capped sub-alert"
        )
    else:
        probability = z_part
    evidence = [
        _evidence("window_bytes", "total bytes transferred in window", round(window_bytes, 0))
    ]
    if z != 0.0:
        evidence.append(_evidence("bytes_zscore", "bytes vs benign baseline", round(z, 2)))
    verdict = _intel_verdict(ctx)
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
    window total (mean x event count) crosses the alert band at five or more
    executions. Without endpoint telemetry the detector reports disabled —
    flow data cannot see processes.
    """
    state = ctx.state
    mean_exec = state.features.get("malware_process_executions")
    if mean_exec is None:
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
    executions = mean_exec * state.features.get("event_count", 1.0)
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


def run_all_detectors(
    state: NetworkState,
    history: tuple[NetworkState, ...],
    thresholds: DetectorSet | None = None,
    asset_registry: dict[str, AssetRecord] | None = None,
    threat_feed: ThreatIntelFeed | None = None,
) -> tuple[AttackFinding, ...]:
    """Run every detector over one window state and return all findings.

    Includes both window-based detectors (ddos, recon, credential, lateral,
    c2, exfil, insider, phishing, malware) AND the sequence-prediction
    detector that fires on detection history patterns.
    """
    from trajectory.sequence_detector import detect_sequence_prediction

    active = thresholds or DetectorSet()
    ctx = DetectorContext(
        state=state, history=history, asset_registry=asset_registry, threat_feed=threat_feed
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
