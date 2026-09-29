# SPDX-License-Identifier: Apache-2.0
"""Synthetic scenario generator for SENTINEL.

Three properties make this replay data useful for a world model rather than a
flow classifier:

**Both telemetry levels.** Every connection is emitted twice: once as a ``flow``
event (aggregate counters) and once as a ``packet`` event (IP/TCP header values).
That mirrors how a capture actually reaches a sensor, and it is the only way the
packet-level features the problem statement asks for — TTL spread, TCP window
size, fragmentation, retransmissions, payload distribution — can be model inputs
instead of dead columns.

**Dwell time.** An infiltration does not switch on in one window. Each stage
ramps over several windows, and the attack is preceded by a *low-and-slow*
precursor that is invisible to flow-rate thresholds and visible only in packet
shape. Labels stay honest: precursor windows are labelled ``Benign`` because the
kill chain has not started, so a model earns lead time by recognising the
precursor, not by being handed the answer.

**Class overlap (v3).** ``v2`` drew each phase from its own disjoint band of
byte volumes, port sets, destination hosts and TCP flag combinations. The
infiltration label was therefore recoverable from one scalar: on ``v2`` a
logistic regression over 98 features scored ROC-AUC 0.9933 on the test split,
while a *single* feature (``flag_psh_ratio``) scored 0.9861 — a gap of 0.0072.
Ninety-seven of ninety-eight features were decoration.

``v3`` keeps the phases semantically distinct but stops letting volume carry the
label:

* Benign traffic is a mixture, not a single small band. It includes bulk
  transfers (backups, exports) whose byte volume overlaps the lateral phase, and
  established sessions that set PSH, which ``v2`` reserved for the attack.
* The lateral phase draws from a wide log-normal band that reaches *below* the
  benign median, and a quarter of its transfers are deliberately quiet.
* Every phase draws destinations from the full host pool, so ``server-03`` is
  no longer a lateral-only host.
* Port pools overlap. Business ports, service ports and probe ports all appear
  across phases; the distinguishing feature is the *fan-out per connection*, not
  which port was touched.
* Phase lengths, connection counts and transfer sizes are drawn per scenario, so
  no window index means the same thing in two scenarios and an attack window can
  be quieter than a benign one.

The signal that survives is structural, and it is the one that actually
separates the stages in real traffic: reconnaissance is many distinct
destinations per connection, short-lived and unacknowledged; lateral movement is
few ports, established sessions, and sustained internal-to-internal transfer.

Stage design:
  benign -> precursor (low-and-slow probing) -> recon (scan ramp)
  -> lateral (transfer ramp)

Precursor signature (deliberately below flow thresholds):
  high IAT and IAT variance, wide destination-port fan-out, near-zero bytes,
  jittered TTL, small TCP windows, occasional retransmissions.
"""

from __future__ import annotations

import math
import random
from datetime import UTC, datetime, timedelta

from sentinel.schemas import NetworkState, StateLabel, UnifiedEvent
from sentinel.state_builder import build_network_states
from sentinel.targets import LabelledState, make_state_key

#: v3 changes the per-phase distributions. Bumped so a v2-trained artifact is
#: never silently applied to v3 windows.
DATASET_ID = "synthetic-recon-lateral-v3"
INTERNAL_HOSTS = [f"host-{index:02d}" for index in range(1, 9)]
SERVERS = ["auth-service", "server-03", "file-server", "web-proxy"]

# Benign desktop/server TCP windows seen in the wild; the slow scan uses small
# ones, which is a packet-shape signal a flow rate threshold cannot see.
BENIGN_WINDOWS = (64240.0, 65535.0, 29200.0, 8192.0)
SCAN_WINDOWS = (1024.0, 2920.0, 5840.0)
# Don't Fragment set, as an integer IP flags word.
DF_FLAG = 0x4000

# Ports appear in more than one phase. A port is not a stage label; the number
# of distinct destinations per connection is.
BUSINESS_PORTS = (80, 443, 53, 8443, 8080, 3306, 5432, 5900)
SERVICE_PORTS = (22, 88, 135, 139, 445, 1433, 3389)
PROBE_PORTS = (21, 23, 993, 1434, 2049, 3128, 5222, 6379, 9200)

# TCP flag words.
SYN_ACK = 2 | 16
SYN_ACK_PSH = 2 | 16 | 8
SYN_ACK_FIN = 2 | 16 | 1
SYN_RST = 2 | 4
SYN_ACK_RST = 2 | 16 | 4


def _log_normal_bytes(rng: random.Random, median: float, sigma: float, lo: float, hi: float):
    """Draw a positive, heavy-tailed size.

    Real transfer sizes are not uniform: a log-normal keeps the tail fat enough
    that a "normal" window can look like an attack window and back.
    """
    return float(min(hi, max(lo, math.exp(rng.gauss(math.log(median), sigma)))))


def generate_scenario_events(
    scenario_id: str,
    *,
    seed: int,
    benign_minutes: int = 20,
    recon_minutes: int = 8,
    lateral_minutes: int = 8,
    precursor_minutes: int = 4,
    start: datetime | None = None,
) -> tuple[list[UnifiedEvent], dict[str, datetime]]:
    """Generate one scenario's flow events with precursor signals.

    Args:
        precursor_minutes: Minutes of low-rate probing mixed into the
            benign phase *before* the recon label begins.  These are
            genuine early-warning signals the model can learn; they are
            labelled "Benign" to maintain label honesty (the attack
            hasn't started yet).

    Returns:
        (events, boundaries) where boundaries has recon_start and
        lateral_start timestamps used for labelling.
    """
    if min(benign_minutes, recon_minutes, lateral_minutes) < 1:
        raise ValueError("every phase must last at least one minute")
    if precursor_minutes >= benign_minutes:
        precursor_minutes = max(1, benign_minutes // 3)

    rng = random.Random(f"{DATASET_ID}:{scenario_id}:{seed}")
    origin = start or datetime(2026, 1, 1, tzinfo=UTC)
    attacker = rng.choice(INTERNAL_HOSTS)
    events: list[UnifiedEvent] = []
    counter = 0

    # Nuisance parameters for this scenario, drawn before any phase runs. They
    # are independent of the stage schedule on purpose: how busy a network is,
    # and how long each stage lasts, must not predict the label. v2 fixed every
    # phase length for every scenario, so window index was a label proxy.
    benign_len = max(3, int(rng.gauss(benign_minutes, benign_minutes * 0.22)))
    recon_len = max(2, int(rng.gauss(recon_minutes, recon_minutes * 0.30)))
    lateral_len = max(2, int(rng.gauss(lateral_minutes, lateral_minutes * 0.30)))
    prec_len = max(1, min(precursor_minutes, benign_len - 1))
    # This scenario's overall load. Scales benign *and* attack volume, so a busy
    # scenario is busy during its benign phase too.
    load = max(0.35, rng.gauss(1.0, 0.28))
    # How often a benign window happens to contain a bulk transfer. Without
    # this, "big window" and "infiltration" are the same event.
    bulk_rate = rng.uniform(0.10, 0.38)
    # How often a lateral transfer is quiet enough to look ordinary. Real
    # lateral movement that only reads a file is small.
    stealth_rate = rng.uniform(0.15, 0.45)
    # Benign connection volume, widened so an attack window can be quieter than
    # a benign one.
    benign_lo, benign_hi = int(4 * load), int(11 * load)

    def emit(
        ts: datetime,
        src: str,
        dst: str,
        *,
        dport: int,
        nbytes: float,
        packets: float,
        flags: int,
        failed_auth: float = 0.0,
        slow_scan: bool = False,
    ) -> None:
        """Emit one connection as a flow event plus its packet-level evidence.

        ``slow_scan`` marks a low-and-slow probe: the flow counters stay inside
        benign rate limits, while the packet header values (jittered TTL, small
        window, retransmissions, no DF) carry the evasion signal.
        """
        nonlocal counter
        counter += 1
        iat = max(0.001, rng.gauss(2.4 if slow_scan else 0.1, 0.9 if slow_scan else 0.03))
        events.append(
            UnifiedEvent(
                event_id=f"{scenario_id}:{counter}",
                timestamp=ts,
                source_entity=src,
                destination_entity=dst,
                event_type="flow",
                features={
                    "source_port": float(rng.randint(40000, 60000)),
                    "destination_port": float(dport),
                    "protocol": 6.0,
                    "bytes": nbytes,
                    "packets": packets,
                    "duration": max(0.05, rng.gauss(1.0, 0.3)),
                    "tcp_flags": float(flags),
                    "syn_count": 1.0,
                    "ack_count": max(0.0, packets - 1.0),
                    "rst_count": 1.0 if flags & 4 else 0.0,
                    "iat_mean": iat,
                    "iat_variance": max(0.0, rng.gauss(1.8 if slow_scan else 0.01, 0.4)),
                    "bidirectional_ratio": min(1.0, max(0.0, rng.gauss(0.7, 0.1))),
                    "failed_auth": failed_auth,
                },
                source_format="replay",
                provenance=f"{DATASET_ID}:{scenario_id}",
            )
        )
        events.append(_packet_event(counter, ts, src, dst, dport, nbytes, flags, slow_scan))

    def _packet_event(
        number: int,
        ts: datetime,
        src: str,
        dst: str,
        dport: int,
        nbytes: float,
        flags: int,
        slow_scan: bool,
    ) -> UnifiedEvent:
        """Packet-level evidence for one connection.

        TTL is per-host stable except during a slow scan, where the attacker
        varies it; segmentation caps payload per packet at 1460 bytes, so a
        60 kB transfer shows up as many packets with a narrow payload size.
        """
        host_ttl = 128 if src.startswith("server") or src == "auth-service" else 64
        ttl = float(rng.choice((48, 52, 56, 61, 64))) if slow_scan else float(host_ttl)
        # One packet in eight is a retransmission, and slow scans fragment.
        retransmitted = 1.0 if counter % 8 == 0 else 0.0
        fragmented = 0.0 if slow_scan and counter % 4 else float(DF_FLAG)
        return UnifiedEvent(
            event_id=f"{scenario_id}:{counter}p",
            timestamp=ts + timedelta(milliseconds=counter % 5),
            source_entity=src,
            destination_entity=dst,
            event_type="packet",
            features={
                "ttl": ttl,
                "tcp_window_size": float(rng.choice(SCAN_WINDOWS if slow_scan else BENIGN_WINDOWS)),
                "fragment_flags": fragmented,
                "frag_offset": 0.0 if counter % 3 else float(rng.choice((1480, 2960))),
                "payload_size": min(float(nbytes), 1460.0),
                "retransmission": retransmitted,
                "tcp_flags": float(flags),
                "protocol": 6.0,
                "source_port": float(rng.randint(40000, 60000)),
                "destination_port": float(dport),
            },
            source_format="replay",
            provenance=f"{DATASET_ID}:{scenario_id}",
        )

    minute = 0

    # --- Phase 1: Benign + low-and-slow precursor ----------------------
    # The precursor deliberately stays *below* any flow-rate threshold: few
    # connections per minute, near-zero bytes, spread over minutes. What gives
    # it away is packet shape — jittered TTL, small windows, retransmissions,
    # wide port fan-out — which is why the observation carries both levels.
    precursor_start_minute = max(1, benign_len - prec_len)
    for minute_idx in range(benign_len):
        ts = origin + timedelta(minutes=minute_idx)
        _benign_minute(
            rng,
            emit,
            ts,
            lo=benign_lo,
            hi=benign_hi,
            bulk_rate=bulk_rate,
        )

        if minute_idx >= precursor_start_minute:
            progress = (minute_idx - precursor_start_minute + 1) / prec_len
            # Two to six probes a minute, rising across the precursor: still far
            # below the benign connection count.
            probe_count = 2 + int(progress * rng.randint(2, 5))
            # Each probe sweeps a fresh port, so destination-port entropy climbs
            # while bytes per connection stay negligible.
            ports = rng.sample(
                [22, 23, 80, 135, 139, 445, 1433, 3306, 3389, 5432, 5900, 8080, 8443],
                k=probe_count,
            )
            for port in ports:
                emit(
                    ts + timedelta(seconds=rng.uniform(0, 55)),
                    attacker,
                    rng.choice(INTERNAL_HOSTS + SERVERS),
                    dport=port,
                    nbytes=float(rng.randint(40, 120)),
                    packets=2.0,
                    flags=SYN_RST,
                    slow_scan=True,
                )
            for _ in range(int(progress * rng.randint(1, 3))):
                emit(
                    ts + timedelta(seconds=rng.uniform(0, 55)),
                    attacker,
                    "auth-service",
                    dport=88,
                    nbytes=180.0,
                    packets=3.0,
                    flags=SYN_ACK_RST,
                    failed_auth=1.0,
                    slow_scan=True,
                )
        minute += 1

    # --- Phase 2: Reconnaissance (formal label starts here) ----------
    # Dwell time: the scan ramps over its own minutes instead of appearing at
    # full intensity in the first window, so a trajectory is genuinely gradual.
    recon_start = origin + timedelta(minutes=minute)
    for recon_index in range(recon_len):
        ts = origin + timedelta(minutes=minute)
        _benign_minute(rng, emit, ts, lo=benign_lo, hi=benign_hi, bulk_rate=bulk_rate)
        ramp = 0.45 + 0.55 * (recon_index + 1) / recon_len
        # Wide fan-out per connection: the structural signal, and the reason a
        # port list alone cannot label this phase.
        for probe in range(max(2, int(rng.randint(9, 18) * ramp * load))):
            emit(
                ts + timedelta(seconds=probe * 3),
                attacker,
                rng.choice(INTERNAL_HOSTS + SERVERS),
                # Mostly fresh ports, but drawn from the shared pools so no port
                # is exclusive to recon.
                dport=rng.choice(tuple(BUSINESS_PORTS) + tuple(SERVICE_PORTS) + tuple(PROBE_PORTS)),
                # Probes are short, but the upper tail overlaps an ordinary
                # benign session so "small window" is not a label.
                nbytes=_log_normal_bytes(rng, median=140.0, sigma=0.95, lo=40.0, hi=9_000.0),
                packets=float(rng.randint(2, 6)),
                flags=SYN_RST,
            )
        for attempt in range(max(1, int(rng.randint(2, 5) * ramp))):
            emit(
                ts + timedelta(seconds=30 + attempt * 4),
                attacker,
                "auth-service",
                dport=88,
                nbytes=_log_normal_bytes(rng, median=220.0, sigma=0.6, lo=90.0, hi=1_200.0),
                packets=float(rng.randint(2, 5)),
                flags=SYN_ACK_RST,
                failed_auth=1.0,
            )
        minute += 1

    # --- Phase 3: Lateral movement -----------------------------------
    lateral_start = origin + timedelta(minutes=minute)
    for lateral_index in range(lateral_len):
        ts = origin + timedelta(minutes=minute)
        _benign_minute(rng, emit, ts, lo=benign_lo, hi=benign_hi, bulk_rate=bulk_rate)
        # Exfiltration ramps too: the first lateral minutes move less data.
        ramp = 0.4 + 0.6 * (lateral_index + 1) / lateral_len
        for hop in range(max(1, int(rng.randint(3, 7) * ramp * load))):
            stealth = rng.random() < stealth_rate
            if stealth:
                # A lateral hop that reads a file and leaves. Ordinary-sized.
                nbytes = _log_normal_bytes(rng, median=2_600.0, sigma=0.7, lo=300.0, hi=12_000.0)
            else:
                nbytes = _log_normal_bytes(
                    rng, median=34_000.0, sigma=1.05, lo=4_000.0, hi=220_000.0
                )
            # Destinations come from the whole pool, including the hosts the
            # benign phase already talks to.
            dst = rng.choice(INTERNAL_HOSTS + SERVERS)
            # Not every lateral hop pushes data with PSH: service creation,
            # credential use and remote exec ride an established session without
            # it. Only the bulk-transfer path is PSH-dominated.
            if stealth or rng.random() < 0.40:
                flags = SYN_ACK if rng.random() < 0.6 else SYN_ACK_FIN
            else:
                flags = SYN_ACK_PSH
            emit(
                ts + timedelta(seconds=hop * 7),
                attacker,
                dst,
                # Few distinct ports, the structural opposite of recon.
                dport=rng.choice((445, 3389, 5985, 22, 1433)),
                nbytes=nbytes,
                # Packet count follows the transfer size with spread, so it is
                # not an independent label proxy.
                packets=max(2.0, nbytes / float(rng.randint(700, 1_400))),
                flags=flags,
            )
        minute += 1

    events.sort(key=lambda event: event.timestamp)
    return events, {"recon_start": recon_start, "lateral_start": lateral_start}


def generate_labelled_states(
    scenario_ids: list[str],
    *,
    seed: int,
    window_seconds: int,
    stride_seconds: int,
    benign_minutes: int = 20,
    recon_minutes: int = 8,
    lateral_minutes: int = 8,
    precursor_minutes: int = 4,
) -> list[LabelledState]:
    """Generate windowed, labelled states for several independent scenarios.

    The phase lengths are forwarded so a caller can generate the *same* attack
    family at different intensities. That is what makes a drift experiment
    possible without bolting noise onto a feature vector: shorten ``lateral_minutes``
    and the attacker is doing the same thing faster and quieter, which is a shift
    in the covariate distribution rather than a different dataset.
    """
    if not scenario_ids:
        raise ValueError("at least one scenario id is required")
    labelled: list[LabelledState] = []
    for offset, scenario_id in enumerate(scenario_ids):
        start = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=offset)
        events, boundaries = generate_scenario_events(
            scenario_id,
            seed=seed,
            start=start,
            benign_minutes=benign_minutes,
            recon_minutes=recon_minutes,
            lateral_minutes=lateral_minutes,
            precursor_minutes=precursor_minutes,
        )
        states = build_network_states(
            events, window_seconds=window_seconds, stride_seconds=stride_seconds
        )
        for index, state in enumerate(states):
            labelled.append(_label_state(state, index, scenario_id, boundaries))
    return labelled


def _label_state(
    state: NetworkState, index: int, scenario_id: str, boundaries: dict[str, datetime]
) -> LabelledState:
    """Label windows with attack stage; precursor windows remain "Benign".

    The precursor signals (low-rate probing during the benign phase) are
    intentionally NOT labelled as Reconnaissance — the attack hasn't
    officially started.  This is honest labelling: the model's job is to
    fire on precursor signals *before* the recon label appears.
    """
    last_instant = state.window_end
    if last_instant > boundaries["lateral_start"]:
        stage, infiltration = "Lateral Movement", True
    elif last_instant > boundaries["recon_start"]:
        stage, infiltration = "Reconnaissance", False
    else:
        stage, infiltration = "Benign", False
    key = make_state_key(state, index)
    return LabelledState(
        state_key=key,
        scenario_id=scenario_id,
        state=state,
        label=StateLabel(
            state_key=key,
            scenario_id=scenario_id,
            infiltration=infiltration,
            attack_stage=stage,
            label_source="derived",
        ),
    )


def _benign_minute(
    rng: random.Random,
    emit,
    ts: datetime,
    *,
    lo: int = 6,
    hi: int = 12,
    bulk_rate: float = 0.0,
) -> None:
    """Emit one minute of ordinary traffic.

    A mixture, deliberately, because ordinary traffic is not one shape:

    * ``browse`` — small request/response pairs on web and business ports.
    * ``api`` — mid-sized calls, some with PSH set. v2 reserved PSH for the
      attack phase, which made ``flag_psh_ratio`` a single-feature label at
      ROC-AUC 0.986. Real established sessions set it; so does this one.
    * ``bulk`` — a backup or export whose byte volume overlaps the lateral
      phase. This is the reason a big window is no longer an attack window.
    * ``probe`` — an unacknowledged SYN+RST from a health check, a port sweep
      from another tool, or a misconfigured client. Reconnaissance is not the
      only thing that fans out across ports.

    Destinations come from the full host pool, so no host identifies a stage.
    Arrival times are jittered inside the minute and occasionally cluster, so
    window boundaries do not align with traffic edges.
    """
    count = rng.randint(max(1, lo), max(lo + 1, hi))
    # A bulk transfer is a per-window event, not a per-connection one. Applied
    # per connection it fired in almost every window, which is not how a network
    # behaves and which flattened the volume signal the detectors read.
    bulk_window = rng.random() < bulk_rate
    for _ in range(count):
        roll = rng.random()
        # One burst per minute carries a cluster of connections.
        burst = rng.random() < 0.22
        offset = rng.uniform(0, 8) if burst else rng.uniform(0, 59)
        src = rng.choice(INTERNAL_HOSTS)
        dst = rng.choice(SERVERS + INTERNAL_HOSTS)
        if bulk_window and roll < 0.34:
            nbytes = _log_normal_bytes(rng, median=110_000.0, sigma=0.95, lo=12_000.0, hi=900_000.0)
            emit(
                ts + timedelta(seconds=offset),
                src,
                dst,
                dport=rng.choice((445, 22, 1433, 5432)),
                nbytes=nbytes,
                packets=max(2.0, nbytes / float(rng.randint(800, 1_400))),
                flags=SYN_ACK_PSH,
            )
        elif roll < 0.62:
            # Most established data transfers set PSH. v2 set PSH only in the
            # attack phase, which made flag_psh_ratio a single-feature label at
            # ROC-AUC 0.986; ordinary sessions set it too.
            emit(
                ts + timedelta(seconds=offset),
                src,
                dst,
                dport=rng.choice(BUSINESS_PORTS),
                nbytes=_log_normal_bytes(rng, median=9_000.0, sigma=1.05, lo=300.0, hi=260_000.0),
                packets=float(rng.randint(6, 220)),
                flags=SYN_ACK_PSH if rng.random() < 0.72 else SYN_ACK,
            )
        elif roll < 0.652:
            emit(
                ts + timedelta(seconds=offset),
                src,
                rng.choice(INTERNAL_HOSTS + SERVERS),
                dport=rng.choice(PROBE_PORTS),
                nbytes=_log_normal_bytes(rng, median=110.0, sigma=0.8, lo=35.0, hi=1_800.0),
                packets=2.0,
                flags=SYN_RST,
            )
        else:
            emit(
                ts + timedelta(seconds=offset),
                src,
                dst,
                dport=rng.choice(BUSINESS_PORTS),
                nbytes=_log_normal_bytes(rng, median=2_600.0, sigma=0.95, lo=120.0, hi=60_000.0),
                packets=float(rng.randint(3, 90)),
                flags=SYN_ACK_FIN if rng.random() < 0.3 else SYN_ACK,
            )
