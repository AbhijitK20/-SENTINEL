# SPDX-License-Identifier: Apache-2.0
"""Synthetic scenario generator for SENTINEL.

Two properties make this replay data useful for a world model rather than a
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

Stage design:
  benign -> precursor (low-and-slow probing) -> recon (scan ramp)
  -> lateral (transfer ramp)

Precursor signature (deliberately below flow thresholds):
  high IAT and IAT variance, wide destination-port fan-out, near-zero bytes,
  jittered TTL, small TCP windows, occasional retransmissions.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from sentinel.schemas import NetworkState, StateLabel, UnifiedEvent
from sentinel.state_builder import build_network_states
from sentinel.targets import LabelledState, make_state_key

DATASET_ID = "synthetic-recon-lateral-v2"
INTERNAL_HOSTS = [f"host-{index:02d}" for index in range(1, 9)]
SERVERS = ["auth-service", "server-03", "file-server", "web-proxy"]

# Benign desktop/server TCP windows seen in the wild; the slow scan uses small
# ones, which is a packet-shape signal a flow rate threshold cannot see.
BENIGN_WINDOWS = (64240.0, 65535.0, 29200.0, 8192.0)
SCAN_WINDOWS = (1024.0, 2920.0, 5840.0)
# Don't Fragment set, as an integer IP flags word.
DF_FLAG = 0x4000


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
    precursor_start_minute = max(1, benign_minutes - precursor_minutes)
    for minute_idx in range(benign_minutes):
        ts = origin + timedelta(minutes=minute_idx)
        _benign_minute(rng, emit, ts)

        if minute_idx >= precursor_start_minute:
            progress = (minute_idx - precursor_start_minute + 1) / precursor_minutes
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
                    flags=2 | 4,  # SYN + RST
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
                    flags=2 | 16 | 4,
                    failed_auth=1.0,
                    slow_scan=True,
                )
        minute += 1

    # --- Phase 2: Reconnaissance (formal label starts here) ----------
    # Dwell time: the scan ramps over its own minutes instead of appearing at
    # full intensity in the first window, so a trajectory is genuinely gradual.
    recon_start = origin + timedelta(minutes=minute)
    for recon_index in range(recon_minutes):
        ts = origin + timedelta(minutes=minute)
        _benign_minute(rng, emit, ts)
        ramp = 0.45 + 0.55 * (recon_index + 1) / recon_minutes
        for probe in range(max(2, int(rng.randint(12, 20) * ramp))):
            emit(
                ts + timedelta(seconds=probe * 3),
                attacker,
                rng.choice(INTERNAL_HOSTS + SERVERS),
                dport=rng.choice([22, 135, 139, 445, 3389, 8080]),
                nbytes=float(rng.randint(60, 200)),
                packets=2.0,
                flags=2 | 4,  # SYN + RST
            )
        for attempt in range(max(1, int(rng.randint(3, 6) * ramp))):
            emit(
                ts + timedelta(seconds=30 + attempt * 4),
                attacker,
                "auth-service",
                dport=88,
                nbytes=180.0,
                packets=3.0,
                flags=2 | 16 | 4,
                failed_auth=1.0,
            )
        minute += 1

    # --- Phase 3: Lateral movement -----------------------------------
    lateral_start = origin + timedelta(minutes=minute)
    for lateral_index in range(lateral_minutes):
        ts = origin + timedelta(minutes=minute)
        _benign_minute(rng, emit, ts)
        # Exfiltration ramps too: the first lateral minutes move less data.
        ramp = 0.4 + 0.6 * (lateral_index + 1) / lateral_minutes
        for hop in range(max(1, int(rng.randint(4, 8) * ramp))):
            emit(
                ts + timedelta(seconds=hop * 7),
                attacker,
                "server-03" if hop % 2 == 0 else rng.choice(INTERNAL_HOSTS),
                dport=rng.choice([445, 3389, 5985]),
                nbytes=float(rng.randint(20_000, 80_000) * ramp),
                packets=float(rng.randint(40, 120)),
                flags=2 | 16 | 8,  # SYN + ACK + PSH
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
) -> list[LabelledState]:
    """Generate windowed, labelled states for several independent scenarios."""
    if not scenario_ids:
        raise ValueError("at least one scenario id is required")
    labelled: list[LabelledState] = []
    for offset, scenario_id in enumerate(scenario_ids):
        start = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(days=offset)
        events, boundaries = generate_scenario_events(scenario_id, seed=seed, start=start)
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


def _benign_minute(rng: random.Random, emit, ts: datetime) -> None:
    for _ in range(rng.randint(6, 12)):
        emit(
            ts + timedelta(seconds=rng.uniform(0, 59)),
            rng.choice(INTERNAL_HOSTS),
            rng.choice(SERVERS[:1] + SERVERS[2:]),
            dport=rng.choice([443, 80, 53, 8443]),
            nbytes=float(rng.randint(400, 6000)),
            packets=float(rng.randint(4, 30)),
            flags=2 | 16,
        )
