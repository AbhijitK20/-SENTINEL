"""Deterministic synthetic replay scenarios for pipeline validation.

These scenarios follow the DEMO_SCENARIO.md storyline (baseline traffic, then
reconnaissance, then lateral movement) and exist to exercise the pipeline
end-to-end without external datasets. They are not a benchmark and must never
be presented as real traffic.
"""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

from trajectory.schemas import NetworkState, StateLabel, UnifiedEvent
from trajectory.state_builder import build_network_states
from trajectory.targets import LabelledState, make_state_key

DATASET_ID = "synthetic-recon-lateral-v1"
INTERNAL_HOSTS = [f"host-{index:02d}" for index in range(1, 9)]
SERVERS = ["auth-service", "server-03", "file-server", "web-proxy"]


def generate_scenario_events(
    scenario_id: str,
    *,
    seed: int,
    benign_minutes: int = 20,
    recon_minutes: int = 8,
    lateral_minutes: int = 8,
    start: datetime | None = None,
) -> tuple[list[UnifiedEvent], dict[str, datetime]]:
    """Generate one scenario's flow events and the stage boundaries used for labels."""
    if min(benign_minutes, recon_minutes, lateral_minutes) < 1:
        raise ValueError("every phase must last at least one minute")
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
    ) -> None:
        nonlocal counter
        counter += 1
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
                    "iat_mean": max(0.001, rng.gauss(0.1, 0.03)),
                    "bidirectional_ratio": min(1.0, max(0.0, rng.gauss(0.7, 0.1))),
                    "failed_auth": failed_auth,
                },
                source_format="replay",
                provenance=f"{DATASET_ID}:{scenario_id}",
            )
        )

    minute = 0
    for _ in range(benign_minutes):
        _benign_minute(rng, emit, origin + timedelta(minutes=minute))
        minute += 1
    recon_start = origin + timedelta(minutes=minute)
    for _ in range(recon_minutes):
        ts = origin + timedelta(minutes=minute)
        _benign_minute(rng, emit, ts)
        # Reconnaissance: many new destinations, small SYN/RST probes, rising failed auth.
        for probe in range(rng.randint(12, 20)):
            target = rng.choice(INTERNAL_HOSTS + SERVERS)
            emit(
                ts + timedelta(seconds=probe * 3),
                attacker,
                target,
                dport=rng.choice([22, 135, 139, 445, 3389, 8080]),
                nbytes=float(rng.randint(60, 200)),
                packets=2.0,
                flags=2 | 4,  # SYN + RST
            )
        for attempt in range(rng.randint(3, 6)):
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
    lateral_start = origin + timedelta(minutes=minute)
    for _ in range(lateral_minutes):
        ts = origin + timedelta(minutes=minute)
        _benign_minute(rng, emit, ts)
        # Lateral movement: sustained new internal connections with larger transfers.
        for hop in range(rng.randint(4, 8)):
            emit(
                ts + timedelta(seconds=hop * 7),
                attacker,
                "server-03" if hop % 2 == 0 else rng.choice(INTERNAL_HOSTS),
                dport=rng.choice([445, 3389, 5985]),
                nbytes=float(rng.randint(20_000, 80_000)),
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
        # Distinct start times keep state keys unique across scenarios.
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
    # A window is labelled by the stage active at its end so that the label
    # never depends on events after the window closes.
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
            rng.choice(SERVERS[:1] + SERVERS[2:]),  # normal hosts rarely touch server-03
            dport=rng.choice([443, 80, 53, 8443]),
            nbytes=float(rng.randint(400, 6000)),
            packets=float(rng.randint(4, 30)),
            flags=2 | 16,
        )
