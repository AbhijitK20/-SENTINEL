# SPDX-License-Identifier: Apache-2.0
"""Port behaviour features for network state windows.

Eight pure functions that compute port-level statistics from flow summaries.
Every function is pure, typed, and documents its insufficient-evidence behaviour.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Sequence


def dst_port_nunique(ports: Sequence[int]) -> int:
    """Number of distinct destination ports observed.

    The primary scan signal: a high nunique with few flows-per-port is a port scan.
    Returns 0 for empty input (insufficient evidence).
    """
    return len(set(ports))


def dst_port_entropy(ports: Sequence[int]) -> float | None:
    """Shannon entropy of the destination port distribution.

    High entropy (~log2(n)) => uniform random scan or diverse service traffic.
    Low entropy => concentrated targeting (single-service probe).

    Returns None for fewer than 2 ports — insufficient evidence.
    """
    n = len(ports)
    if n < 2:
        return None
    counts = Counter(ports)
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def dst_port_sequential_score(time_ordered_ports: Sequence[int]) -> float | None:
    """Fraction of consecutive probes whose destination port differs by exactly ±1.

    1.0  => textbook sequential scan (nmap without -r)
    ~0.0 => random targeting or normal traffic

    Returns None for fewer than 3 ports — insufficient evidence.
    Requires time-ordered ports per source host, not a flat bag.
    """
    n = len(time_ordered_ports)
    if n < 3:
        return None
    sequential = 0
    for i in range(1, n):
        if abs(time_ordered_ports[i] - time_ordered_ports[i - 1]) == 1:
            sequential += 1
    return sequential / (n - 1)


def dst_port_randomness(ports: Sequence[int]) -> float | None:
    """Randomness of port selection: 1 - sequential_score.

    1.0 => fully random targeting
    0.0 => sequential scan

    Returns None for fewer than 3 ports — insufficient evidence.
    """
    score = dst_port_sequential_score(ports)
    if score is None:
        return None
    return 1.0 - score


def ports_per_host_max(pairs: Sequence[tuple[str, int]]) -> float:
    """Maximum number of distinct destination ports per source host.

    High values indicate per-target fan-out (horizontal scan).
    Returns 0 for empty input.
    """
    if not pairs:
        return 0.0
    host_ports: dict[str, set[int]] = {}
    for host, port in pairs:
        host_ports.setdefault(host, set()).add(port)
    return float(max(len(ports) for ports in host_ports.values()))


def dst_port_wellknown_share(ports: Sequence[int]) -> float | None:
    """Fraction of destination ports in the well-known range (0-1023).

    High share => service-targeting behaviour (web, SSH, DB probes).
    Returns None for empty input — insufficient evidence.
    """
    if not ports:
        return None
    wellknown = sum(1 for p in ports if p < 1024)
    return wellknown / len(ports)


def dst_port_low_share(ports: Sequence[int]) -> float | None:
    """Fraction of destination ports in the low/registered range (1024-49151).

    Returns None for empty input — insufficient evidence.
    """
    if not ports:
        return None
    low = sum(1 for p in ports if 1024 <= p <= 49151)
    return low / len(ports)


def src_port_ephemeral_share(ports: Sequence[int]) -> float | None:
    """Fraction of source ports in the ephemeral range (49152-65535).

    High share => typical client behaviour (source port randomisation).
    Low share with high dst_port_nunique => potential spoofed source ports.

    Returns None for empty input — insufficient evidence.
    """
    if not ports:
        return None
    ephemeral = sum(1 for p in ports if p >= 49152)
    return ephemeral / len(ports)
