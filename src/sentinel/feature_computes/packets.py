# SPDX-License-Identifier: Apache-2.0
"""Packet-level features for network state windows.

Features computed from raw packet data: fragment flags, retransmissions,
IAT statistics, bidirectional ratio, TTL analysis.
"""

from __future__ import annotations

import math
from collections.abc import Sequence


def frag_df_share(flags: Sequence[int]) -> float | None:
    """Fraction of packets with Don't Fragment (DF) flag set.

    Returns None for empty input — insufficient evidence.
    """
    if not flags:
        return None
    df = sum(1 for f in flags if f & 0x4000)  # Bit 13 of flags
    return df / len(flags)


def frag_mf_share(flags: Sequence[int]) -> float | None:
    """Fraction of packets with More Fragments (MF) flag set.

    High MF share => fragmented attack or pathological MTU.
    Returns None for empty input — insufficient evidence.
    """
    if not flags:
        return None
    mf = sum(1 for f in flags if f & 0x2000)  # Bit 12 of flags
    return mf / len(flags)


def frag_offset_nunique(offsets: Sequence[int]) -> float | None:
    """Number of distinct fragment offsets observed.

    High nunique with MF set => IP fragmentation attack.
    Returns None for empty input.
    """
    if not offsets:
        return None
    return float(len(set(offsets)))


def retransmission_count(
    packets: Sequence[tuple[str, str, int, int, int, int]],
) -> int:
    """Count of retransmitted packets.

    A retransmission is a repeated (src, dst, sport, dport, seq, len) tuple.
    Returns 0 for empty input.
    """
    if not packets:
        return 0
    seen: dict[tuple, int] = {}
    retrans = 0
    for pkt in packets:
        key = pkt  # (src, dst, sport, dport, seq, len)
        count = seen.get(key, 0)
        if count > 0:
            retrans += 1
        seen[key] = count + 1
    return retrans


def retransmission_rate(
    packets: Sequence[tuple[str, str, int, int, int, int]],
) -> float | None:
    """Fraction of packets that are retransmissions.

    Returns None for empty input — insufficient evidence.
    """
    if not packets:
        return None
    return retransmission_count(packets) / len(packets)


def iat_stats(iats: Sequence[float]) -> dict[str, float | None]:
    """Inter-arrival time statistics.

    Returns dict with keys: iat_mean, iat_var, iat_max, iat_min, iat_p90, iat_cv.
    All values are None for fewer than 2 packets — insufficient evidence.

    iat_cv (coefficient of variation) is the beaconing signature:
    - Low CV (< 0.05) with regular spacing => C2 beacon
    - High CV (> 0.6) => bursty human traffic
    """
    n = len(iats)
    if n < 2:
        return {
            "iat_mean": None,
            "iat_var": None,
            "iat_max": None,
            "iat_min": None,
            "iat_p90": None,
            "iat_cv": None,
        }

    mean = sum(iats) / n
    var = sum((x - mean) ** 2 for x in iats) / (n - 1) if n > 1 else 0.0
    std = math.sqrt(var) if var > 0 else 0.0

    ordered = sorted(iats)
    k = 0.9 * (n - 1)
    f = int(k)
    c = min(f + 1, n - 1)
    d = k - f
    p90 = ordered[f] + d * (ordered[c] - ordered[f])

    cv = std / mean if mean > 0 else 0.0

    return {
        "iat_mean": mean,
        "iat_var": var,
        "iat_max": max(iats),
        "iat_min": min(iats),
        "iat_p90": p90,
        "iat_cv": cv,
    }


def bidirectional_ratio_from_packets(
    forward_bytes: Sequence[int],
    reverse_bytes: Sequence[int],
) -> float | None:
    """Reverse bytes / total bytes per 5-tuple.

    Low ratio (< 0.1) => unidirectional (exfil or streaming).
    High ratio (~0.5) => balanced bidirectional (normal traffic).

    Returns None if total bytes is 0 — insufficient evidence.
    """
    total = sum(forward_bytes) + sum(reverse_bytes)
    if total == 0:
        return None
    return sum(reverse_bytes) / total


def ttl_nunique_per_src(
    src_ttl_pairs: Sequence[tuple[str, int]],
) -> float | None:
    """Number of distinct TTL values per source host, averaged across hosts.

    Multiple TTLs from one source => spoofing or NAT'd botnet.
    Returns None for empty input.
    """
    if not src_ttl_pairs:
        return None
    host_ttls: dict[str, set[int]] = {}
    for src, ttl in src_ttl_pairs:
        host_ttls.setdefault(src, set()).add(ttl)
    return sum(len(ttls) for ttls in host_ttls.values()) / len(host_ttls)
