# SPDX-License-Identifier: Apache-2.0
"""Flag ratios and protocol share features.

Counts are volume-dependent and won't transfer across networks;
ratios are the network-invariant signal.
"""

from __future__ import annotations

from typing import Sequence


def flag_syn_ratio(flags: Sequence[int]) -> float | None:
    """Fraction of flows with SYN flag set.

    SYN-flood: > 0.8; normal traffic: < 0.1.
    Returns None for empty input — insufficient evidence.
    """
    if not flags:
        return None
    syn = sum(1 for f in flags if f & 2)
    return syn / len(flags)


def flag_ack_ratio(flags: Sequence[int]) -> float | None:
    """Fraction of flows with ACK flag set.

    Returns None for empty input.
    """
    if not flags:
        return None
    ack = sum(1 for f in flags if f & 16)
    return ack / len(flags)


def flag_fin_ratio(flags: Sequence[int]) -> float | None:
    """Fraction of flows with FIN flag set.

    Returns None for empty input.
    """
    if not flags:
        return None
    fin = sum(1 for f in flags if f & 1)
    return fin / len(flags)


def flag_rst_ratio(flags: Sequence[int]) -> float | None:
    """Fraction of flows with RST flag set.

    High RST ratio => connection resets, possible port scan or service rejection.
    Returns None for empty input.
    """
    if not flags:
        return None
    rst = sum(1 for f in flags if f & 4)
    return rst / len(flags)


def flag_psh_ratio(flags: Sequence[int]) -> float | None:
    """Fraction of flows with PSH flag set.

    Returns None for empty input.
    """
    if not flags:
        return None
    psh = sum(1 for f in flags if f & 8)
    return psh / len(flags)


def flag_urg_ratio(flags: Sequence[int]) -> float | None:
    """Fraction of flows with URG flag set.

    Returns None for empty input.
    """
    if not flags:
        return None
    urg = sum(1 for f in flags if f & 32)
    return urg / len(flags)


def flag_syn_ack_ratio(flags: Sequence[int]) -> float | None:
    """SYN count divided by max(ACK count, 1).

    High ratio => SYN flood without completing handshakes.
    Returns None for empty input.
    """
    if not flags:
        return None
    syn = sum(1 for f in flags if f & 2)
    ack = sum(1 for f in flags if f & 16)
    return syn / max(ack, 1)


def flag_no_ack_share(flags: Sequence[int]) -> float | None:
    """Share of flows with SYN set but ACK not set (half-open connections).

    High share => SYN scan or SYN flood.
    Returns None for empty input.
    """
    if not flags:
        return None
    syn_no_ack = sum(1 for f in flags if (f & 2) and not (f & 16))
    return syn_no_ack / len(flags)


def flag_xmas_share(flags: Sequence[int]) -> float | None:
    """Share of flows with FIN+PSH+URG all set (XMAS scan).

    XMAS scan: > 0.9; normal traffic: ~0.0.
    Returns None for empty input.
    """
    if not flags:
        return None
    xmas = sum(1 for f in flags if (f & 1) and (f & 8) and (f & 32))
    return xmas / len(flags)


def proto_tcp_share(protocols: Sequence[int]) -> float | None:
    """Fraction of flows using TCP (protocol = 6).

    Returns None for empty input.
    """
    if not protocols:
        return None
    tcp = sum(1 for p in protocols if p == 6)
    return tcp / len(protocols)


def proto_udp_share(protocols: Sequence[int]) -> float | None:
    """Fraction of flows using UDP (protocol = 17).

    Returns None for empty input.
    """
    if not protocols:
        return None
    udp = sum(1 for p in protocols if p == 17)
    return udp / len(protocols)


def proto_icmp_share(protocols: Sequence[int]) -> float | None:
    """Fraction of flows using ICMP (protocol = 1).

    Returns None for empty input.
    """
    if not protocols:
        return None
    icmp = sum(1 for p in protocols if p == 1)
    return icmp / len(protocols)
