# SPDX-License-Identifier: Apache-2.0
"""Build ordered network states from normalized telemetry events."""

from __future__ import annotations

import bisect
import math
import warnings
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from enum import StrEnum

from sentinel.feature_computes.flags import (
    flag_ack_ratio,
    flag_fin_ratio,
    flag_no_ack_share,
    flag_psh_ratio,
    flag_rst_ratio,
    flag_syn_ack_ratio,
    flag_syn_ratio,
    flag_urg_ratio,
    flag_xmas_share,
    proto_icmp_share,
    proto_tcp_share,
    proto_udp_share,
)
from sentinel.feature_computes.packets import (
    frag_df_share,
    frag_mf_share,
    frag_offset_nunique,
    iat_stats,
    retransmission_count,
    retransmission_rate,
    ttl_nunique_per_src,
)
from sentinel.feature_computes.ports import (
    dst_port_entropy,
    dst_port_low_share,
    dst_port_nunique,
    dst_port_sequential_score,
    dst_port_wellknown_share,
    ports_per_host_max,
    src_port_ephemeral_share,
)
from sentinel.schemas import NetworkState, UnifiedEvent

FEATURE_VERSION = "state-features-v4"


class Agg(StrEnum):
    """Aggregation functions applied to per-window feature value lists."""

    SUM = "sum"
    MEAN = "mean"
    STD = "std"
    VAR = "var"
    MAX = "max"
    MIN = "min"
    P50 = "p50"
    P90 = "p90"
    P99 = "p99"
    ENTROPY = "entropy"
    NUNIQUE = "nunique"
    RATIO = "ratio"


# Feature name -> tuple of aggregations to emit.
# Absent inputs produce absent keys, never 0.0.
# v3: removed meaningless aggregations (destination_port_mean, source_port_mean,
# protocol_mean). Added derived behavioural features.
AGGREGATION_POLICY: dict[str, tuple[Agg, ...]] = {
    "bytes": (Agg.SUM, Agg.MEAN, Agg.STD, Agg.MAX, Agg.P90),
    "packets": (Agg.SUM, Agg.MEAN, Agg.MAX),
    "duration": (Agg.MEAN, Agg.STD, Agg.MAX),
    "payload_size": (Agg.SUM, Agg.MEAN, Agg.STD, Agg.P50, Agg.P90, Agg.ENTROPY),
    "ttl": (Agg.MEAN, Agg.STD, Agg.VAR, Agg.MIN, Agg.MAX, Agg.NUNIQUE),
    "tcp_window_size": (Agg.MEAN, Agg.STD, Agg.MIN, Agg.MAX),
    "iat_mean": (Agg.MEAN, Agg.VAR, Agg.MAX, Agg.MIN, Agg.P90),
    "iat_variance": (Agg.MEAN, Agg.MAX),
    "iat_max": (Agg.MEAN, Agg.MAX),
    "retransmission": (Agg.SUM, Agg.MEAN),
    "bidirectional_ratio": (Agg.MEAN, Agg.STD),
    "syn_count": (Agg.SUM, Agg.MEAN),
    "ack_count": (Agg.SUM, Agg.MEAN),
    "fin_count": (Agg.SUM, Agg.MEAN),
    "rst_count": (Agg.SUM, Agg.MEAN),
    "urg_count": (Agg.SUM, Agg.MEAN),
    "failed_auth": (Agg.SUM,),
    "auth_attempt": (Agg.SUM,),
    "source_port": (Agg.NUNIQUE,),
    "destination_port": (Agg.NUNIQUE,),
    "protocol": (Agg.NUNIQUE,),
    "tcp_flags": (Agg.NUNIQUE,),
}

# Raw per-event header values consumed by the explicit packet computes below.
# Aggregating them (e.g. summing IP flag words) would be meaningless, so they
# never reach the generic sum fallback.
RAW_ONLY_FEATURES = frozenset({"fragment_flags", "ip_flags", "frag_offset"})

# IPv4 ranges that are private, loopback, link-local or otherwise inside the
# network being observed. Anything else in address form is off-net.
_PRIVATE_V4_FIRST_OCTET_RANGES = ((10,), (172,), (192,), (127,), (169,))


def _is_private_v4(address: str) -> bool:
    parts = address.split(".")
    if len(parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
        return False
    octets = (int(p) for p in parts)
    first = next(octets)
    if first in (10, 127):  # RFC1918 10/8, loopback
        return True
    if first == 172:  # RFC1918 172.16/12
        return 16 <= next(octets) <= 31
    if first == 192:  # RFC1918 192.168/16, and 192.0.0.0/24 IETF protocol
        second = next(octets)
        return second == 168 or second == 0
    if first == 169:  # link-local
        return True
    if first == 100 and next(octets) == 64:  # CGNAT 100.64/10
        return True
    return False


def is_external_destination(entity: str) -> bool:
    """True when an entity name denotes something outside the observed network.

    **This used to be a two-item prefix test and matched nothing real.** The old
    expression was::

        entity.startswith(("external", "1.2.3.4"))

    which only ever matched a literal entity named ``external-something`` or the
    single hard-coded address ``1.2.3.4``. Measured across every window of the
    committed synthetic corpus, ``external_destination_count`` was identically
    ``0.0``, so the Exfiltration rule in ``stage_mapping.py`` — which requires
    this count to be positive — could never fire on any shipped data. The same
    expression would also have failed on a real capture, where destinations are
    public addresses and registered domain names.

    The definition used here is about where the address points, not how it is
    spelled:

    * an IPv4 literal is external unless it falls in a private, loopback,
      link-local or CGNAT range;
    * a hostname carrying a dot is a fully-qualified name (``evil.com``) and is
      external; bare internal names (``host-01``, ``auth-service``) are not;
    * a leading ``external`` is still honoured, so producers that label their own
      off-net entities keep working.
    """
    name = entity.strip().lower()
    if not name:
        return False
    if name.startswith("external"):
        return True
    looks_like_v4 = all(part.isdigit() for part in name.split(".")) and name.count(".") == 3
    if looks_like_v4:
        return not _is_private_v4(name)
    if ":" in name:  # IPv6 literal
        return name in ("::1", "::")
    return "." in name


# Aggregation types that are undefined for single-event windows.
_UNDEFINED_FOR_SINGLE = {Agg.STD, Agg.VAR, Agg.P50, Agg.P90, Agg.P99, Agg.ENTROPY}

# Legacy aliases: old flat feature name -> new enriched name.
# Used by stage_mapping.py and detectors.py until S7 migrates them.
LEGACY_ALIASES: dict[str, str] = {
    "bytes": "bytes_sum",
    "packets": "packets_sum",
    "duration": "duration_mean",
    "payload_size": "payload_size_sum",
    "syn_count": "syn_count_sum",
    "ack_count": "ack_count_sum",
    "fin_count": "fin_count_sum",
    "rst_count": "rst_count_sum",
    "failed_auth": "failed_auth_sum",
    "iat_mean": "iat_mean_mean",
    "auth_attempt": "auth_attempt_sum",
    "urg_count": "urg_count_sum",
}


def resolve_alias(name: str) -> str:
    """Resolve a legacy flat feature name to its v2 equivalent, emitting a warning."""
    if name in LEGACY_ALIASES:
        warnings.warn(
            f"Feature {name!r} is deprecated; use {LEGACY_ALIASES[name]!r} instead",
            DeprecationWarning,
            stacklevel=2,
        )
        return LEGACY_ALIASES[name]
    return name


def build_network_states(
    events: tuple[UnifiedEvent, ...] | list[UnifiedEvent],
    *,
    window_seconds: int,
    stride_seconds: int,
    include_empty: bool = False,
) -> tuple[NetworkState, ...]:
    """Aggregate events into ordered, possibly overlapping time windows.

    Windows are half-open intervals ``[start, end)`` anchored to the earliest
    event. An event belongs to every window that contains its timestamp, which
    supports a stride shorter than the window duration without losing events.
    """
    if window_seconds <= 0 or stride_seconds <= 0:
        raise ValueError("window_seconds and stride_seconds must be positive")
    if not events:
        return ()

    ordered_events = sorted(events, key=lambda event: event.timestamp)
    stamps = [e.timestamp for e in ordered_events]
    origin = stamps[0]
    latest = stamps[-1]
    window_delta = timedelta(seconds=window_seconds)
    stride_delta = timedelta(seconds=stride_seconds)

    states: list[NetworkState] = []
    start = origin
    while start <= latest:
        end = start + window_delta
        lo = bisect.bisect_left(stamps, start)
        hi = bisect.bisect_left(stamps, end)
        window_events = ordered_events[lo:hi]
        if window_events or include_empty:
            states.append(_build_state(start, end, window_events))
        start += stride_delta
    return tuple(states)


def _build_state(
    start: datetime,
    end: datetime,
    events: list[UnifiedEvent],
) -> NetworkState:
    feature_values: dict[str, list[float]] = defaultdict(list)
    entities: set[str] = set()
    edges: dict[tuple[str, str], dict[str, float]] = defaultdict(
        lambda: {"count": 0.0, "bytes": 0.0}
    )
    source_ids: list[str] = []
    flow_count = 0
    packet_count = 0

    for event in events:
        source_ids.append(event.event_id)
        entities.update((event.source_entity, event.destination_entity))
        if event.event_type == "flow":
            flow_count += 1
        elif event.event_type == "packet":
            packet_count += 1
        for name, value in event.features.items():
            feature_values[name].append(value)
        edge = edges[(event.source_entity, event.destination_entity)]
        edge["count"] += 1
        edge["bytes"] += event.features.get("bytes", event.features.get("payload_size", 0.0))

    features: dict[str, float] = {
        "event_count": float(len(events)),
        "flow_event_count": float(flow_count),
        "packet_event_count": float(packet_count),
        "external_destination_count": float(
            sum(1 for entity in entities if is_external_destination(entity))
        ),
    }

    # Apply the aggregation policy to each feature present in the window.
    for name, values in feature_values.items():
        if name in RAW_ONLY_FEATURES:
            continue
        aggs = AGGREGATION_POLICY.get(name)
        if aggs is None:
            # Unknown feature: fall back to sum (count-like) if all non-negative,
            # else mean. This preserves backward compat for custom features.
            features[name] = sum(values)
            continue
        if not isinstance(aggs, tuple):
            aggs = (aggs,)
        n = len(values)
        for agg in aggs:
            out_name = f"{name}_{agg.value}"
            if agg in _UNDEFINED_FOR_SINGLE and n < 2:
                continue  # absent, not 0.0
            if agg == Agg.SUM:
                features[out_name] = sum(values)
            elif agg == Agg.MEAN:
                features[out_name] = sum(values) / n
            elif agg == Agg.STD:
                features[out_name] = _std(values)
            elif agg == Agg.VAR:
                features[out_name] = _var(values)
            elif agg == Agg.MAX:
                features[out_name] = max(values)
            elif agg == Agg.MIN:
                features[out_name] = min(values)
            elif agg == Agg.P50:
                features[out_name] = _percentile(values, 50)
            elif agg == Agg.P90:
                features[out_name] = _percentile(values, 90)
            elif agg == Agg.P99:
                features[out_name] = _percentile(values, 99)
            elif agg == Agg.ENTROPY:
                features[out_name] = _entropy(values)
            elif agg == Agg.NUNIQUE:
                features[out_name] = float(len(set(values)))
            elif agg == Agg.RATIO:
                pass  # computed by the caller if needed

        # Legacy flat alias: emit the original name pointing to the first
        # aggregation (sum for count-like, mean for continuous). This keeps
        # stage_mapping.py, detectors.py, and existing tests working until S7
        # migrates them to the enriched names.
        if name in LEGACY_ALIASES:
            flat_name = name
            if Agg.SUM in aggs:
                features[flat_name] = sum(values)
            elif Agg.MEAN in aggs:
                features[flat_name] = sum(values) / n
            elif aggs:
                # Fallback: compute the first aggregation
                first = aggs[0]
                if first == Agg.SUM:
                    features[flat_name] = sum(values)
                elif first == Agg.MEAN:
                    features[flat_name] = sum(values) / n
                elif first == Agg.NUNIQUE:
                    features[flat_name] = float(len(set(values)))

    # TCP flag bitmask decomposition: if tcp_flags bitmask values were
    # collected, decompose into per-flag counts. This always overwrites
    # any pre-existing individual flag features, ensuring bitmask truth.
    _FLAG_MAP = {2: "syn_count", 16: "ack_count", 1: "fin_count", 4: "rst_count", 32: "urg_count"}
    tcp_vals = feature_values.get("tcp_flags")
    if tcp_vals:
        n = len(tcp_vals)
        for bit, fname in _FLAG_MAP.items():
            flag_vals = [1.0 if int(v) & bit else 0.0 for v in tcp_vals]
            features[f"{fname}_sum"] = sum(flag_vals)
            features[f"{fname}_mean"] = sum(flag_vals) / n if n else 0.0

    def _set_feature_if(d: dict, key: str, val):
        """Set feature if value is not None."""
        if val is not None:
            d[key] = val

    def _set_if(name: str, fn, args=None):
        """Helper to compute and set a feature if result is not None."""
        if args is None:
            result = fn()
        elif isinstance(args, (list, tuple)):
            result = fn(args)
        else:
            result = fn(args)
        _set_feature_if(features, name, result)

    # Port behaviour features (P1-T1)
    src_ports = feature_values.get("source_port", [])
    dst_ports = feature_values.get("destination_port", [])
    if src_ports:
        high_count = sum(1 for p in src_ports if p > 1024)
        features["high_port_ratio"] = high_count / len(src_ports)
    else:
        features["high_port_ratio"] = 0.0
    if dst_ports:
        int_ports = [int(p) for p in dst_ports]
        features["dst_port_nunique"] = float(dst_port_nunique(int_ports))
        ent = dst_port_entropy(int_ports)
        features["dst_port_entropy"] = ent if ent is not None else 0.0
        wellknown = dst_port_wellknown_share(int_ports)
        features["dst_port_wellknown_share"] = wellknown if wellknown is not None else 0.0
        low = dst_port_low_share(int_ports)
        features["dst_port_low_share"] = low if low is not None else 0.0
    else:
        features["dst_port_nunique"] = 0.0
        features["dst_port_entropy"] = 0.0
        features["dst_port_wellknown_share"] = 0.0
        features["dst_port_low_share"] = 0.0
    if src_ports:
        int_src = [int(p) for p in src_ports]
        ephemeral = src_port_ephemeral_share(int_src)
        features["src_port_ephemeral_share"] = ephemeral if ephemeral is not None else 0.0
    else:
        features["src_port_ephemeral_share"] = 0.0

    # Port sequential score needs time-ordered ports per source host.
    # We approximate from event order (events are time-ordered).
    host_dst_ports: dict[str, list[int]] = defaultdict(list)
    for event in events:
        if "destination_port" in event.features:
            host_dst_ports[event.source_entity].append(int(event.features["destination_port"]))
    sequential_scores = []
    for host_ports in host_dst_ports.values():
        score = dst_port_sequential_score(host_ports)
        if score is not None:
            sequential_scores.append(score)
    if sequential_scores:
        features["dst_port_sequential_score"] = sum(sequential_scores) / len(sequential_scores)
        features["dst_port_randomness"] = 1.0 - features["dst_port_sequential_score"]
    else:
        features["dst_port_sequential_score"] = 0.0
        features["dst_port_randomness"] = 0.0

    # Ports per host max
    if dst_ports:
        pairs = [(events[i].source_entity, int(dst_ports[i])) for i in range(len(events))]
        features["ports_per_host_max"] = ports_per_host_max(pairs)
    else:
        features["ports_per_host_max"] = 0.0

    # Flag ratio features (P1-T2): computed from tcp_flags bitmask
    if tcp_vals:
        int_flags = [int(v) for v in tcp_vals]

        def _flag_if(name: str, fn):
            result = fn(int_flags)
            features[name] = result if result is not None else 0.0

        _flag_if("flag_syn_ratio", flag_syn_ratio)
        _flag_if("flag_ack_ratio", flag_ack_ratio)
        _flag_if("flag_fin_ratio", flag_fin_ratio)
        _flag_if("flag_rst_ratio", flag_rst_ratio)
        _flag_if("flag_psh_ratio", flag_psh_ratio)
        _flag_if("flag_urg_ratio", flag_urg_ratio)
        _flag_if("flag_syn_ack_ratio", flag_syn_ack_ratio)
        _flag_if("flag_no_ack_share", flag_no_ack_share)
        _flag_if("flag_xmas_share", flag_xmas_share)
    else:
        for name in [
            "flag_syn_ratio",
            "flag_ack_ratio",
            "flag_fin_ratio",
            "flag_rst_ratio",
            "flag_psh_ratio",
            "flag_urg_ratio",
            "flag_syn_ack_ratio",
            "flag_no_ack_share",
            "flag_xmas_share",
        ]:
            features[name] = 0.0

    # Protocol share features (P1-T2)
    protos = feature_values.get("protocol", [])
    if protos:
        int_protos = [int(p) for p in protos]

        def _proto_if(name: str, fn):
            result = fn(int_protos)
            features[name] = result if result is not None else 0.0

        _proto_if("proto_tcp_share", proto_tcp_share)
        _proto_if("proto_udp_share", proto_udp_share)
        _proto_if("proto_icmp_share", proto_icmp_share)
    else:
        for name in ["proto_tcp_share", "proto_udp_share", "proto_icmp_share"]:
            features[name] = 0.0

    # Packet-level features (P1-T3) — fragment flags, retransmissions, IAT, TTL
    # Fragment features come from the IP header flags. PCAP ingestion emits
    # `fragment_flags`; other producers may use `ip_flags` — accept both so a
    # real capture and a replay produce identical feature names.
    ip_flags = feature_values.get("fragment_flags") or feature_values.get("ip_flags") or []
    if ip_flags:
        int_ip_flags = [int(f) for f in ip_flags]

        def _frag_if(name: str, fn):
            result = fn(int_ip_flags)
            features[name] = result if result is not None else 0.0

        _frag_if("frag_df_share", frag_df_share)
        _frag_if("frag_mf_share", frag_mf_share)
    else:
        # Absent packet telemetry is recorded as an absent key, not as a measured
        # zero. It used to be written as 0.0, and after standardization that put
        # frag_df_share at z = -10.04 on a flow-only capture: the training
        # distribution for this column sits at 1.0 with a standard deviation of
        # 0.1, so "no packet evidence" was indistinguishable from "every packet
        # cleared DF". The vector stays rectangular either way — `vectorize_states`
        # imputes a missing column at the training mean — so writing the zero
        # bought nothing and cost a ten-sigma outlier.
        pass

    # Distinct fragment offsets: high alongside MF means fragmentation abuse.
    frag_offsets = feature_values.get("frag_offset", [])
    if frag_offsets:
        result = frag_offset_nunique([int(offset) for offset in frag_offsets])
        features["frag_offset_nunique"] = result if result is not None else 0.0
    else:
        # Absent fragment offsets carry no evidence; see the note on frag_df_share.
        pass

    # Retransmissions: the per-packet duplicate flag is set at ingestion and
    # aggregated per window here.
    retrans = feature_values.get("retransmission", [])
    features["retransmission_count"] = float(retransmission_count(retrans))
    retrans_rate = retransmission_rate(retrans)
    features["retransmission_rate"] = retrans_rate if retrans_rate is not None else 0.0

    # IAT statistics from iat_mean values already collected
    iat_vals = feature_values.get("iat_mean", [])
    if iat_vals:
        iat = iat_stats(iat_vals)
        for k, v in iat.items():
            features[k] = v if v is not None else 0.0
    else:
        for k in ["iat_mean", "iat_var", "iat_max", "iat_min", "iat_p90", "iat_cv"]:
            features[k] = 0.0

    # TTL uniqueness per source
    if "ttl" in feature_values:
        src_ttl = [
            (e.source_entity, int(e.features.get("ttl", 0))) for e in events if "ttl" in e.features
        ]
        if src_ttl:
            result = ttl_nunique_per_src(src_ttl)
            features["ttl_nunique_per_src"] = result if result is not None else 0.0
        else:
            features["ttl_nunique_per_src"] = 0.0
    else:
        features["ttl_nunique_per_src"] = 0.0

    edge_summary = [
        {
            "source": source,
            "destination": destination,
            "count": values["count"],
            "bytes": values["bytes"],
        }
        for (source, destination), values in sorted(edges.items())
    ]
    return NetworkState(
        window_start=start,
        window_end=end,
        features=features,
        entities=sorted(entities),
        edge_summary=edge_summary,
        coverage={"flow": flow_count > 0, "packet": packet_count > 0},
        source_ids=source_ids,
    )


def _std(values: list[float]) -> float:
    """Sample standard deviation."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return math.sqrt(sum((v - mean) ** 2 for v in values) / (n - 1))


def _var(values: list[float]) -> float:
    """Sample variance."""
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return sum((v - mean) ** 2 for v in values) / (n - 1)


def _percentile(values: list[float], pct: int) -> float:
    """Linear interpolation percentile."""
    ordered = sorted(values)
    n = len(ordered)
    k = (pct / 100) * (n - 1)
    f = int(k)
    c = min(f + 1, n - 1)
    d = k - f
    return ordered[f] + d * (ordered[c] - ordered[f])


def _entropy(values: list[float]) -> float:
    """Shannon entropy of discrete values (quantised to integers)."""
    if not values:
        return 0.0
    counts = Counter(int(v) for v in values)
    total = len(values)
    return -sum((c / total) * math.log2(c / total) for c in counts.values() if c > 0)
