# SPDX-License-Identifier: Apache-2.0
"""Feature registry — single source of truth for all SENTINEL features.

Every feature emitted by _build_state is registered here. Downstream consumers
(catalog generation, drift monitoring, SHAP labelling, UI feature glossary)
read from this one place.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FeatureDtype(Enum):
    """Data type of a feature."""

    FLOAT = "float"
    INT = "int"


class InsufficientEvidence(Enum):
    """Behaviour when there is insufficient data to compute the feature."""

    ABSENT = "absent"  # Key is absent from features dict
    ZERO = "zero"  # Key is present with value 0.0
    NONE = "none"  # Key is present with value None (for float features)


@dataclass(frozen=True)
class FeatureSpec:
    """Specification for a single feature."""

    name: str
    base_field: str  # Which raw event field this derives from
    dtype: FeatureDtype = FeatureDtype.FLOAT
    insufficient_evidence: InsufficientEvidence = InsufficientEvidence.ZERO
    introduced_in: str = "state-features-v3"
    model_eligible: bool = True
    description: str = ""


class FeatureRegistry:
    """Single source of truth for all SENTINEL features.

    Usage:
        registry = FeatureRegistry()
        all_features = registry.all()
        catalog = registry.to_catalog()
    """

    def __init__(self) -> None:
        self._features: dict[str, FeatureSpec] = {}
        self._register_builtin_features()

    def _register_builtin_features(self) -> None:
        """Register all built-in features from state_builder."""
        # Event counts (always present)
        self._register("event_count", "", description="Total events in window")
        self._register("flow_event_count", "", description="Flow events in window")
        self._register("packet_event_count", "", description="Packet events in window")
        self._register(
            "external_destination_count",
            "",
            description="External destinations in window",
        )

        # Byte/packet aggregations
        for suffix in ["sum", "mean", "std", "max", "p90"]:
            self._register(f"bytes_{suffix}", "bytes", description=f"Bytes {suffix}")
        for suffix in ["sum", "mean", "max"]:
            self._register(f"packets_{suffix}", "packets", description=f"Packets {suffix}")

        # Duration
        for suffix in ["mean", "std", "max"]:
            self._register(f"duration_{suffix}", "duration", description=f"Duration {suffix}")

        # Payload size
        for suffix in ["sum", "mean", "std", "p50", "p90", "entropy"]:
            self._register(
                f"payload_size_{suffix}", "payload_size", description=f"Payload {suffix}"
            )

        # TTL
        for suffix in ["mean", "std", "var", "min", "max", "nunique"]:
            self._register(f"ttl_{suffix}", "ttl", description=f"TTL {suffix}")

        # TCP window size
        for suffix in ["mean", "std", "min", "max"]:
            self._register(
                f"tcp_window_size_{suffix}", "tcp_window_size", description=f"TCP window {suffix}"
            )

        # IAT features
        for suffix in ["mean", "var", "max", "min", "p90"]:
            self._register(f"iat_mean_{suffix}", "iat_mean", description=f"IAT mean {suffix}")
        for suffix in ["mean", "max"]:
            self._register(
                f"iat_variance_{suffix}", "iat_variance", description=f"IAT variance {suffix}"
            )
        for suffix in ["mean", "max"]:
            self._register(f"iat_max_{suffix}", "iat_max", description=f"IAT max {suffix}")

        # Bidirectional ratio
        for suffix in ["mean", "std"]:
            self._register(
                f"bidirectional_ratio_{suffix}",
                "bidirectional_ratio",
                description=f"Bidirectional ratio {suffix}",
            )

        # TCP flag counts (from bitmask decomposition)
        for flag in ["syn", "ack", "fin", "rst", "urg"]:
            for suffix in ["sum", "mean"]:
                self._register(
                    f"{flag}_count_{suffix}",
                    "tcp_flags",
                    description=f"{flag.upper()} count {suffix}",
                )

        # Failed auth / auth attempt
        self._register("failed_auth_sum", "failed_auth", description="Failed auth count")
        self._register("auth_attempt_sum", "auth_attempt", description="Auth attempt count")

        # Port features (v3)
        self._register("source_port_nunique", "source_port", description="Unique source ports")
        self._register(
            "destination_port_nunique", "destination_port", description="Unique destination ports"
        )
        self._register("protocol_nunique", "protocol", description="Unique protocols")
        self._register("tcp_flags_nunique", "tcp_flags", description="Unique TCP flag values")

        # High port ratio (v2)
        self._register("high_port_ratio", "source_port", description="High port ratio")

        # Port behaviour features (v3, P1-T1)
        self._register("dst_port_nunique", "destination_port", description="Unique dst ports")
        self._register("dst_port_entropy", "destination_port", description="Dst port entropy")
        self._register(
            "dst_port_sequential_score",
            "destination_port",
            description="Sequential port scan score",
        )
        self._register("dst_port_randomness", "destination_port", description="Port randomness")
        self._register("ports_per_host_max", "destination_port", description="Max ports per host")
        self._register(
            "dst_port_wellknown_share",
            "destination_port",
            description="Well-known port share",
        )
        self._register("dst_port_low_share", "destination_port", description="Low port share")
        self._register(
            "src_port_ephemeral_share", "source_port", description="Ephemeral port share"
        )

        # Flag ratio features (v3, P1-T2)
        for flag in ["syn", "ack", "fin", "rst", "psh", "urg"]:
            self._register(f"flag_{flag}_ratio", "tcp_flags", description=f"{flag.upper()} ratio")
        self._register(
            "flag_syn_ack_ratio", "tcp_flags", description="SYN/ACK ratio"
        )
        self._register(
            "flag_no_ack_share", "tcp_flags", description="SYN-no-ACK share"
        )
        self._register("flag_xmas_share", "tcp_flags", description="XMAS scan share")

        # Protocol share features (v3, P1-T2)
        self._register("proto_tcp_share", "protocol", description="TCP protocol share")
        self._register("proto_udp_share", "protocol", description="UDP protocol share")
        self._register("proto_icmp_share", "protocol", description="ICMP protocol share")

        # Packet-level features (v3, P1-T3)
        self._register("frag_df_share", "ip_flags", description="DF flag share")
        self._register("frag_mf_share", "ip_flags", description="MF flag share")
        self._register("iat_mean", "iat_mean", description="Mean IAT")
        self._register("iat_var", "iat_mean", description="IAT variance")
        self._register("iat_max", "iat_mean", description="Max IAT")
        self._register("iat_min", "iat_mean", description="Min IAT")
        self._register("iat_p90", "iat_mean", description="90th percentile IAT")
        self._register("iat_cv", "iat_mean", description="IAT coefficient of variation")
        self._register(
            "ttl_nunique_per_src", "ttl", description="TTL uniqueness per source"
        )

    def _register(
        self,
        name: str,
        base_field: str,
        dtype: FeatureDtype = FeatureDtype.FLOAT,
        insufficient_evidence: InsufficientEvidence = InsufficientEvidence.ZERO,
        introduced_in: str = "state-features-v3",
        model_eligible: bool = True,
        description: str = "",
    ) -> None:
        """Register a feature."""
        self._features[name] = FeatureSpec(
            name=name,
            base_field=base_field,
            dtype=dtype,
            insufficient_evidence=insufficient_evidence,
            introduced_in=introduced_in,
            model_eligible=model_eligible,
            description=description,
        )

    def all(self) -> list[FeatureSpec]:
        """Return all registered features."""
        return list(self._features.values())

    def get(self, name: str) -> FeatureSpec | None:
        """Get a feature by name."""
        return self._features.get(name)

    def names(self) -> list[str]:
        """Return all feature names."""
        return sorted(self._features.keys())

    def model_eligible_names(self) -> list[str]:
        """Return names of model-eligible features."""
        return sorted(f.name for f in self._features.values() if f.model_eligible)

    def to_catalog(self) -> list[dict]:
        """Export features as a catalog (for docs/FEATURE_CATALOG.md)."""
        return [
            {
                "name": f.name,
                "base_field": f.base_field,
                "dtype": f.dtype.value,
                "insufficient_evidence": f.insufficient_evidence.value,
                "introduced_in": f.introduced_in,
                "model_eligible": f.model_eligible,
                "description": f.description,
            }
            for f in self._features.values()
        ]
