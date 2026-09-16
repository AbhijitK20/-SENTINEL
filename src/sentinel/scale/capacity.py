# SPDX-License-Identifier: Apache-2.0
"""Capacity model for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CapacityEstimate:
    """Capacity estimate for a component."""

    component: str
    events_per_second: int
    concurrent_analysts: int
    tenants: int
    notes: str = ""


@dataclass
class CapacityModel:
    """Overall capacity model."""

    node_count: int
    estimates: list[CapacityEstimate]
    measured_at: str = ""
    methodology: str = ""


# Default capacity model based on synthetic benchmarks
DEFAULT_CAPACITY = CapacityModel(
    node_count=1,
    estimates=[
        CapacityEstimate(
            component="Ingestion Worker",
            events_per_second=50_000,
            concurrent_analysts=0,
            tenants=100,
            notes="Batch processing with backpressure",
        ),
        CapacityEstimate(
            component="Inference Worker",
            events_per_second=500,
            concurrent_analysts=0,
            tenants=50,
            notes="Model inference per window",
        ),
        CapacityEstimate(
            component="API Gateway",
            events_per_second=1_000,
            concurrent_analysts=1_000,
            tenants=200,
            notes="REST API endpoints",
        ),
        CapacityEstimate(
            component="Database",
            events_per_second=10_000,
            concurrent_analysts=100,
            tenants=100,
            notes="Postgres with connection pooling",
        ),
    ],
    methodology="k6 load tests on synthetic data",
)


def get_capacity_model() -> CapacityModel:
    """Get the capacity model."""
    return DEFAULT_CAPACITY


def estimate_node_count(target_events_per_second: int) -> int:
    """Estimate number of nodes needed for target throughput."""
    ingestion_capacity = DEFAULT_CAPACITY.estimates[0].events_per_second
    if ingestion_capacity <= 0:
        return 1
    return max(1, -(-target_events_per_second // ingestion_capacity))
