# SPDX-License-Identifier: Apache-2.0
"""Metrics for SENTINEL observability."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Metric:
    """Metric definition."""

    name: str
    description: str
    unit: str
    labels: list[str]


# RED metrics (Rate/Errors/Duration)
RED_METRICS: list[Metric] = [
    Metric(
        name="http_requests_total",
        description="Total HTTP requests",
        unit="count",
        labels=["method", "path", "status"],
    ),
    Metric(
        name="http_request_duration_seconds",
        description="HTTP request duration",
        unit="seconds",
        labels=["method", "path"],
    ),
    Metric(
        name="http_request_errors_total",
        description="Total HTTP request errors",
        unit="count",
        labels=["method", "path", "status"],
    ),
]

# Domain metrics
DOMAIN_METRICS: list[Metric] = [
    Metric(
        name="windows_processed_total",
        description="Total windows processed",
        unit="count",
        labels=["tenant_id"],
    ),
    Metric(
        name="forecasts_generated_total",
        description="Total forecasts generated",
        unit="count",
        labels=["tenant_id"],
    ),
    Metric(
        name="model_inference_duration_seconds",
        description="Model inference duration",
        unit="seconds",
        labels=["model_name"],
    ),
    Metric(
        name="queue_depth",
        description="Queue depth",
        unit="count",
        labels=["queue_name"],
    ),
    Metric(
        name="detection_rate",
        description="Detection rate",
        unit="count",
        labels=["attack_type"],
    ),
]


def get_all_metrics() -> list[Metric]:
    """Get all metrics."""
    return RED_METRICS + DOMAIN_METRICS


def get_metric_by_name(name: str) -> Metric | None:
    """Get metric by name."""
    for metric in get_all_metrics():
        if metric.name == name:
            return metric
    return None
