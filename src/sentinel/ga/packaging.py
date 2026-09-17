# SPDX-License-Identifier: Apache-2.0
"""Packaging for SENTINEL."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HelmChart:
    """Helm chart configuration."""

    name: str
    version: str
    app_version: str
    description: str = ""
    maintainers: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)


@dataclass
class DockerCompose:
    """Docker Compose configuration."""

    services: list[str] = field(default_factory=list)
    volumes: list[str] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)


@dataclass
class ReleaseArtifact:
    """Release artifact metadata."""

    name: str
    version: str
    sha256: str
    signed: bool = False
    sbom_included: bool = False


# Default Helm chart
DEFAULT_HELM_CHART = HelmChart(
    name="sentinel",
    version="0.1.0",
    app_version="0.1.0",
    description="SENTINEL - Network Threat Intelligence Forecasting Platform",
    maintainers=["SENTINEL Team"],
    dependencies=["postgresql", "redis"],
)

# Default Docker Compose
DEFAULT_DOCKER_COMPOSE = DockerCompose(
    services=["sentinel-api", "sentinel-worker", "sentinel-db", "sentinel-redis"],
    volumes=["sentinel-data", "sentinel-models"],
    networks=["sentinel-network"],
)


def get_helm_chart() -> HelmChart:
    """Get the Helm chart configuration."""
    return DEFAULT_HELM_CHART


def get_docker_compose() -> DockerCompose:
    """Get the Docker Compose configuration."""
    return DEFAULT_DOCKER_COMPOSE
