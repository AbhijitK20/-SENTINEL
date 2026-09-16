# SPDX-License-Identifier: Apache-2.0
"""Deterministic educational attack stories for the SENTINEL dashboard.

The Dubsmash story is explicitly illustrative: public reporting describes the
impact and exposed data, but does not establish every technical step shown
here. The scenario uses synthetic hosts and records only.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CaseStudyPhase:
    """One phase in an attack story."""

    number: int
    name: str
    summary: str
    source: str
    destination: str
    protocol: str
    port: int
    evidence: tuple[str, ...]
    status: str
    attack_type: str


@dataclass(frozen=True)
class PacketFlowStep:
    """Human-readable packet/application flow step."""

    layer: str
    source: str
    destination: str
    action: str
    status: str


def dubsmash_inspired_case() -> tuple[CaseStudyPhase, ...]:
    """Return a synthetic, bounded credential-reuse breach workflow."""
    return (
        CaseStudyPhase(
            1,
            "Credential source",
            "Synthetic credential pairs are reused from an unrelated breach.",
            "credential-dump",
            "attacker-01",
            "HTTPS",
            443,
            ("reused credentials", "external source", "automation"),
            "observed in scenario",
            "credential_abuse",
        ),
        CaseStudyPhase(
            2,
            "Credential stuffing",
            "Automated login attempts target many accounts on the public API.",
            "attacker-01",
            "web-api-01",
            "HTTPS",
            443,
            ("high login rate", "many accounts", "failed-auth burst"),
            "detected",
            "credential_abuse",
        ),
        CaseStudyPhase(
            3,
            "Valid account access",
            "A reused credential succeeds after the failed-attempt burst.",
            "attacker-01",
            "auth-service",
            "HTTPS",
            443,
            ("success after failures", "new source", "session issued"),
            "detected",
            "credential_abuse",
        ),
        CaseStudyPhase(
            4,
            "Discovery and collection",
            "The session enumerates APIs and requests sensitive records.",
            "web-api-01",
            "database-primary",
            "TCP",
            3306,
            ("admin path", "API enumeration", "large result set"),
            "detected",
            "exfiltration",
        ),
        CaseStudyPhase(
            5,
            "Exfiltration",
            "A bounded synthetic sample represents a much larger data theft.",
            "web-api-01",
            "external-destination",
            "HTTPS",
            443,
            ("outbound volume", "sensitive dataset", "external destination"),
            "contained in demo",
            "exfiltration",
        ),
    )


def packet_flow_steps() -> tuple[PacketFlowStep, ...]:
    """Return the TCP and application flow used by the case-study diagram."""
    return (
        PacketFlowStep("TCP", "attacker-01", "edge-firewall", "SYN :443", "normal"),
        PacketFlowStep("TCP", "edge-firewall", "attacker-01", "SYN-ACK", "normal"),
        PacketFlowStep("TCP", "attacker-01", "edge-firewall", "ACK", "normal"),
        PacketFlowStep("HTTP", "attacker-01", "web-api-01", "POST /login", "suspicious"),
        PacketFlowStep("DB", "web-api-01", "database-primary", "SELECT auth record", "suspicious"),
        PacketFlowStep("HTTP", "web-api-01", "attacker-01", "401 Unauthorized", "suspicious"),
        PacketFlowStep("HTTP", "attacker-01", "web-api-01", "POST /login reused pair", "malicious"),
        PacketFlowStep("HTTP", "web-api-01", "attacker-01", "302 session issued", "malicious"),
        PacketFlowStep("HTTP", "attacker-01", "web-api-01", "GET /admin/users.json", "malicious"),
        PacketFlowStep("DB", "web-api-01", "database-primary", "SELECT users", "malicious"),
        PacketFlowStep("HTTP", "web-api-01", "attacker-01", "large JSON response", "malicious"),
    )


def case_study_topology() -> tuple[dict[str, str], tuple[dict[str, object], ...]]:
    """Return synthetic nodes and weighted edges for the topology graphic."""
    nodes = {
        "attacker-01": "External attacker",
        "edge-firewall": "Firewall / load balancer",
        "web-api-01": "Web/API server",
        "auth-service": "Authentication service",
        "database-primary": "Primary database",
        "external-destination": "External destination",
        "sentinel-sensor": "SENTINEL sensor",
    }
    edges = tuple(
        {
            "source": phase.source,
            "destination": phase.destination,
            "label": phase.name,
            "protocol": phase.protocol,
            "port": phase.port,
            "bytes": 48000.0 if phase.number >= 4 else 1200.0,
            "severity": (
                "high"
                if phase.status == "detected"
                else "critical"
                if phase.status == "contained in demo"
                else "medium"
            ),
        }
        for phase in dubsmash_inspired_case()
    )
    return nodes, edges


def replay_topology(
    phase_number: int,
    *,
    contained: bool = False,
) -> tuple[dict[str, str], tuple[dict[str, object], ...]]:
    """Return topology edges visible up to a replay phase.

    ``contained`` models the administrator pruning the attacker branch at the
    edge firewall. It is deliberately a simulation state, not a real firewall
    command.
    """
    nodes, edges = case_study_topology()
    phases = dubsmash_inspired_case()
    visible = tuple(
        edge for edge, phase in zip(edges, phases, strict=True) if phase.number <= phase_number
    )
    if contained:
        visible = tuple(
            {**edge, "severity": "normal", "blocked": True}
            for edge in visible
            if edge["source"] != "attacker-01"
        )
    return nodes, visible
