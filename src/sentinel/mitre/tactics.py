# SPDX-License-Identifier: Apache-2.0
"""MITRE ATT&CK tactics."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Tactic:
    """MITRE ATT&CK tactic."""

    id: str
    name: str
    description: str
    shortname: str


TACTICS: dict[str, Tactic] = {
    "TA0043": Tactic(
        id="TA0043",
        name="Reconnaissance",
        description="Adversaries may gather information to plan future operations.",
        shortname="reconnaissance",
    ),
    "TA0001": Tactic(
        id="TA0001",
        name="Initial Access",
        description="Adversaries may attempt to get a foothold onto your network.",
        shortname="initial-access",
    ),
    "TA0002": Tactic(
        id="TA0002",
        name="Execution",
        description="Adversaries may run malicious code on a system.",
        shortname="execution",
    ),
    "TA0003": Tactic(
        id="TA0003",
        name="Persistence",
        description="Adversaries may attempt to maintain access to systems.",
        shortname="persistence",
    ),
    "TA0004": Tactic(
        id="TA0004",
        name="Privilege Escalation",
        description="Adversaries may attempt to gain higher-level permissions.",
        shortname="privilege-escalation",
    ),
    "TA0005": Tactic(
        id="TA0005",
        name="Defense Evasion",
        description="Adversaries may attempt to avoid being detected.",
        shortname="defense-evasion",
    ),
    "TA0006": Tactic(
        id="TA0006",
        name="Credential Access",
        description="Adversaries may attempt to get account credentials.",
        shortname="credential-access",
    ),
    "TA0007": Tactic(
        id="TA0007",
        name="Discovery",
        description="Adversaries may attempt to learn about the system and internal network.",
        shortname="discovery",
    ),
    "TA0008": Tactic(
        id="TA0008",
        name="Lateral Movement",
        description="Adversaries may move through the network.",
        shortname="lateral-movement",
    ),
    "TA0009": Tactic(
        id="TA0009",
        name="Collection",
        description="Adversaries may attempt to gather data of interest.",
        shortname="collection",
    ),
    "TA0010": Tactic(
        id="TA0010",
        name="Exfiltration",
        description="Adversaries may attempt to steal data.",
        shortname="exfiltration",
    ),
    "TA0011": Tactic(
        id="TA0011",
        name="Command and Control",
        description="Adversaries may communicate with systems they control.",
        shortname="command-and-control",
    ),
    "TA0040": Tactic(
        id="TA0040",
        name="Impact",
        description="Adversaries may attempt to disrupt or compromise systems.",
        shortname="impact",
    ),
}


def get_tactic(tactic_id: str) -> Tactic | None:
    """Get tactic by ID."""
    return TACTICS.get(tactic_id)


def get_tactic_by_name(name: str) -> Tactic | None:
    """Get tactic by name (case-insensitive)."""
    name_lower = name.lower()
    for tactic in TACTICS.values():
        if tactic.name.lower() == name_lower or tactic.shortname == name_lower:
            return tactic
    return None


def list_tactics() -> list[Tactic]:
    """List all tactics in order."""
    return list(TACTICS.values())
