# SPDX-License-Identifier: Apache-2.0
"""MITRE ATT&CK techniques — reduced set for network-observable attacks."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Technique:
    """MITRE ATT&CK technique."""

    id: str
    name: str
    tactic_id: str
    description: str
    platforms: list[str]
    data_sources: list[str]


TECHNIQUES: dict[str, Technique] = {
    "T1046": Technique(
        id="T1046",
        name="Network Service Discovery",
        tactic_id="TA0007",
        description="Adversaries may attempt to get a listing of services running on remote hosts.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Network intrusion detection system"],
    ),
    "T1040": Technique(
        id="T1040",
        name="Network Sniffing",
        tactic_id="TA0006",
        description="Adversaries may attempt to get a listing of services running on remote hosts.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic"],
    ),
    "T1110": Technique(
        id="T1110",
        name="Brute Force",
        tactic_id="TA0006",
        description="Adversaries may use brute force techniques to gain access to accounts.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Authentication logs"],
    ),
    "T1110.001": Technique(
        id="T1110.001",
        name="Password Guessing",
        tactic_id="TA0006",
        description="Adversaries may attempt to get a listing of accounts.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Authentication logs"],
    ),
    "T1021": Technique(
        id="T1021",
        name="Remote Services",
        tactic_id="TA0008",
        description="Adversaries may use valid accounts to log into a service.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Authentication logs"],
    ),
    "T1021.001": Technique(
        id="T1021.001",
        name="Remote Desktop Protocol",
        tactic_id="TA0008",
        description="Adversaries may use RDP to move laterally.",
        platforms=["Windows"],
        data_sources=["Network traffic", "Authentication logs"],
    ),
    "T1021.002": Technique(
        id="T1021.002",
        name="SMB/Windows Admin Shares",
        tactic_id="TA0008",
        description="Adversaries may use SMB to interact with admin shares.",
        platforms=["Windows"],
        data_sources=["Network traffic", "Authentication logs"],
    ),
    "T1071": Technique(
        id="T1071",
        name="Application Layer Protocol",
        tactic_id="TA0011",
        description="Adversaries may communicate using application layer protocols.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Packet capture"],
    ),
    "T1071.001": Technique(
        id="T1071.001",
        name="Web Protocols",
        tactic_id="TA0011",
        description="Adversaries may communicate using HTTP/HTTPS.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Packet capture"],
    ),
    "T1071.004": Technique(
        id="T1071.004",
        name="DNS",
        tactic_id="TA0011",
        description="Adversaries may communicate using DNS.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Packet capture"],
    ),
    "T1048": Technique(
        id="T1048",
        name="Exfiltration Over Alternative Protocol",
        tactic_id="TA0010",
        description="Adversaries may steal data by exfiltrating it over a different protocol.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Packet capture"],
    ),
    "T1048.001": Technique(
        id="T1048.001",
        name="Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
        tactic_id="TA0010",
        description="Adversaries may steal data by exfiltrating it over an encrypted protocol.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Packet capture"],
    ),
    "T1566": Technique(
        id="T1566",
        name="Phishing",
        tactic_id="TA0001",
        description="Adversaries may send phishing messages to gain access.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Email gateway", "Network traffic"],
    ),
    "T1566.001": Technique(
        id="T1566.001",
        name="Spearphishing Attachment",
        tactic_id="TA0001",
        description="Adversaries may send spearphishing emails with a malicious attachment.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Email gateway", "File monitoring"],
    ),
    "T1059": Technique(
        id="T1059",
        name="Command and Scripting Interpreter",
        tactic_id="TA0002",
        description="Adversaries may abuse command and script interpreters.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Process monitoring", "Command history"],
    ),
    "T1078": Technique(
        id="T1078",
        name="Valid Accounts",
        tactic_id="TA0001",
        description="Adversaries may obtain and abuse credentials of existing accounts.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Authentication logs"],
    ),
    "T1498": Technique(
        id="T1498",
        name="Network Denial of Service",
        tactic_id="TA0040",
        description="Adversaries may attempt to cause a denial of service.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Netflow"],
    ),
    "T1572": Technique(
        id="T1572",
        name="Protocol Tunneling",
        tactic_id="TA0011",
        description="Adversaries may tunnel network communications.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Packet capture"],
    ),
    "T1573": Technique(
        id="T1573",
        name="Encrypted Channel",
        tactic_id="TA0011",
        description="Adversaries may conceal C2 communications with encryption.",
        platforms=["Linux", "Windows", "macOS"],
        data_sources=["Network traffic", "Packet capture"],
    ),
}


def get_technique(technique_id: str) -> Technique | None:
    """Get technique by ID."""
    return TECHNIQUES.get(technique_id)


def get_techniques_by_tactic(tactic_id: str) -> list[Technique]:
    """Get all techniques for a tactic."""
    return [t for t in TECHNIQUES.values() if t.tactic_id == tactic_id]


def list_techniques() -> list[Technique]:
    """List all techniques."""
    return list(TECHNIQUES.values())
