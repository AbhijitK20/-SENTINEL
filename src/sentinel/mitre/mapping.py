# SPDX-License-Identifier: Apache-2.0
"""MITRE ATT&CK mapping from dataset labels to techniques."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class LabelMapping:
    """Mapping from dataset label to ATT&CK technique."""

    label: str
    technique_id: str
    tactic_id: str
    rationale: str
    dataset: str


# CIC-IDS2017 label mappings
CIC_IDS2017_MAPPINGS: list[LabelMapping] = [
    LabelMapping(
        label="BENIGN",
        technique_id="",
        tactic_id="",
        rationale="Normal traffic, no attack technique",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="FTP-Patator",
        technique_id="T1110.001",
        tactic_id="TA0006",
        rationale="FTP brute force attempt with password guessing",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="SSH-Patator",
        technique_id="T1110.001",
        tactic_id="TA0006",
        rationale="SSH brute force attempt with password guessing",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="DoS slowloris",
        technique_id="T1498",
        tactic_id="TA0040",
        rationale="Slow-rate HTTP DoS attack",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="DoS Slowhttptest",
        technique_id="T1498",
        tactic_id="TA0040",
        rationale="HTTP slow-rate DoS attack",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="DoS Hulk",
        technique_id="T1498",
        tactic_id="TA0040",
        rationale="High-volume HTTP DoS attack",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="DoS GoldenEye",
        technique_id="T1498",
        tactic_id="TA0040",
        rationale="HTTP GET flood DoS attack",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="Heartbleed",
        technique_id="T1040",
        tactic_id="TA0006",
        rationale="Heartbleed OpenSSL vulnerability exploitation",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="Web Attack - Brute Force",
        technique_id="T1110.001",
        tactic_id="TA0006",
        rationale="Web application brute force attack",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="Web Attack - XSS",
        technique_id="T1059",
        tactic_id="TA0002",
        rationale="Cross-site scripting attack",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="Web Attack - Sql Injection",
        technique_id="T1059",
        tactic_id="TA0002",
        rationale="SQL injection attack",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="Infiltration",
        technique_id="T1078",
        tactic_id="TA0001",
        rationale="Infiltration attempt using valid accounts",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="Bot",
        technique_id="T1071.001",
        tactic_id="TA0011",
        rationale="Botnet C2 communication over HTTP",
        dataset="CIC-IDS2017",
    ),
    LabelMapping(
        label="PortScan",
        technique_id="T1046",
        tactic_id="TA0007",
        rationale="Network port scanning for service discovery",
        dataset="CIC-IDS2017",
    ),
]


def get_label_mapping(label: str, dataset: str = "CIC-IDS2017") -> LabelMapping | None:
    """Get mapping for a dataset label."""
    for mapping in CIC_IDS2017_MAPPINGS:
        if mapping.label == label and mapping.dataset == dataset:
            return mapping
    return None


def get_all_mappings(dataset: str = "CIC-IDS2017") -> list[LabelMapping]:
    """Get all mappings for a dataset."""
    return [m for m in CIC_IDS2017_MAPPINGS if m.dataset == dataset]


def map_prediction_to_techniques(
    prediction: float,
    stage: str,
    confidence: str,
) -> list[dict[str, str]]:
    """Map a prediction to ATT&CK techniques with rationale."""
    mappings = {
        "Reconnaissance": {"technique": "T1046", "tactic": "TA0007"},
        "Initial Access": {"technique": "T1566", "tactic": "TA0001"},
        "Lateral Movement": {"technique": "T1021", "tactic": "TA0008"},
        "Command and Control": {"technique": "T1071", "tactic": "TA0011"},
        "Exfiltration": {"technique": "T1048", "tactic": "TA0010"},
    }

    if stage not in mappings:
        return []

    mapping = mappings[stage]
    return [
        {
            "technique_id": mapping["technique"],
            "tactic_id": mapping["tactic"],
            "confidence": confidence,
            "rationale": f"Stage {stage} with prediction {prediction:.3f}",
        }
    ]
