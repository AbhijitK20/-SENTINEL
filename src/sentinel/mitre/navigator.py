# SPDX-License-Identifier: Apache-2.0
"""ATT&CK Navigator layer export."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from sentinel.mitre.tactics import TACTICS
from sentinel.mitre.techniques import TECHNIQUES


def export_layer(
    techniques_used: list[dict[str, Any]],
    name: str = "SENTINEL Detection Layer",
    description: str = "Techniques detected by SENTINEL",
) -> dict[str, Any]:
    """Export an ATT&CK Navigator layer JSON.

    Args:
        techniques_used: List of dicts with technique_id and score.
        name: Layer name.
        description: Layer description.

    Returns:
        Navigator layer JSON that loads in the official ATT&CK Navigator.
    """
    # Build technique scores
    technique_scores = {}
    for item in techniques_used:
        tid = item["technique_id"]
        score = item.get("score", 1)
        technique_scores[tid] = max(technique_scores.get(tid, 0), score)

    # Build layer
    layer = {
        "name": name,
        "versions": {
            "attack": "14.0",
            "navigator": "4.8.1",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": description,
        "created": datetime.now(UTC).isoformat(),
        "techniques": [],
        "gradient": {
            "colors": [
                "#ffffff",
                "#ff6b6b",
            ],
            "minValue": 0,
            "maxValue": 1,
        },
        "legendItems": [
            {"label": "Detected", "color": "#ff6b6b"},
            {"label": "Not Detected", "color": "#ffffff"},
        ],
        "selectTechniques": [],
        "selectSubtechniques": [],
    }

    # Add techniques
    for tid, score in technique_scores.items():
        if tid in TECHNIQUES:
            technique = TECHNIQUES[tid]
            layer["techniques"].append(
                {
                    "techniqueID": tid,
                    "tactic": TACTICS.get(technique.tactic_id, {}).shortname
                    if technique.tactic_id in TACTICS
                    else "",
                    "color": "#ff6b6b" if score > 0 else "#ffffff",
                    "comment": f"Score: {score}",
                    "enabled": True,
                    "metadata": [
                        {"name": "score", "value": str(score)},
                        {"name": "technique_name", "value": technique.name},
                    ],
                    "links": [],
                    "showSubtechniques": False,
                }
            )

    return layer


def layer_to_json(layer: dict[str, Any], indent: int = 2) -> str:
    """Convert layer to JSON string."""
    return json.dumps(layer, indent=indent)


def save_layer(layer: dict[str, Any], path: str) -> None:
    """Save layer to file."""
    with open(path, "w") as f:
        f.write(layer_to_json(layer))
