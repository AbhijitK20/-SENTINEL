# SPDX-License-Identifier: Apache-2.0
"""Attack-phase registry — single source of truth for the lab attack buttons.

Both the attack script (``scripts/full_attack.py``) and the dashboard
(``sentinel.dashboard.tabs.live``) read this module, so a phase can never be
offered as a button without the script also being able to run it.

``detector`` is the SENTINEL attack-type a phase is designed to trip and
``technique`` is derived from the canonical :data:`sentinel.detectors.MITRE`
map, so the two cannot drift.  ``detector: None`` means SENTINEL has no
detector for that phase; callers must surface that gap rather than imply
coverage.
"""

from __future__ import annotations

import json
from typing import Any

from sentinel.detectors import MITRE
from sentinel.schemas import UnifiedEvent

SUMMARY_MARKER = "---SENTINEL-SUMMARY-JSON---"

PHASES: list[dict[str, Any]] = [
    {
        "name": "ddos",
        "label": "DDoS Simulation",
        "description": "30 rapid requests to spike the flow rate",
        "detector": "ddos",
    },
    {
        "name": "recon",
        "label": "Port Scan",
        "description": "TCP port scan + directory brute-force",
        "detector": "reconnaissance",
    },
    {
        "name": "brute_force",
        "label": "Brute Force",
        "description": "15 credential-stuffing attempts against login",
        "detector": "credential_abuse",
    },
    {
        "name": "injection",
        "label": "Injection",
        "description": "12 SQLi / XSS / CMDi / path-traversal payloads",
        "detector": None,
    },
    {
        "name": "lateral",
        "label": "Lateral Movement",
        "description": "12 chained endpoint calls simulating a pivot",
        "detector": "lateral_movement",
    },
    {
        "name": "exfil",
        "label": "Data Exfiltration",
        "description": "6 bulk pulls with limit=1000",
        "detector": "exfiltration",
    },
    {
        "name": "c2",
        "label": "C2 Beaconing",
        "description": "8 periodic callbacks to the health endpoint",
        "detector": "command_and_control",
    },
    {
        "name": "insider",
        "label": "Insider Threat",
        "description": "6 off-hours admin accesses",
        "detector": "insider_threat",
    },
    {
        "name": "malware",
        "label": "Malware Staging",
        "description": "5 suspicious file uploads",
        "detector": "malware_activity",
    },
]

for _phase in PHASES:
    _key = _phase["detector"]
    _phase["technique"] = MITRE[_key] if _key else None

PHASE_NAMES: list[str] = [p["name"] for p in PHASES]


def phase_summary(name: str, events: list[UnifiedEvent]) -> dict[str, Any]:
    """What a phase actually extracted, measured from the responses it received."""
    statuses: dict[int, int] = {}
    for event in events:
        code = int(event.features.get("http_status", 0))
        statuses[code] = statuses.get(code, 0) + 1
    return {
        "phase": name,
        "provenance_tag": events[0].provenance.split(":")[1] if events else None,
        "events": len(events),
        "bytes_sent": sum(e.features.get("bytes_sent", 0.0) for e in events),
        "bytes_received": sum(e.features.get("bytes_received", 0.0) for e in events),
        "http_statuses": statuses,
        "endpoints": len({e.destination_entity for e in events}),
    }


def parse_summary(text: str) -> dict[str, Any]:
    """Read the machine-readable summary block printed by ``--summary-json``."""
    if SUMMARY_MARKER not in text:
        return {"phases": [], "push": {}}
    payload = text.split(SUMMARY_MARKER, 1)[1]
    summary = json.loads(payload[: payload.rindex("}") + 1])
    for row in summary.get("phases", []):
        row["http_statuses"] = {int(k): v for k, v in row.get("http_statuses", {}).items()}
    return summary
