"""Unit tests for scripts/validate_real_detectors.py scoring.

The harness itself needs the demo stack (docker) to run; these tests pin the
pure scoring logic without any network or containers.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "validate_real_detectors.py"
spec = importlib.util.spec_from_file_location("validate_real_detectors", SCRIPT)
validate_real_detectors = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = validate_real_detectors  # dataclasses need the module registered
spec.loader.exec_module(validate_real_detectors)  # type: ignore[union-attr]

_verdict = validate_real_detectors._verdict


def test_no_claim_is_neither_hit_nor_miss() -> None:
    assert _verdict(set(), set()) == "NO-CLAIM"
    assert _verdict(set(), {"reconnaissance"}) == "NO-CLAIM"


def test_all_claimed_detectors_seen_is_hit() -> None:
    assert _verdict({"reconnaissance"}, set()) == "HIT"
    assert _verdict({"reconnaissance", "exfiltration"}, set()) == "HIT"


def test_any_missed_claim_is_miss() -> None:
    assert _verdict({"reconnaissance", "exfiltration"}, {"exfiltration"}) == "MISS"


def test_scenario_modules_use_the_attacks_namespace() -> None:
    """The attack modules import each other as `attacks.*` (see full_chain)."""
    for scenario in validate_real_detectors.SCENARIOS:
        assert scenario.module.startswith("attacks."), scenario.module
