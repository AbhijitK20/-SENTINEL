"""Verify that core modules import cleanly without optional dependencies.

Covers acceptance criteria AC4 for S1-T1: each core module must be importable
when torch, scapy, fastapi, and streamlit are hidden. Torch-requiring codepaths
are expected to raise RuntimeError, not ImportError.

Each check runs in a fresh subprocess. In-process ``sys.modules`` surgery on
already-loaded C extensions (numpy, torch) makes Python raise
``ImportError: cannot load module more than once per process`` and can
segfault, so isolation is not optional here.
"""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Modules that must import without any optional dependency.
CORE_MODULES: Sequence[str] = [
    "sentinel.ingestion",
    "sentinel.state_builder",
    "sentinel.features",
    "sentinel.baseline",
    "sentinel.predict",
    "sentinel.stage_mapping",
    "sentinel.detectors",
    "sentinel.evaluation",
    "sentinel.schemas",
    "sentinel.config",
    "sentinel.targets",
    "sentinel.calibration",
    "sentinel.correlation",
    "sentinel.assets",
    "sentinel.cases",
    "sentinel.drift",
    "sentinel.compliance",
    "sentinel.feedback",
    "sentinel.ledger",
]

OPTIONAL_MODULES = ("torch", "scapy", "fastapi", "streamlit")

# Runs before the check body: blocks imports of the optional top-level packages.
_HIDE_OPTIONAL = """
import sys

class _HideOptionalImporter:
    def __init__(self, blocked):
        self._blocked = set(blocked)

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in self._blocked:
            raise ImportError(f"Blocked optional dependency: {fullname}")
        return None

sys.meta_path.insert(0, _HideOptionalImporter(BLOCKED))
"""


def _run_without_optional_deps(body: str, blocked: Sequence[str] = OPTIONAL_MODULES) -> str:
    program = f"BLOCKED = {tuple(blocked)!r}\n{_HIDE_OPTIONAL}\n{body}"
    result = subprocess.run(
        [sys.executable, "-c", program],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"subprocess failed (exit {result.returncode})\n"
        f"--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}"
    )
    return result.stdout


@pytest.mark.parametrize("module_name", CORE_MODULES)
def test_core_module_imports_without_optional_deps(module_name: str) -> None:
    """Each core module must be importable when optional deps are absent."""
    _run_without_optional_deps(
        f"import importlib\nmod = importlib.import_module({module_name!r})\n"
        f"assert mod is not None, {module_name!r} + ' imported as None'\n"
        f"print({module_name!r} + ' OK')\n"
    )


def test_predict_imports_without_torch() -> None:
    """AC1: importing sentinel.predict must not fail when torch is absent."""
    out = _run_without_optional_deps(
        "from sentinel.predict import ForecastArtifacts\nprint(ForecastArtifacts.__name__)\n",
        blocked=("torch",),
    )
    assert "ForecastArtifacts" in out


def test_temporal_raises_runtime_error_not_import_error() -> None:
    """AC2: torch-requiring tests must raise RuntimeError, not ImportError."""
    _run_without_optional_deps(
        "from sentinel import temporal\n"
        "try:\n"
        "    temporal._require_torch()\n"
        "except RuntimeError as exc:\n"
        "    assert 'PyTorch' in str(exc), str(exc)\n"
        "    print('RuntimeError OK')\n"
        "else:\n"
        "    raise SystemExit('expected RuntimeError from _require_torch()')\n",
        blocked=("torch",),
    )
