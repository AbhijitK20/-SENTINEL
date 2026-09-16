"""Verify that core modules import cleanly without optional dependencies.

Covers acceptance criteria AC4 for S1-T1: each core module must be importable
when torch, scapy, fastapi, and streamlit are hidden via sys.modules patching.
Torch-requiring codepaths are expected to raise RuntimeError, not ImportError.
"""

from __future__ import annotations

import importlib
import sys
import types
from collections.abc import Sequence

import pytest

# Modules that must import without any optional dependency.
CORE_MODULES: Sequence[str] = [
    "trajectory.ingestion",
    "trajectory.state_builder",
    "trajectory.features",
    "trajectory.baseline",
    "trajectory.predict",
    "trajectory.stage_mapping",
    "trajectory.detectors",
    "trajectory.evaluation",
    "trajectory.schemas",
    "trajectory.config",
    "trajectory.targets",
    "trajectory.calibration",
    "trajectory.correlation",
    "trajectory.assets",
    "trajectory.cases",
    "trajectory.drift",
    "trajectory.compliance",
    "trajectory.feedback",
    "trajectory.ledger",
]

OPTIONAL_MODULES = ("torch", "scapy", "fastapi", "streamlit")


class _HideOptionalImporter:
    """Meta path finder that blocks imports of specified top-level packages.

    Unlike setting sys.modules[name] = None, this makes ``import torch``
    raise ImportError, which is what the codebase's try/except blocks expect
    and what scipy's introspection can survive.
    """

    def __init__(self, blocked: tuple[str, ...]) -> None:
        self._blocked = set(blocked)

    def find_module(
        self, fullname: str, path: Sequence[str] | None = None
    ) -> types.ModuleType | None:
        top = fullname.split(".")[0]
        if top in self._blocked:
            return self
        return None

    def load_module(self, fullname: str) -> types.ModuleType:
        raise ImportError(f"Blocked optional dependency: {fullname}")


@pytest.fixture()
def hide_optional_deps(monkeypatch: pytest.MonkeyPatch):
    """Temporarily make optional top-level packages appear absent.

    Saves and restores the *entire* ``sys.modules`` snapshot so that modules
    which were already imported (and cached references to torch/scapy/etc.)
    are restored to their pre-test state.  This prevents leakage across test
    files in the same process.
    """
    # Snapshot the current state so we can fully restore it later.
    saved_modules = dict(sys.modules)
    saved_meta_path = list(sys.meta_path)

    # Remove any already-imported optional deps and their submodules.
    for mod_name in OPTIONAL_MODULES:
        sys.modules.pop(mod_name, None)
        prefix = mod_name + "."
        for k in [k for k in sys.modules if k.startswith(prefix)]:
            sys.modules.pop(k, None)

    # Install a meta path finder that blocks future imports.
    finder = _HideOptionalImporter(OPTIONAL_MODULES)
    sys.meta_path.insert(0, finder)

    yield

    # Fully restore sys.modules and sys.meta_path to the pre-test snapshot.
    sys.modules.clear()
    sys.modules.update(saved_modules)
    sys.meta_path[:] = saved_meta_path


@pytest.mark.parametrize("module_name", CORE_MODULES)
def test_core_module_imports_without_optional_deps(module_name: str, hide_optional_deps):
    """Each core module must be importable when optional deps are absent."""
    # Force re-import so the patched sys.modules takes effect.
    if module_name in sys.modules:
        del sys.modules[module_name]
    mod = importlib.import_module(module_name)
    assert mod is not None, f"{module_name} imported as None"


def test_predict_imports_without_torch(monkeypatch: pytest.MonkeyPatch):
    """AC1: importing trajectory.predict must not fail when torch is absent."""
    finder = _HideOptionalImporter(("torch",))
    monkeypatch.setattr(sys, "meta_path", [finder] + sys.meta_path, raising=False)
    for k in list(sys.modules):
        if k == "torch" or k.startswith("torch."):
            monkeypatch.delitem(sys.modules, k, raising=False)
    if "trajectory.predict" in sys.modules:
        del sys.modules["trajectory.predict"]
    mod = importlib.import_module("trajectory.predict")
    assert hasattr(mod, "ForecastArtifacts")


def test_temporal_raises_runtime_error_not_import_error(
    monkeypatch: pytest.MonkeyPatch,
):
    """AC2: torch-requiring tests must raise RuntimeError, not ImportError."""
    finder = _HideOptionalImporter(("torch",))
    monkeypatch.setattr(sys, "meta_path", [finder] + sys.meta_path, raising=False)
    for k in list(sys.modules):
        if k == "torch" or k.startswith("torch."):
            monkeypatch.delitem(sys.modules, k, raising=False)
    if "trajectory.temporal" in sys.modules:
        del sys.modules["trajectory.temporal"]
    mod = importlib.import_module("trajectory.temporal")
    with pytest.raises(RuntimeError, match="PyTorch"):
        mod._require_torch()
