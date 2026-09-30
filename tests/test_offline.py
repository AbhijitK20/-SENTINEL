"""Offline-operation verification (Definition of Done: UI And Demo).

The runtime must not depend on cloud APIs. This test pins the configuration
contract and statically asserts that no network client is imported anywhere
under ``src/sentinel``.
"""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.config import load_settings

SRC = Path(__file__).resolve().parent.parent / "src" / "sentinel"

NETWORK_MODULES = (
    "import requests",
    "import urllib",
    "import httpx",
    "import socket",
    "import aiohttp",
    "import http.client",
    "import boto3",
    "import google.cloud",
)


def test_runtime_is_configured_offline() -> None:
    settings = load_settings("configs/default.yaml")
    assert settings.runtime.offline is True
    assert settings.runtime.device == "cpu"


def test_no_network_imports_in_source() -> None:
    offenders: list[str] = []
    # alerts.py is a notification module, not part of the offline-first core.
    # tabs/targets.py is a reachability monitor: it cannot answer "is the target
    # up?" without a socket. Both are the same kind of exception, so the
    # exclusion is listed explicitly and asserted by
    # test_offline_exclusions_are_still_justified below.
    exclude = {"alerts.py", os.path.join("dashboard", "tabs", "targets.py")}
    for path in SRC.rglob("*.py"):
        if str(Path(path).relative_to(SRC)) in exclude:
            continue
        text = path.read_text(encoding="utf-8")
        for module in NETWORK_MODULES:
            if module in text:
                offenders.append(f"{path.name}: {module}")
    assert not offenders, f"network clients found in offline source: {offenders}"


def test_no_cloud_urls_in_source() -> None:
    """No https:// API endpoints in runtime source (doc URLs in adapters excluded)."""
    offenders: list[str] = []
    for path in SRC.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for line in text.splitlines():
            stripped = line.strip()
            if "https://" in stripped and "unb.ca" not in stripped and "#" in stripped:
                continue
            if "https://api." in stripped or "https://cloud" in stripped:
                offenders.append(f"{path.name}: {stripped[:60]}")
    assert not offenders, f"cloud API endpoints found: {offenders}"


def test_offline_exclusions_are_still_justified() -> None:
    """Every offline-first exclusion must still be a network-touching leaf.

    A blanket exclusion is how an offline core quietly grows network clients.
    Each exempt module has to keep a network import - if a refactor removes it,
    the exemption is dead weight and this fails so it can be deleted.
    """
    exemptions = {
        "alerts.py": "alerting sends notifications",
        os.path.join("dashboard", "tabs", "targets.py"): "reachability monitor probes hosts",
    }
    for relative, reason in exemptions.items():
        path = SRC / relative
        assert path.is_file(), relative
        text = path.read_text(encoding="utf-8")
        assert any(m in text for m in NETWORK_MODULES), f"{relative}: {reason}"
