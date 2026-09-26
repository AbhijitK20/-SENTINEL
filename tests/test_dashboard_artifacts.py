# SPDX-License-Identifier: Apache-2.0
"""The console must open on the shipped artifacts, and say which ones.

The Makefile has claimed "analyst console preloaded with the committed release
artifacts" while the dashboard ignored ``--artifacts`` entirely and always
trained in-session. These tests pin the resolution order, because the failure
mode is quiet: a console that loads the wrong bundle looks exactly like one that
loads the right one until the numbers disagree.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_APP = Path(__file__).resolve().parents[1] / "src" / "sentinel" / "dashboard" / "app.py"


def _load_resolver():
    """Pull ``resolve_artifact_dir`` out of the Streamlit script.

    The dashboard is a Streamlit script, not an importable module: importing it
    executes the whole app. Reading the source and exec'ing only the function
    keeps the logic testable without running Streamlit.
    """
    source = _APP.read_text(encoding="utf-8")
    start = source.index("ROOT = Path(__file__)")
    end = source.index("\ntry:\n    artifact_dir", start)
    namespace: dict = {"sys": sys, "Path": Path, "os": __import__("os"), "__file__": str(_APP)}
    exec(compile(source[start:end], str(_APP), "exec"), namespace)  # noqa: S102
    return namespace["resolve_artifact_dir"], namespace


resolve_artifact_dir, _ns = _load_resolver()
RELEASE_BUNDLE = _ns["RELEASE_BUNDLE"]


def test_explicit_flag_wins(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("SENTINEL_ARTIFACTS_DIR", raising=False)
    chosen = resolve_artifact_dir(["--artifacts", str(tmp_path)])
    assert chosen == tmp_path


def test_environment_is_used_when_no_flag(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("SENTINEL_ARTIFACTS_DIR", str(tmp_path))
    assert resolve_artifact_dir([]) == tmp_path


def test_a_named_directory_that_does_not_exist_raises_rather_than_substituting(
    tmp_path, monkeypatch
) -> None:
    # Being told "these are your artifacts" and silently getting a different
    # bundle is worse than an error.
    monkeypatch.delenv("SENTINEL_ARTIFACTS_DIR", raising=False)
    missing = tmp_path / "nope"
    with pytest.raises(FileNotFoundError, match="will not substitute"):
        resolve_artifact_dir(["--artifacts", str(missing)])


def test_a_flag_with_no_value_falls_through_to_auto_detection(monkeypatch) -> None:
    monkeypatch.delenv("SENTINEL_ARTIFACTS_DIR", raising=False)
    # `--artifacts` with nothing after it must not crash or resolve to cwd.
    chosen = resolve_artifact_dir(["--artifacts"])
    assert chosen is None or chosen == RELEASE_BUNDLE


def test_the_committed_bundle_is_found_by_default(monkeypatch) -> None:
    monkeypatch.delenv("SENTINEL_ARTIFACTS_DIR", raising=False)
    chosen = resolve_artifact_dir([])
    assert chosen == RELEASE_BUNDLE, (
        "the committed release bundle should load with no arguments, which is "
        "what makes `make demo` true"
    )


def test_the_release_bundle_really_does_load() -> None:
    from sentinel.predict import load_artifacts

    loaded = load_artifacts(RELEASE_BUNDLE)
    assert loaded.baseline_result.feature_schema.width > 0
    assert loaded.baseline_model is not None


def test_a_stale_bundle_is_skipped_not_fatal(tmp_path, monkeypatch) -> None:
    # A directory that exists but cannot load must fall through to the next
    # candidate rather than blocking startup. The resolver reads these as
    # globals from the exec'd namespace, so that is what gets replaced.
    monkeypatch.delenv("SENTINEL_ARTIFACTS_DIR", raising=False)
    stale = tmp_path / "stale"
    stale.mkdir()
    (stale / "baseline_result.json").write_text("{not json", encoding="utf-8")

    resolver, namespace = _load_resolver()
    namespace["RELEASE_BUNDLE"] = stale
    namespace["FALLBACK_ARTIFACT_DIRS"] = ()
    assert resolver([]) is None, "an unloadable bundle must be skipped, not fatal"


def test_the_console_renders_from_the_bundle_without_training(monkeypatch) -> None:
    """The whole point: opening the console must not retrain anything.

    Streamlit's AppTest cannot pass script arguments, so the env var route is
    exercised here; the `--artifacts` flag is covered by the resolver tests above
    and the Makefile sets both.
    """
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTINEL_ARTIFACTS_DIR", str(RELEASE_BUNDLE))
    at = AppTest.from_file(str(_APP), default_timeout=180)
    at.run()

    assert not at.exception, f"console raised: {[e.value for e in at.exception]}"
    header = " ".join(markdown.value for markdown in at.markdown)
    assert "98 features" in header
    assert "artifacts" in header, "the console must say which artifacts it loaded"
