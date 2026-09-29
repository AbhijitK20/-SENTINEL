# SPDX-License-Identifier: Apache-2.0
"""The console must open on the shipped artifacts, and say which ones.

The Makefile has claimed "analyst console preloaded with the committed release
artifacts" while the dashboard ignored ``--artifacts`` entirely and always
trained in-session. These tests pin the resolution order, because the failure
mode is quiet: a console that loads the wrong bundle looks exactly like one that
loads the right one until the numbers disagree.
"""

from __future__ import annotations

import json
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
SYNTHETIC_BUNDLE = _ns["SYNTHETIC_BUNDLE"]


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


def test_the_default_served_bundle_is_the_real_cic_trained_one() -> None:
    """Pin *which* bundle the console serves, not just that it describes it.

    The provenance test above reads RELEASE_BUNDLE out of the app, so it would
    pass just as happily if the app were pointed at the synthetic bundle - it
    checks the header is truthful, not that the answer is the one we want. This
    is the test that fails if someone reverts RELEASE_BUNDLE to `v1` and thereby
    quietly turns "trained on CIC-IDS2017" back into a claim about a generator.
    """
    manifest = json.loads((RELEASE_BUNDLE / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["dataset_id"] == "cic-ids2017-trafficlabelling-derived-v1", (
        f"the default bundle must be the one trained on real CIC-IDS2017 windows; "
        f"RELEASE_BUNDLE points at {RELEASE_BUNDLE.name}, whose dataset_id is "
        f"{manifest.get('dataset_id')!r}"
    )
    assert manifest["windows"] == 4899
    assert RELEASE_BUNDLE.name == "real-cic-v1"


def test_the_synthetic_bundle_is_kept_as_a_reachable_fallback() -> None:
    """The higher-scoring bundle stays shipped and selectable.

    Dropping it would make the F1 gap unrecoverable without a retrain, and would
    discard a bundle this project already verified. It is a fallback, not dead
    weight: --artifacts and SENTINEL_ARTIFACTS_DIR both reach it.
    """
    from sentinel.predict import load_artifacts

    assert SYNTHETIC_BUNDLE.is_dir(), "the synthetic bundle must stay in the repository"
    loaded = load_artifacts(SYNTHETIC_BUNDLE)
    assert loaded.baseline_result.feature_schema.width > 0

    # And it must be genuinely better, or calling it a fallback is a fiction.
    real_f1 = load_artifacts(RELEASE_BUNDLE).baseline_result.metrics["test"].f1
    synthetic_f1 = loaded.baseline_result.metrics["test"].f1
    assert synthetic_f1 > real_f1, (
        "the synthetic bundle is documented as the higher-F1 fallback; if that "
        f"reverses, the docs and this test both need revisiting (synthetic "
        f"{synthetic_f1:.3f} vs real {real_f1:.3f})"
    )


def test_the_console_renders_from_the_bundle_without_training(monkeypatch) -> None:
    """The whole point: opening the console must not retrain anything.

    Streamlit's AppTest cannot pass script arguments, so the env var route is
    exercised here; the `--artifacts` flag is covered by the resolver tests above
    and the Makefile sets both.
    """
    from streamlit.testing.v1 import AppTest

    from sentinel.predict import load_artifacts

    monkeypatch.setenv("SENTINEL_ARTIFACTS_DIR", str(RELEASE_BUNDLE))
    at = AppTest.from_file(str(_APP), default_timeout=180)
    at.run()

    assert not at.exception, f"console raised: {[e.value for e in at.exception]}"
    header = " ".join(markdown.value for markdown in at.markdown)
    # The feature count is read from the bundle rather than restated here. It
    # used to be the literal "98 features", which is the synthetic generator's
    # width; the served bundle is trained on the real aggregate and has a
    # different one, so a hardcoded number would have failed for the wrong reason.
    width = load_artifacts(RELEASE_BUNDLE).baseline_result.feature_schema.width
    assert f"{width} features" in header
    assert "artifacts" in header, "the console must say which artifacts it loaded"


def test_the_header_names_the_dataset_the_served_bundle_was_trained_on(monkeypatch) -> None:
    """A real-trained model must never be labelled synthetic, or the reverse.

    The header used to carry a hardcoded "synthetic generator (no real-trained
    bundle is shipped)" string. That stayed true only until a real-trained bundle
    was committed, at which point the console was lying to every visitor with no
    test failing. The claim is now derived from the bundle's MANIFEST, and this
    test pins that the two agree.
    """
    from streamlit.testing.v1 import AppTest

    manifest = json.loads((RELEASE_BUNDLE / "MANIFEST.json").read_text(encoding="utf-8"))
    dataset_id = manifest.get("dataset_id")
    assert dataset_id, (
        "the served bundle must record its dataset_id; the header reads the model "
        "provenance from the manifest and cannot state an origin that is not there"
    )

    monkeypatch.setenv("SENTINEL_ARTIFACTS_DIR", str(RELEASE_BUNDLE))
    at = AppTest.from_file(str(_APP), default_timeout=180)
    at.run()

    assert not at.exception, f"console raised: {[e.value for e in at.exception]}"
    header = " ".join(markdown.value for markdown in at.markdown)
    assert dataset_id in header, (
        "the header must name the dataset the served model was trained on, read "
        f"from MANIFEST.json; expected {dataset_id!r}"
    )
    assert "no real-trained bundle is shipped" not in header, (
        "that string is false now that a real-trained bundle ships, and must not come back"
    )


def test_a_bundle_without_a_manifest_still_names_something(tmp_path) -> None:
    """Missing or incomplete manifests degrade to a stated name, not a guess.

    Reporting "synthetic" because the manifest was missing would be inventing an
    origin, which is the failure this whole change exists to prevent. The two
    degraded cases are different facts - absent versus present-but-silent - so
    they get different wording.
    """
    source = _APP.read_text(encoding="utf-8")
    start = source.index("def _model_provenance")
    end = source.index("\ntry:\n    if use_derived", start)
    ns: dict = {"json": json, "Path": Path}
    exec(compile(source[start:end], str(_APP), "exec"), ns)  # noqa: S102
    describe = ns["_model_provenance"]

    # No manifest at all: say the manifest was unreadable, name the directory.
    assert "manifest unreadable" in describe(tmp_path, "some-dataset")
    assert "some-dataset" not in describe(tmp_path, "some-dataset")

    # A manifest that exists but records no dataset_id: the synthetic bundle
    # predates that field, and guessing its generator is exactly the drift this
    # function removes.
    (tmp_path / "MANIFEST.json").write_text(json.dumps({"bundle": "v1"}), encoding="utf-8")
    assert "not recorded" in describe(tmp_path, "some-dataset")
    assert "synthetic" not in describe(tmp_path, "some-dataset")

    # No bundle loaded at all: the model was trained in this session, on the
    # dataset named by the caller.
    assert describe(None, "some-dataset") == "trained in this session on some-dataset"


def test_cloud_hides_the_raw_csv_dataset_and_readonly_disables_retraining(monkeypatch) -> None:
    """The hosted surface must match what the host can actually provide.

    The licensed CSVs are not in the repository, so offering a raw-CSV option on
    Cloud leads to a 15-20 minute windowing attempt that then fails. These env
    vars were set by the entry shim and read by nothing at all.
    """
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("SENTINEL_ARTIFACTS_DIR", str(RELEASE_BUNDLE))
    monkeypatch.setenv("SENTINEL_CLOUD", "1")
    monkeypatch.setenv("SENTINEL_READONLY", "1")
    at = AppTest.from_file(str(_APP), default_timeout=180)
    at.run()

    assert not at.exception, f"console raised: {[e.value for e in at.exception]}"

    # The dataset picker is a radio, so its options are the surface to assert on.
    # An earlier version of this test scanned sidebar markdown, where the option
    # never appears - it passed whether or not the guard existed.
    dataset_options = [
        option for radio in at.sidebar.radio if radio.label == "Dataset" for option in radio.options
    ]
    assert not any("1.2 GB" in option for option in dataset_options), (
        "the raw-CSV dataset must be hidden when SENTINEL_CLOUD=1; the licensed "
        f"CSVs are not in the repository, so it would fail after a 15-20 minute "
        f"windowing attempt. Got: {dataset_options}"
    )
    # The committed pre-windowed aggregate is the real-data path and must survive.
    assert any("pre-windowed" in option for option in dataset_options), (
        f"Cloud must still offer the committed real CIC-IDS2017 aggregate: {dataset_options}"
    )

    retrain = [b for b in at.sidebar.button if "Train / retrain" in b.label]
    assert retrain and all(b.disabled for b in retrain), (
        "the retrain control must be disabled when SENTINEL_READONLY=1"
    )


def test_local_runs_keep_both_the_raw_dataset_and_retraining(monkeypatch, tmp_path) -> None:
    """The guards above must be cloud-only.

    A local checkout has the CSVs and a working trainer; disabling either one
    locally would remove capability rather than correct a hosted limitation.
    """
    from streamlit.testing.v1 import AppTest

    monkeypatch.delenv("SENTINEL_CLOUD", raising=False)
    monkeypatch.delenv("SENTINEL_READONLY", raising=False)
    monkeypatch.setenv("SENTINEL_ARTIFACTS_DIR", str(RELEASE_BUNDLE))
    at = AppTest.from_file(str(_APP), default_timeout=180)
    at.run()

    assert not at.exception, f"console raised: {[e.value for e in at.exception]}"

    dataset_options = [
        option for radio in at.sidebar.radio if radio.label == "Dataset" for option in radio.options
    ]
    assert any("1.2 GB" in option for option in dataset_options), (
        "a local checkout has the licensed CSVs, so the raw-CSV option must stay "
        f"available when SENTINEL_CLOUD is unset. Got: {dataset_options}"
    )
    retrain = [b for b in at.sidebar.button if "Train / retrain" in b.label]
    assert retrain and not any(b.disabled for b in retrain), (
        "retraining must stay available when SENTINEL_READONLY is unset"
    )
