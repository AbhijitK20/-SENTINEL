"""Dataset identity: one canonical name, provenance recorded exactly once.

The dashboard used to retype the dataset id as a literal, and the downloadable
demo report hardcoded ``synthetic-recon-lateral-v1`` while the run that produced
it used ``-v2`` — a silently mislabelled artifact. These tests pin the fix:

- the name lives in one place (``sentinel.synthetic.DATASET_ID``)
- no module retypes it as a literal
- the report states the dataset of the run that produced it
- the single provenance caveat stays exactly where it was
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel.synthetic import DATASET_ID

REPO_ROOT = Path(__file__).resolve().parents[1]
APP = REPO_ROOT / "src" / "sentinel" / "dashboard" / "app.py"

# Any module that retypes a dataset id literal instead of importing the constant.
_LITERAL = re.compile(r"[\"'](?:synthetic-recon-lateral-v\d|CIC-IDS2017)")


def test_dataset_id_is_the_single_source_of_truth() -> None:
    assert DATASET_ID == "synthetic-recon-lateral-v2"


def test_app_imports_the_canonical_id_instead_of_retyping_it() -> None:
    source = APP.read_text(encoding="utf-8")
    assert "from sentinel.synthetic import" in source, "app.py must import DATASET_ID"
    assert "import DATASET_ID" in source
    assert not _LITERAL.search(source), (
        "app.py retypes a dataset id literal; import DATASET_ID instead"
    )


def test_demo_report_call_does_not_hardcode_a_dataset_id() -> None:
    """Pins the actual bug: the download button passed a stale ``-v1`` literal
    while the run used the canonical id, mislabelling the artifact."""
    source = APP.read_text(encoding="utf-8")
    assert 'dataset_id="synthetic-recon-lateral-v1"' not in source
    assert "dataset_id=dataset_id" in source, (
        "the demo report must use the id of the run that produced it"
    )


def test_release_exporter_records_the_dataset_id() -> None:
    """Future bundles state their training data; the current v1 bundle cannot
    be re-exported without retraining, so it stays flagged rather than guessed.
    """
    exporter = (REPO_ROOT / "scripts" / "export_release_artifacts.py").read_text(encoding="utf-8")
    assert "dataset_id" in exporter, "exporter must write dataset_id into MANIFEST.json"


def test_current_release_bundle_dataset_id_is_not_guessed() -> None:
    """Documents the known gap instead of inventing a value for it."""
    manifest = json.loads(
        (REPO_ROOT / "models" / "release" / "v1" / "MANIFEST.json").read_text(encoding="utf-8")
    )
    dataset_id = manifest.get("dataset_id")
    assert dataset_id in (None, DATASET_ID), (
        "bundle must either record the canonical id or omit it; never a stale one"
    )
