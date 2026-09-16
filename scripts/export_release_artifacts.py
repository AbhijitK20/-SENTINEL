"""Export a versioned, checksummed release artifact bundle.

    uv run python scripts/export_release_artifacts.py \
        --baseline reports/generated/baseline \
        --temporal reports/generated/temporal \
        --calibration reports/generated/calibration \
        --out models/release/v1

Produces a self-contained bundle that ``predict.load_artifacts()`` can load
without any training step.  Every file is SHA-256 checksummed and recorded in
MANIFEST.json together with the git SHA, config hash, and runtime versions.

The bundle is the single source of truth for the demo and for judges who clone
the repo — no training is required to run inference.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _git_sha() -> str:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return "unknown"


def _copy_file(src: Path, dst: Path, files: dict[str, Path], base: Path) -> None:
    """Copy src to dst and record it in the files manifest relative to base."""
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(src.read_bytes())
    rel = dst.relative_to(base).as_posix()
    files[rel] = dst


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--baseline",
        default="reports/generated/baseline",
        help="Directory containing baseline_result.json, baseline_model.joblib",
    )
    parser.add_argument(
        "--temporal",
        default="reports/generated/temporal",
        help="Directory containing temporal_result.json and weights/",
    )
    parser.add_argument(
        "--calibration",
        default="reports/generated/calibration",
        help="Directory containing calibration.json",
    )
    parser.add_argument(
        "--out",
        default="models/release/v1",
        help="Output directory for the release bundle (default: models/release/v1)",
    )
    parser.add_argument("--config", default="configs/default.yaml", help="Config used for training")
    args = parser.parse_args()

    baseline_dir = Path(args.baseline)
    temporal_dir = Path(args.temporal)
    calibration_dir = Path(args.calibration)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    files: dict[str, Path] = {}

    # --- Baseline artifacts ---
    for name in ("baseline_result.json", "baseline_model.joblib", "baseline_report.md"):
        src = baseline_dir / name
        if src.is_file():
            _copy_file(src, out / name, files, base=out)

    # --- Feature schema and split manifest (extracted from baseline_result.json) ---
    baseline_result = baseline_dir / "baseline_result.json"
    if baseline_result.is_file():
        result = json.loads(baseline_result.read_text(encoding="utf-8"))
        schema = result.get("feature_schema", {})
        if schema:
            schema_path = out / "feature_schema.json"
            schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
            files[schema_path.relative_to(out).as_posix()] = schema_path
        split_manifest = result.get("split_manifest", {})
        if split_manifest:
            sm_path = out / "split_manifest.json"
            sm_path.write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")
            files[sm_path.relative_to(out).as_posix()] = sm_path

    # --- Temporal artifacts (weights) ---
    temporal_result = temporal_dir / "temporal_result.json"
    if temporal_result.is_file():
        _copy_file(temporal_result, out / "temporal_result.json", files, base=out)

    weights_dir = temporal_dir / "weights"
    if weights_dir.is_dir():
        for pt_file in sorted(weights_dir.glob("model_h*.pt")):
            _copy_file(pt_file, out / "weights" / pt_file.name, files, base=out)

    # --- Calibration ---
    cal_path = calibration_dir / "calibration.json"
    if cal_path.is_file():
        _copy_file(cal_path, out / "calibration.json", files, base=out)

    # --- Config snapshot ---
    config_src = Path(args.config)
    if config_src.is_file():
        _copy_file(config_src, out / "TRAINING_CONFIG.yaml", files, base=out)

    # --- Provenance ---
    git_sha = _git_sha()
    provenance = (
        f"# Provenance\n\n"
        f"- Exported: {datetime.now(UTC).isoformat()}\n"
        f"- Git SHA: `{git_sha}`\n"
        f"- Python: {platform.python_version()}\n"
        f"- Platform: {platform.platform()}\n"
        f"- Config: `{config_src}`\n"
    )
    prov_path = out / "PROVENANCE.md"
    prov_path.write_text(provenance, encoding="utf-8")
    files[prov_path.relative_to(out).as_posix()] = prov_path

    # --- MANIFEST.json ---
    file_hashes = {}
    for name, path in sorted(files.items()):
        file_hashes[name] = {
            "sha256": _sha256(path),
            "size_bytes": path.stat().st_size,
        }

    manifest = {
        "version": "release-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "git_sha": git_sha,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "config": str(config_src),
        "files": file_hashes,
    }
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Release bundle exported to {out}")
    print(f"  files: {len(files)}")
    print(f"  git SHA: {git_sha}")
    for name in sorted(files):
        print(f"  {name}: {file_hashes[name]['sha256'][:16]}… ({file_hashes[name]['size_bytes']} bytes)")


if __name__ == "__main__":
    main()
