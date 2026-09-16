"""Export a versioned, checksummed release artifact bundle.

    uv run python scripts/export_release_artifacts.py \
        --run-dir reports/generated/benchmark \
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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--run-dir",
        required=True,
        help="Path to reports/generated/benchmark (or any run directory with baseline/ + temporal/)",
    )
    parser.add_argument(
        "--out",
        default="models/release/v1",
        help="Output directory for the release bundle (default: models/release/v1)",
    )
    parser.add_argument("--config", default="configs/default.yaml", help="Config used for training")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    baseline_dir = run_dir / "baseline"
    temporal_dir = run_dir / "temporal"
    calibration_dir = run_dir / "calibration"

    files: dict[str, Path] = {}

    # --- Baseline artifacts ---
    for name in ("baseline_result.json", "baseline_model.joblib", "baseline_report.md"):
        src = baseline_dir / name
        if src.is_file():
            dst = out / name
            dst.write_bytes(src.read_bytes())
            files[name] = dst

    # --- Feature schema (embedded in baseline_result.json, also useful standalone) ---
    if (baseline_dir / "baseline_result.json").is_file():
        result = json.loads((baseline_dir / "baseline_result.json").read_text(encoding="utf-8"))
        schema = result.get("feature_schema", {})
        if schema:
            schema_path = out / "feature_schema.json"
            schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
            files["feature_schema.json"] = schema_path
        split_manifest = result.get("split_manifest", {})
        if split_manifest:
            manifest_path = out / "split_manifest.json"
            manifest_path.write_text(json.dumps(split_manifest, indent=2), encoding="utf-8")
            files["split_manifest.json"] = manifest_path

    # --- Temporal artifacts (weights) ---
    temporal_result_path = temporal_dir / "temporal_result.json"
    if temporal_result_path.is_file():
        dst = out / "temporal_result.json"
        dst.write_bytes(temporal_result_path.read_bytes())
        files["temporal_result.json"] = dst

    weights_dir = temporal_dir / "weights"
    if weights_dir.is_dir():
        out_weights = out / "weights"
        out_weights.mkdir(exist_ok=True)
        for pt_file in sorted(weights_dir.glob("model_h*.pt")):
            dst = out_weights / pt_file.name
            dst.write_bytes(pt_file.read_bytes())
            files[f"weights/{pt_file.name}"] = dst

    # --- Calibration ---
    cal_path = calibration_dir / "calibration.json"
    if cal_path.is_file():
        dst = out / "calibration.json"
        dst.write_bytes(cal_path.read_bytes())
        files["calibration.json"] = dst

    # --- Config snapshot ---
    config_src = Path(args.config)
    if config_src.is_file():
        dst = out / "TRAINING_CONFIG.yaml"
        dst.write_bytes(config_src.read_bytes())
        files["TRAINING_CONFIG.yaml"] = dst

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
    files["PROVENANCE.md"] = prov_path

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
    manifest_path = out / "MANIFEST.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    print(f"Release bundle exported to {out}")
    print(f"  files: {len(files)}")
    print(f"  git SHA: {git_sha}")
    for name in sorted(files):
        print(f"  {name}: {file_hashes[name]['sha256'][:16]}… ({file_hashes[name]['size_bytes']} bytes)")
    print(f"  MANIFEST.json: {manifest_path}")


if __name__ == "__main__":
    main()
