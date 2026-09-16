"""Verify the integrity of a release artifact bundle.

    uv run python scripts/verify_release_artifacts.py models/release/v1

Re-hashes every file listed in MANIFEST.json and exits non-zero on any
mismatch.  Designed to run in CI after the export step.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle_dir", help="Path to the release bundle directory")
    args = parser.parse_args()

    bundle = Path(args.bundle_dir)
    manifest_path = bundle / "MANIFEST.json"
    if not manifest_path.is_file():
        print(f"ERROR: MANIFEST.json not found in {bundle}", file=sys.stderr)
        return 1

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    files = manifest.get("files", {})

    errors = 0
    for name, expected in sorted(files.items()):
        path = bundle / name
        if not path.is_file():
            print(f"MISSING: {name}", file=sys.stderr)
            errors += 1
            continue
        actual_sha = _sha256(path)
        actual_size = path.stat().st_size
        if actual_sha != expected["sha256"]:
            print(
                f"HASH MISMATCH: {name}\n"
                f"  expected: {expected['sha256']}\n"
                f"  actual:   {actual_sha}",
                file=sys.stderr,
            )
            errors += 1
        if actual_size != expected["size_bytes"]:
            print(
                f"SIZE MISMATCH: {name}\n"
                f"  expected: {expected['size_bytes']}\n"
                f"  actual:   {actual_size}",
                file=sys.stderr,
            )
            errors += 1

    if errors:
        print(f"\nVERIFICATION FAILED: {errors} error(s)", file=sys.stderr)
        return 1

    print(f"VERIFICATION PASSED: {len(files)} files, all hashes match")
    print(f"  bundle: {bundle}")
    print(f"  git SHA: {manifest.get('git_sha', 'unknown')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
