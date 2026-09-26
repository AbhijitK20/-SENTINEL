#!/usr/bin/env bash
# One-command full pipeline: lint, reachability, tests, every benchmark, charts.
#
#   ./run_all.sh                      # default benchmark experiment
#   ./run_all.sh --scenarios 15       # extra args pass through to the benchmark
#
# Reproducible by construction: fixed config, seed, and artifact paths; every
# number in the reports comes from typed contracts (see BENCHMARK.md).
#
# Every published number in docs/CLAIMS.md is produced by one of the steps
# below. If you add a claim, add the step that produces it here.
set -euo pipefail
cd "$(dirname "$0")"

echo "== lint =="
uv run ruff check src tests scripts
uv run ruff format --check src tests scripts

# Every module must be reachable from an entry point, or listed in ALLOWLIST
# with a reason. This is what stops dead code accumulating again.
echo "== reachability =="
uv run python scripts/check_reachability.py --strict

echo "== tests =="
uv run pytest -q

echo "== benchmark (train, calibrate, replay, rollout, forecast) =="
uv run python scripts/run_benchmark.py --output reports/generated/benchmark "$@"

echo "== rolling-origin backtest =="
uv run python scripts/run_backtest.py --output reports/generated/benchmark/backtest

echo "== per-detector precision/recall =="
uv run python scripts/run_detector_benchmark.py \
    --output reports/generated/benchmark/detectors

echo "== world model open-loop skill =="
uv run python scripts/run_world_model.py \
    --output reports/generated/benchmark/world_model \
    --baseline reports/generated/benchmark/pipeline/baseline \
    --compare-cores

echo "== release bundle =="
uv run python scripts/export_release_artifacts.py \
    --from-benchmark --out models/release/v1
uv run python scripts/verify_release_artifacts.py models/release/v1

echo "== golden path (headless demo) =="
uv run python scripts/demo_script.py --output reports/generated/benchmark/demo_script

echo "== burndown & snapshot =="
uv run python scripts/render_burndown.py
uv run python scripts/render_snapshot.py

cat <<'EOF'

All done. Reports:
  reports/generated/benchmark/BENCHMARK.md
  reports/generated/benchmark/backtest/backtest.md
  reports/generated/benchmark/detectors/detector_benchmark.md
  reports/generated/benchmark/world_model/WORLD_MODEL.md
  reports/generated/benchmark/demo_script/demo.json
  reports/generated/burndown.html

Real CIC-IDS2017 numbers need the licensed CSVs:
  data/raw/cic-ids2017/TrafficLabelling/  then  make bench-real
EOF
