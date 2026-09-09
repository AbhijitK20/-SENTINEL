#!/usr/bin/env bash
# One-command full pipeline: lint, tests, benchmark, dashboard data, charts.
#
#   ./run_all.sh                      # default benchmark experiment
#   ./run_all.sh --scenarios 15       # extra args pass through to the benchmark
#
# Reproducible by construction: fixed config, seed, and artifact paths; every
# number in the reports comes from typed contracts (see BENCHMARK.md).
set -euo pipefail
cd "$(dirname "$0")"

echo "== lint =="
uv run ruff check src tests scripts

echo "== tests =="
uv run pytest -q

echo "== benchmark (train, calibrate, replay, rollout, forecast) =="
uv run python scripts/run_benchmark.py --output reports/generated/benchmark "$@"

echo "== burndown & snapshot =="
uv run python scripts/render_burndown.py
uv run python scripts/render_snapshot.py

echo "All done. Open reports/generated/burndown.html and reports/generated/benchmark/BENCHMARK.md"
