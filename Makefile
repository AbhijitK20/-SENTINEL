.PHONY: setup gate demo train reproduce bench-real lint test clean

setup:  ## install everything
	uv sync --all-extras

gate:  ## lint + format-check + tests (run before every commit)
	uv run ruff check src tests scripts
	uv run ruff format --check src tests scripts
	uv run pytest -q

lint:  ## lint only
	uv run ruff check src tests scripts

test:  ## tests only
	uv run pytest -q

format:  ## auto-format code
	uv run ruff format src tests scripts

demo:  ## dashboard with pretrained release weights, no training
	uv run streamlit run src/trajectory/dashboard/app.py -- --artifacts models/release/v1

train:  ## full reproducible training run
	uv run python scripts/run_benchmark.py --config configs/default.yaml

reproduce:  ## train, then verify metrics match RESULTS.md within tolerance
	uv run python scripts/run_benchmark.py --config configs/default.yaml
	uv run python scripts/verify_results.py --results RESULTS.md --run reports/generated/benchmark

bench-real:  ## CIC-IDS2017 cross-day benchmark
	uv run python scripts/run_real_benchmark.py --data-dir data/raw/cic-ids2017/TrafficLabelling

clean:  ## remove build artifacts and caches
	rm -rf .ruff_cache .pytest_cache __pycache__ dist build
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
