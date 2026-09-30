.PHONY: setup gate lint reach test format demo demo-live web-app train reproduce verify \
	export bench-world bench-real bench-backtest bench-detectors bench-calibration bench-telemetry bench-evasion bench-labels bench-drift bench-perf demo-path clean \
	derived loeo detectors-real

BUNDLE ?= models/release/v1
BENCH  ?= reports/generated/benchmark
CONFIG ?= configs/default.yaml

setup:  ## install everything
	uv sync --all-extras --all-groups

# ── Quality gate ────────────────────────────────────────────────────────
gate:  ## lint + format-check + reachability + tests + release verification
	uv run ruff check src tests scripts
	uv run ruff format --check src tests scripts
	uv run python scripts/check_reachability.py --strict
	uv run pytest -q
	$(MAKE) verify

lint:  ## lint only
	uv run ruff check src tests scripts

reach:  ## fail if any module is unreachable from an entry point
	uv run python scripts/check_reachability.py --strict

test:  ## tests only
	uv run pytest -q

format:  ## auto-format code
	uv run ruff format src tests scripts

# ── Release bundle ──────────────────────────────────────────────────────
verify:  ## check the committed release bundle against its manifest
	uv run python scripts/verify_release_artifacts.py $(BUNDLE)

DATASET ?= synthetic-recon-lateral-v2

export:  ## rebuild the release bundle from the last benchmark run
	uv run python scripts/export_release_artifacts.py --from-benchmark \
		--dataset-id $(DATASET) --out $(BUNDLE)
	$(MAKE) verify

# ── Running the product ─────────────────────────────────────────────────
web-app:  ## analyst console (Streamlit)
	uv run streamlit run src/sentinel/dashboard/app.py

demo:  ## analyst console preloaded with the committed release artifacts
	SENTINEL_ARTIFACTS_DIR=$(BUNDLE) uv run streamlit run src/sentinel/dashboard/app.py -- --artifacts $(BUNDLE)

demo-live:  ## console + API + vulnerable target + sensors (docker)
	docker compose --profile demo up -d

demo-path:  ## headless golden-path demo: prints the six-beat narrative, no clicking
	uv run python scripts/demo_script.py --output $(BENCH)/demo_script

# ── Deploying ───────────────────────────────────────────────────────────
# Three separate Vercel projects, so a broken container in one cannot take the
# others down. `--cwd` does NOT isolate vercel.json discovery, so the console
# deploy swaps the config in and restores it afterwards.
deploy-api:  ## Vercel: the REST API container (project sentinel-api)
	vercel deploy --prod --archive=tgz --project sentinel-api

deploy-console:  ## Vercel: the Streamlit console container (project sentinel-console)
	@cp vercel.json vercel.json.api.bak
	@cp vercel.console.json vercel.json
	@vercel deploy --prod --archive=tgz --project sentinel-console; st=$$?; \
	 mv vercel.json.api.bak vercel.json; exit $$st

deploy-landing:  ## Vercel: the static landing page (project landing)
	vercel deploy --prod --project landing --cwd landing

# ── Reproducing results ─────────────────────────────────────────────────
train:  ## full reproducible benchmark (baseline, temporal, world model, replay)
	uv run python scripts/run_benchmark.py --config $(CONFIG) --output $(BENCH)

reproduce:  ## train, export the bundle, then verify it
	$(MAKE) train
	$(MAKE) export

bench-world:  ## world-model open-loop benchmark + core comparison
	uv run python scripts/run_world_model.py \
		--output $(BENCH)/world_model \
		--baseline $(BUNDLE) \
		--compare-cores

bench-backtest:  ## rolling-origin temporal backtest with drift per origin
	uv run python scripts/run_backtest.py --output $(BENCH)/backtest

bench-detectors:  ## per-detector precision/recall/F1 on held-out windows
	uv run python scripts/run_detector_benchmark.py --output $(BENCH)/detectors

bench-calibration:  ## reliability, ECE and Brier decomposition per model
	uv run python scripts/run_calibration_report.py --output $(BENCH)/calibration

bench-telemetry:  ## minimum sufficient telemetry, with a cost/benefit frontier
	uv run python scripts/run_telemetry_budget.py --output $(BENCH)/telemetry

bench-evasion:  ## red-team the detectors: what it costs to walk past each rule
	uv run python scripts/run_evasion_report.py --output $(BENCH)/evasion

bench-labels:  ## label-efficiency curve, and whether unlabelled data helps
	uv run python scripts/run_label_efficiency.py --output $(BENCH)/label-efficiency

bench-drift:  ## what a stealthier attacker costs, and how long until we notice
	uv run python scripts/run_drift_report.py --output $(BENCH)/drift

bench-perf:  ## throughput in items/second, and whether it is linear
	uv run python scripts/run_perf_profile.py --output $(BENCH)/perf-profile

derived:  ## rebuild the committed pre-windowed CIC-IDS2017 aggregate (needs the licensed CSVs)
	uv run python scripts/export_derived_windows.py \
		--data-dir data/raw/cic-ids2017/TrafficLabelling \
		--out data/derived/cicids2017_windows.parquet

loeo:  ## leave-one-attack-out generalisation on real CIC-IDS2017 (needs the licensed CSVs)
	uv run python scripts/run_loeo_benchmark.py \
		--data-dir data/raw/cic-ids2017/TrafficLabelling \
		--output reports/generated/loeo

detectors-real:  ## detector suite on real CIC-IDS2017, with and without a deployment baseline
	uv run python scripts/measure_real_detectors.py \
		--data-dir data/raw/cic-ids2017/TrafficLabelling \
		--output reports/generated/real-detectors

bench-real:  ## CIC-IDS2017 cross-day benchmark (needs the licensed CSVs)
	uv run python scripts/run_real_benchmark.py \
		--data-dir data/raw/cic-ids2017/TrafficLabelling \
		--output reports/generated/real-benchmark

clean:  ## remove build artifacts and caches
	rm -rf .ruff_cache .pytest_cache __pycache__ dist build
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
