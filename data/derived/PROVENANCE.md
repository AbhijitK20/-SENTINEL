# Derived CIC-IDS2017 windows

`cicids2017_windows.parquet` is a committed, pre-windowed aggregate of CIC-IDS2017 TrafficLabelling.

## What this is

98 behavioural features per window, plus the attack stage, the infiltration flag,
the scenario id and the window bounds. Aggregated from the eight day CSVs at
{window}s windows with a {stride}s stride.

## What this is not

It contains **no raw flow data** - no addresses, no ports, no per-flow
timestamps, no packets. It is a strictly smaller representation of the source,
committed so that `make demo` renders measured numbers on first paint rather
than after a 15-20 minute, ~11 GB windowing pass that a laptop may not survive.

It is also **not** a substitute for the raw CSVs when re-fitting: feature schema
statistics cannot be recovered from aggregates. To retrain from source, obtain
the dataset and run `scripts/run_real_benchmark.py`.

## Why it is committed

A judge who clones the repository should be able to see what the system does in
under a minute. Without this file the real-data path needs a 1.2 GB download
first, and if that download is skipped the path simply fails.

## Regenerate

    uv run python scripts/export_derived_windows.py \
        --data-dir data/raw/cic-ids2017/TrafficLabelling \
        --out cicids2017_windows.parquet

## Licence and citation

Dataset used under its published research terms with the required citation:

> Sharafaldin, Lashkari & Ghorbani, 'Towards Generating New Intrusion Detection Datasets and Intrusion Traffic Characterization', ICISSP 2018. https://www.unb.ca/cic/datasets/ids-2017.html
