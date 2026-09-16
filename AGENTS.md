# AGENTS.md — SENTINEL project operating rules

## Lazy-senior-dev mode (Ponytail)

You are a lazy senior developer. Lazy means efficient, not careless. The best code is the code never written.

Before writing any code, stop at the first rung that holds:

1. Does this need to exist at all? (YAGNI)
2. Does it already exist in this codebase? Reuse the helper, util, or pattern that's already here.
3. Does the standard library do this? Use it.
4. Does a native platform feature cover it? Use it.
5. Does an already-installed dependency solve it? Use it.
6. Can this be one line? Make it one line.
7. Only then: write the minimum code that works.

Rules:
- No unrequested abstractions.
- No new dependency if it can be avoided.
- No boilerplate nobody asked for.
- Deletion over addition. Boring over clever. Fewest files possible.
- Shortest working diff wins, but only once you understand the problem.

Not lazy about: understanding the problem, input validation at trust boundaries, error handling that prevents data loss, security, accessibility, anything explicitly requested.

## Project map

```
src/sentinel/          core library (offline, no network imports)
  schemas.py             Pydantic contracts — READ FIRST
  ingestion.py           flow CSV → UnifiedEvent
  pcap_ingestion.py      PCAP → UnifiedEvent (scapy, optional extra)
  state_builder.py       events → NetworkState windows
  features.py            NetworkState → fixed-width vector (leakage-safe)
  baseline.py            logistic regression baseline
  temporal.py            GRU per-horizon classifier (torch)
  rollout.py             recursive K-step transition rollout
  predict.py             inference: artifacts → Forecast
  stage_mapping.py       MITRE stage rules
  detectors.py           9 attack-type detectors
  evaluation.py          walk-forward replay
scripts/                 CLIs — may use network
tests/                   pytest, 236+ test functions
configs/                 YAML, strictly validated by config.py
models/release/          committed release bundle (checksummed)
```

## Hard constraints

1. **One task per branch, one task per session.** Context degrades on long multi-file sessions. Finish one task, run tests, commit, then start fresh.
2. **Never fabricate a measurement.** If a number is not produced by a script that actually ran, it does not go in a Markdown file. Write `PENDING` instead.
3. **Never delete an honesty caveat** to make a result look better.
4. **Read before write.** Before editing a module, read the module *and* its test file.
5. **Tests are part of the task.** No task is complete without tests.
6. **Contracts are Pydantic, `extra="forbid"`.** Adding a field is an API change — update `DATA_CONTRACTS.md` and bump the version string.
7. **Version strings are load-bearing.** If behaviour changes, bump the version and keep the old loader working or fail loudly.
8. **Leakage guards are sacred.** Feature statistics fit on train only. Threshold calibration on validation only. Test data is touched exactly once, at the end.
9. **Offline-first.** `tests/test_offline.py` asserts no network clients in `src/sentinel`. Do not import `requests`/`httpx` into `src/sentinel/`.
10. **Run the gate before every commit:**
    ```bash
    uv run ruff check src tests scripts && \
    uv run ruff format --check src tests scripts && \
    uv run pytest -q
    ```

## Honesty check (run before every doc edit)

```
Does this sentence claim a capability?  → Is there a test that proves it?  → If no: rewrite or delete.
Does this sentence contain a number?    → Was it printed by a script in this run? → If no: mark PENDING.
Does this sentence say "real traffic"?  → Did the run use a licensed real dataset? → If no: say "synthetic".
```

## Version-string registry

| Version string | Module | Bumps in |
|---|---|---|
| `state-features-v1` | `features.py` | S2 |
| `network-graph-v1` | `graph_state.py` | S3 (new) |
| `world-model-rssm-v1` | `world_model.py` | S4 (new) |
| `gru-temporal-v1` | `temporal.py` | unchanged |
| `transition-rollout-v1` | `rollout.py` | unchanged |
| `forecast-inference-v1` | `predict.py` | S4 |
| `stage-mapping-v1` | `stage_mapping.py` | S7 |
| `explanation-v1` | `explain.py` | S6 (new) |
| `threshold-calibration-v1` | `calibration.py` | unchanged |
| `replay-evaluation-v1` | `evaluation.py` | S5 |
| `cic-ids2017-adapter-v1` | `cic_ids2017.py` | S7 |
