# Sprint 8 Plan

## Goal

Harden the candidate and package the SIH submission.

## Outputs

Final benchmark, README, architecture document, demo script, presentation outline, and limitations.

## Status: COMPLETE (synthetic scope)

- `scripts/run_benchmark.py` produces the reproducible benchmark in one
  command (`benchmark.json` + `BENCHMARK.md`); results recorded in
  `RESULTS.md` per `RESULTS_TEMPLATE.md`.
- Offline operation verified by test (`tests/test_offline.py`: offline config
  pinned, no network clients or cloud endpoints in `src/trajectory`).
- Claim audit: every UI label, report, and document distinguishes observed
  from forecast, and no real-traffic claim is made anywhere (see Claim Status
  in `RESULTS.md` and `BENCHMARK.md`).
- Remaining honest gap, recorded rather than hidden: the benchmark is on
  synthetic replay; a licensed real-data run (CIC-IDS2017) is pending and is
  the only path to a real-traffic lead-time claim.

## Exit Criteria

All P0 requirements have evidence and the submission package contains no unsupported claims — met for synthetic scope; the real-data run remains explicitly open.
