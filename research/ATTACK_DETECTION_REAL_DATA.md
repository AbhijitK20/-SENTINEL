# Attack Detection and Monitoring — Measured Against Real Traffic

Everything here was produced by running our own code this session. The scripts
are described inline so the numbers can be reproduced. The windowing is the one
the console uses for real data: 300 s windows, 150 s stride, 2,830,743 flows
across all eight shipped CIC-IDS2017 CSVs, 983 windows (698 benign, 285 attack).

## The short version

The 9 rule-based detectors and the stage mapper work on the synthetic data they
were tuned on and **do not transfer to real traffic at all**. Measured, not
inferred.

| | synthetic (tuning data) | real CIC-IDS2017 |
|---|---:|---:|
| windows | 720 | 983 |
| benign windows that raised an alert | **41.1%** (222/540) | **99.7%** (696/698) |

On real benign traffic the detector set is effectively always-on. Three
detectors account for nearly all of it: `reconnaissance` fired in 981 of 983
windows, `lateral_movement` in 957, `command_and_control` in 905.

Detection of the real attack windows looks superficially good and is
misleading for the same reason:

| Real attack stage | windows alerted | note |
|---|---:|---|
| Reconnaissance | 24/24 (100%) | but so are 99.7% of benign windows |
| Lateral Movement | 28/28 (100%) | same |
| Command and Control | 83/84 (98.8%) | same |
| Credential Access | 4/58 (6.9%) | barely detected |
| Denial of Service | 4/53 (7.5%) | barely detected |
| Initial Access | 0/38 (0.0%) | never detected |

Three stages at ~100% and three stages at ~0% is not a detector working. It is
three detectors saturating and three never triggering, with the saturated
detectors carrying the "true positives".

## Root cause: the thresholds are calibrated to our own generator

`detect_recon` documents its bands as measured facts:

> the measured separators are the SYN+RST probe share (benign 0.000, recon min
> 0.476) and the low-byte edge share (benign 0.000, recon min 0.364)

Measured on the 698 real benign windows:

| Input | min | median | p90 | max | docstring claim |
|---|---:|---:|---:|---:|---|
| `rst_probe_ratio` | 0.000 | 0.000 | 0.001 | 0.037 | benign 0.000 |
| `low_byte_probe_share` | 0.000 | **0.493** | 0.573 | 0.750 | benign 0.000 |
| `max_source_fanout` | 1 | **121** | 213 | 467 | not stated |
| `edge_count` | 1 | **748** | 1197 | 1912 | gate is 6 |

`rst_probe_ratio` matches the claim exactly. The other two do not, and the
consequence is arithmetic rather than judgement:

- `PROBE_SHARE_ALERT` is **0.30**. Real benign windows have a median low-byte
  probe share of **0.493**. **692 of 698** real benign windows sit at or above
  the alert band. The docstring's *reconnaissance* minimum is 0.364, so ordinary
  traffic sits above the level that was measured to mean an attack.
- `PROBE_MIN_EDGES` is **6** and exists to stop "one or two small flows" from
  counting as a scan. Real benign windows have a median of **748** edges. The
  gate is open on **697 of 698** of them, so the guard that was added for
  exactly this reason does not fire.

That is the whole mechanism. `recon` fires because real benign traffic is
legitimately probe-shaped: short control connections, health checks, keep-alives,
DNS, CDN edges, mobile app chatter. The thresholds were fitted to a generator
whose benign traffic has no such texture, so they are not a valid separator for
real benign traffic. The 41.1% synthetic false-alert rate is the same defect,
partly masked because the generator is cleaner than reality.

This is a calibration problem, not a modelling one. Nothing in the design is
wrong; the numbers in the docstrings describe a different world than the one the
detectors now run in.

## What this means for the claims we publish

`docs/RESULTS.md` reports attack-suite detection on the synthetic benchmark.
Those numbers are real measurements of our detectors, but they are measurements
**on the generator that produced their thresholds**, and this document is the
reason that fact needs to be stated next to them. It is a much weaker result
than a 0.667 detection F1 read alone would suggest.

Note also the direction of the forecasting numbers. The release bundle's world
model reports test F1 1.0000 and the GRU 0.83-0.92 per horizon — all synthetic.
So the two halves of the system are both calibrated to the same generator, and
neither has been shown against real attack windows. The real-data row for the
forecasting models does not exist yet.

## The monitoring layers that are NOT affected

Worth being precise about, because the finding is narrower than "detection is
broken":

- The 98 features are fine. All behavioural, no clock or schedule leakage, and
  they populate correctly on real flows — the adapter produced 983 windows from
  real CSVs with no missing-feature problem.
- The label plumbing is fine, as of the previous commit.
- Stage mapping (`stage_mapping.py`) is **rules, not detectors**, and its
  conditions are written against feature magnitudes that were also chosen on
  synthetic data. The same recalibration applies, but it was not measured here
  and is not claimed.
- The forecasting models, calibration, and the release bundle are unaffected by
  this specific finding. They have their own synthetic-only problem, described
  in `COMPETITIVE_ANALYSIS.md`.

## The fix, in order

1. **Re-measure the bands on real benign traffic.** The detectors are already
   written as explicit band constants (`PROBE_SHARE_WARN`, `PROBE_SHARE_ALERT`,
   `RST_RATIO_*`, `PROBE_MIN_EDGES`, and equivalents in the other eight). This is
   a constants change, not a rewrite. Do it per detector, and set the bands from
   the real distribution above rather than from intuition.
2. **Report a real false-alert rate in the claims table.** Whatever it turns
   out to be. A 99.7% rate is a blocker for a monitoring product; if
   recalibration cannot get it low, that is the finding to publish, and it is
   more valuable than a synthetic number that hides it.
3. **Add a real-data detection evaluation** to the benchmark scripts, so this
   cannot regress silently. The synthetic benchmark should not be the only
   detection number in the repository.
4. **Initial Access and Credential Access need detectors that exist.** They are
   0/38 and 4/58 on real data. The CIC `Thursday-...-WebAttacks` day is
   web-attack traffic and `Tuesday` is brute-force credential traffic; both are
   present and neither is caught.
5. Only then re-tune the forecasting models, which is the separate task in
   `COMPETITIVE_ANALYSIS.md`.

## Reproduction

- Real-data pass: `load_flow_csv` → `flow_labels_from_events` →
  `build_labelled_states(window_seconds=300, stride_seconds=150)` →
  `run_all_detectors(state, history)` per window, tallying `finding.is_alert`.
- Synthetic pass: `generate_labelled_states([f"scenario-{i:02d}" for i in
  range(1, 11)], seed=42, window_seconds=60, stride_seconds=30)` → the same
  detector loop.
- Band statistics: the same real benign windows, computing `rst_count /
  flow_event_count`, the sub-`PROBE_BYTES` edge share using the module constants
  (`PROBE_BYTES=200.0`, `PROBE_MIN_EDGES=6.0`, `PROBE_SHARE_ALERT=0.30`), and
  per-source unique destination counts. An earlier pass in this session hardcoded
  `PROBE_BYTES=100` and reported a median probe share of 0.452; with the real
  constant it is 0.493, and the counts above are the corrected ones.
