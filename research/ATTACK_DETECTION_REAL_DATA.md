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

## Fix, part 1 — what was changed, and what it bought

Branch `fix/detector-calibration-real-data`. Two changes, both reusing machinery
that already existed in the file.

**Reconnaissance: the low-byte edge share is now evidence, not a score.** This is
the original design the docstring already described ("Fan-out is reported as
evidence only"), not a retreat from it. Measured effect on real data:

| | before | after |
|---|---:|---:|
| reconnaissance fired in | 981 / 983 windows | **18 / 983** |
| benign windows alerting | 99.7% | **96.7%** |

**Lateral movement: the band is a rate, and was re-fitted as one.** The old
50k/60k was an absolute byte count fitted on 30 s windows, while the console lets
the operator choose the window — so a 300 s window scored 10x higher for
identical traffic. That is a property of the window, not the traffic. Re-fitted
by sweeping the byte *rate* on the synthetic corpus, keeping the 5:6 warn:alert
shape. On 60 s windows benign sits at 579 B/s median and lateral at 2,490 B/s
median, so the classes separate on the rate: **precision 0.73–0.78, recall 1.00
across seeds 17/42/7/99**, against test floors of 0.70/0.80. `KNOWN_EDGE_BYTES_WARN`
and `KNOWN_EDGE_BYTES_ALERT` are gone.

Three regression tests were added and each was checked to fail against the old
behaviour, not just to pass against the new one.

## Fix, part 2 — what could not be fixed, and why

**The benign false-alert rate is still 96.7%.** Lateral movement fires on 952 of
983 real windows and is the remaining cause. This is not a threshold that was
missed; it is arithmetic:

| corpus | median benign edge byte rate |
|---|---:|
| synthetic-recon-lateral-v2 | 579 B/s |
| real CIC-IDS2017 | **86,175 B/s** |

Real benign traffic is **149x** the volume of the corpus the bands were fitted
on. The attack rate is *below* the real benign median (120,278 B/s versus
86,175 B/s — a ratio of 1.4, with fully overlapping distributions). No threshold
placed anywhere on this quantity is quiet on real benign traffic and loud on real
lateral movement, because the attack sits inside the benign range.

Two alternatives were measured and rejected on evidence rather than taste:

- **History z-score** instead of an absolute band. Best achievable TPR−FPR is
  +0.108 on the synthetic corpus, against F1 0.945 for the absolute band. The
  cause is structural: lateral movement is a *sustained* condition, so a rolling
  baseline rises with the attack and the z-score collapses. Widening the baseline
  helps (lookback 5 → 40 moves TPR−FPR from +0.14 to +0.52) but never reaches the
  absolute band, and false positives stay near 0.20 throughout.
- **Shorter windows.** Separability is not a function of window length: TPR−FPR
  is +0.064 at 30 s, +0.064 at 60 s, +0.093 at 120 s, +0.110 at 300 s. Longer is
  marginally better and all are weak.

The real fix is a **per-deployment learned baseline** — normalising against the
traffic actually observed on that network, which is what the z-score was reaching
for and what its sustained-attack failure mode defeats. That is a design change,
not a recalibration, and it is the honest recommendation rather than a band
tuned to make a number look better.

## What else turned out to be a telemetry gap, not a calibration gap

CIC-IDS2017 flow CSVs carry no `Failed Logins` column, no DNS features and no
endpoint telemetry. Four detectors are therefore structurally unable to score on
this data, and already say so via warnings with probability 0.0 — this is correct
behaviour, not a defect:

- `credential_abuse` — needs `failed_auth`, absent from the CSV schema
- `phishing` — needs `domain_length` / `dns_tunnel_marker`
- `command_and_control` — needs `c2_beacon_score` or a threat-intel feed
- `malware_activity` — needs process-execution telemetry

This matters for reading the per-stage table above. **Initial Access 0/38 is not a
threshold problem.** The `Thursday-WorkingHours-Morning-WebAttacks` day is
present in the corpus and the adapter windows it correctly; the only detectors
that could plausibly catch it are phishing and malware, and both are disabled
because flow telemetry cannot see a web attack. Detecting it needs PCAP-derived
or endpoint data via the `pcap_ingestion` path.

It also explains the 905 `command_and_control` alerts in the original
measurement: they were not from the C2 detector at all, which was disabled. They
came from `sequence_detector.py`, which learns from the alert history — so
reconnaissance and lateral movement saturating cascaded into a C2 prediction on
almost every window. C2 is a symptom, not an independent failure.

## Recommended order

1. **A per-deployment baseline for lateral movement** — the only remaining route
   to a usable false-alert rate. Not a constants change; see the reasoning above.
2. **Report the real-data false-alert rate in the claims table** as it stands,
   96.7%. If a baseline closes it, update it. Publishing 96.7% with an
   explanation is more useful than a synthetic number that hides it.
3. **Extend the benchmark scripts with a real-data detection evaluation.** Done
   for reconnaissance and the lateral band as three regression tests; the
   whole-corpus run belongs in `make bench-detectors` so the rate is visible
   without a 1.2 GB dataset.
4. **PCAP or endpoint telemetry for the four structurally disabled detectors.**
   Initial Access (0/38) and Credential Access (4/58) are unreachable from flow
   CSVs, and no threshold will change that. The `pcap_ingestion` path exists for
   the packet-level view that `detect_recon` now explicitly points at.
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
