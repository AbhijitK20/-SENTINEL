# SIH26153 — Competitor Scan and Requirement Gap Analysis

Written after a GitHub sweep for `SIH26153` and adjacent themes. Reference
material only: the repos live in `research/repos/`, which is gitignored.

## How to read the numbers in this file

Two kinds of number appear here and they are not the same kind.

- **Measured** — produced by a script run in this repo, quoted in *SENTINEL
  measured* columns. Reproducible.
- **Claimed** — a number a competitor's own README or report states. Nothing
  here was independently reproduced. These are labelled *self-reported* and are
  claims, not measurements.

## The scoring requirement, verbatim

From the published problem statement (CC-BY-4.0, via
`vedantchalke36/sih-2026-problem-statements`):

> • Generalise to unseen attack patterns - not merely memorize signatures from
> the training set.

> • Benchmark results comparing model performance (F1 score, precision, recall,
> false positive rate) against a logistic regression baseline trained on the
> same features, demonstrating that the world model's temporal dynamics learning
> provides measurable improvement.

> • Provide explain ability using attention mechanisms, feature attribution or
> equivalent techniques. **Black-box outputs without interpretability are not
> acceptable.**

The statement names CIC-IDS2017/2018, UNSW-NB15, CTU-13, CICIoT2023 and others as
the datasets, and requires K-step rollout, MITRE ATT&CK stage output, driving
features, and an offline demo interface.

## Repos found

| Repo | Language | License | Size | Why it matters |
|---|---|---|---|---|
| `muthukkumaranb/ShadowCat` | Python | **none** | 291 MB | The most serious competitor. 57k LOC, real CIC-IDS2018 PCAP pipeline, a leakage test suite, and a tamper-evident audit chain. |
| `manansheth296-tech/sentinel-net` | Python | **MIT** | 9.4 MB | Closest analogue to us: Python, world model, SHAP, MITRE staging. Usable. |
| `bikram-341/AI-Based-Network-Attack-Forecasting-...` | Python | **none** | 3.5 MB | GRU world model, K=8 rollout, XGBoost type head. |
| `krishnashahane/sentinel-sih` | TypeScript | **MIT** | 2.1 MB | World model in TS. MIT, so usable. |
| `Malini-art/sih26153` | Python | **none** | 376 KB | Small, `zynex_worldmodel`. |
| `rishikrishnan357-svg/SIH26153` | Python | **none** | 1.9 MB | Small, pickled sklearn model + Streamlit. |
| `bansalanikait/SIH26153` | Python | **none** | 71 MB | Identified, **not cloned** — no description, no distinct signal. |

**Licensing.** Only two of these carry a licence. `sentinel-net` and
`sentinel-sih` are MIT, so their code may be read and reused with attribution.
The other four have no licence at all, which is the same situation
`ATTACK_FLOW_PROVENANCE.md` already records for `attack-chain-prediction`: read
the idea, do not lift the code.

## What the competitors do that we do not

### 1. A schedule-artifact leakage test (ShadowCat)

The most important finding in this scan. `data-engineering/src/gate0_leakage_test.py`
trains a classifier on **hour-of-day and day-of-week alone**, and reports it
beside the real feature set:

> Set B has High Recall (0.9961) ... CSE-CIC-IDS2018 was generated via scheduled
> lab testbed scripts where attacks were launched during typical working hours
> (09:00-12:00 and 14:00-16:00). A schedule-only classifier that predicts
> "Attack" during business hours blankets the time intervals when attacks occur.

Their mitigation: *Zero Timestamp Ingestion* — `window_start_utc`,
`window_end_utc` and `source_day` are retained as non-feature metadata and are
never passed into model tensors.

**We already satisfy this rule.** Verified this run: all 98 shipped features
(`models/release/v1/feature_schema.json`) are behavioural — bytes, packets, TCP
flags, ports, TTL, IAT statistics, payload entropy, fragmentation,
retransmissions. There is not one clock, calendar or timestamp feature. So we
are not exposed to the failure they found.

**But we do not have the test.** They prove it; we merely happen to satisfy it.
A schedule-only baseline is a cheap, high-value addition to the claims table,
because it is the kind of negative result a judge can verify.

Their second contribution is **episode-grouped splitting** — holding out whole
contiguous attack bursts, not individual windows, to kill adjacent-window
autocorrelation. We split by scenario, which is related but not the same.

### 2. Reporting at a stated FPR budget

`krishnashahane/sentinel-sih` frames everything at a 5% false-positive budget,
which makes the comparison between models meaningful: single-window logistic
regression scores F1 0.245 / recall 0.144, their world model F1 0.664 / recall
0.606 at the same budget — a 4.5x recall gain, with a *worse* ROC-AUC (0.802 vs
0.814). The point is that ranking metrics alone hide the operating-point win.

We calibrate a threshold on validation, correctly, but our published metrics
are not presented at a common FPR budget, so our baseline-vs-world-model
comparison is the weakest part of the claims table.

### 3. Horizon decay and unseen-attack evaluation as headline numbers

`bikram-341` reports rollout AUC degrading only 4.3% from k=1 to k=8
(0.8153 → 0.7725) and a zero-shot AUC of 0.8054 on attack types held out of
training. `ShadowCat` has `run_loeo_corrected.py` and a chronological holdout
that places Botnet in test only.

We report per-horizon F1, which is the decay view. We have **no
leave-one-attack-out evaluation at all** — `grep` for `leave.one|unseen.*attack|
zero.shot` across `src/sentinel/` and `tests/` returns nothing. Given the
statement's explicit "generalise to unseen attack patterns" clause, this is the
single largest scoring gap in the project.

### 4. A tamper-evident audit chain

`ShadowCat/backend/audit_chain.py` links forecast records with
`prev_entry_hash`, so any edit to an earlier record invalidates every later one.
This is **not** a stated requirement — the problem statement never asks for it;
`ShadowCat` added it themselves. Nice-to-have, not a gap. We do have per-file
SHA-256 in the release manifest, which covers a different threat (artifact
substitution, not record editing).

## Where we stand, measured

All from `models/release/v1/`, i.e. the committed release bundle:

| Model | Split | F1 | Precision | Recall | FPR | PR-AUC |
|---|---|---|---|---|---|---|
| Logistic regression baseline | test | 0.8919 | 0.8684 | 0.9167 | 0.0595 | 0.9784 |
| GRU temporal, horizon 1 | test | 0.8571 | 0.8049 | 0.9167 | 0.0870 | 0.9786 |
| GRU temporal, horizon 5 | test | 0.9231 | 0.8571 | 1.0000 | 0.0714 | 0.9532 |
| RSSM world model | test | 1.0000 | — | — | 0.0000 | 1.0000 |

World model open-loop skill against a persistence baseline: **-0.042 at +1
step, +0.270 at +2, +0.252 at +3**. So the model does beat "repeat the last
window" beyond one step, which is the honest and non-trivial claim available.

**Read those numbers carefully.** A test F1 of exactly 1.0000 is not a good
result; it is a warning. These models are trained on `synthetic-recon-lateral-v2`
— our own generator. The bundle records this, and the stage vocabulary is
`Benign, Lateral Movement, Reconnaissance` — three classes. Every competitor
trains on real CIC-IDS2017/2018. We are currently the only project in this
comparison whose headline forecasting numbers come from a synthetic source,
and a judge reading the dataset link in the statement will notice.

## The finding that changes the plan

**Real labelled CIC-IDS2017 is already sufficient, and we have been ignoring it.**

Measured this run by running the real-data adapter over all eight shipped CSVs
(2,830,743 flows, 300 s windows, 150 s stride):

| Day | Flows | Windows | Stages |
|---|---:|---:|---|
| Friday-WorkingHours-Afternoon-DDos | 225,745 | 37 | Benign 27, Denial of Service 10 |
| Friday-WorkingHours-Afternoon-PortScan | 286,467 | 60 | Benign 36, Reconnaissance 24 |
| Friday-WorkingHours-Morning | 191,033 | 97 | Benign 23, Command and Control 74 |
| Monday-WorkingHours | 529,918 | 195 | Benign 195 |
| Thursday-WorkingHours-Afternoon-Infilteration | 288,602 | 98 | Benign 70, Lateral Movement 28 |
| Thursday-WorkingHours-Morning-WebAttacks | 170,366 | 97 | Benign 59, Initial Access 38 |
| Tuesday-WorkingHours | 445,909 | 195 | Benign 137, Credential Access 58 |
| Wednesday-workingHours | 692,703 | 204 | Benign 151, Denial of Service 43, Command and Control 10 |
| **Total** | **2,830,743** | **983** | **698 benign, 285 attack** |

Six distinct attack stages: **Reconnaissance, Initial Access, Lateral Movement,
Command and Control, Credential Access, Denial of Service.**

This is the crux:

- It covers **four of the five MITRE phases the statement names** —
  Reconnaissance, Initial Access, Lateral Movement, Command & Control. The
  synthetic vocabulary has only two of them. Initial Access and C2 simply do
  not exist in our current stage set.
- **285 attack windows across 6 types and 8 independent days is enough for a
  leave-one-attack-out proof.** Six folds, each holding out a type never seen
  in training. That is the exact evidence the statement asks for.
- It is the dataset the statement links. It removes the "synthetic only" caveat
  from the headline comparison.

The adapter already reads these files correctly; the label plumbing is what the
console bug was about, and that is now fixed and tested.

## Recommended order

1. **Leave-one-attack-out on real CIC-IDS2017.** Highest value, directly
   answers a stated requirement, and the data is already in the repo. Each fold
   holds out one of the six attack types entirely.
2. **Schedule-only baseline.** A few lines: hour + day one-hot, report F1 beside
   the real features. Turns "we happen to be safe" into "we are measurably
   safe", and if it ever comes out high, we want to know before a judge does.
3. **Re-express the baseline comparison at a stated FPR budget**, so the
   world-model gain is a claim about the operating point rather than about
   threshold-free ranking metrics.
4. **Widen the stage vocabulary** to the real data's six stages. Bumping the
   model version is the honest way to do this; the current three-stage
   vocabulary cannot represent Initial Access or C2 at all.
5. **Episode-grouped splitting** as a second holdout protocol, alongside the
   scenario split we already use.

## What not to do

Do not re-export the release bundle to make room for any of this. A re-export
from this machine changes 17 of 18 files despite an identical seed and identical
splits, because float output is platform-dependent. Swapping a published,
checksum-verified bundle for an unpublished one invalidates the golden path and
every figure in `docs/CLAIMS.md`. Provenance was recorded in place instead; see
the commit message for `c0d09c9`.
