# SENTINEL — AI-Based Network Attack Forecasting from Network Traffic Data

**SIH Problem Statement:** SIH26153 · **Team deliverable:** working prototype + dashboard + live demo

## The Problem

Security teams learn about an intrusion when it has already happened. Alerts arrive as isolated events — a scan here, a failed login there — and no tool tells the analyst **what the attacker is likely to do next**, which systems are at risk, or why the alert matters. The result: slow triage, missed escalation paths, and post-incident forensics instead of pre-incident action.

## Our Approach

SENTINEL treats network traffic as a **trajectory, not a snapshot**. Flows are ingested into 300-second windows, featurized (auth failures, byte volumes, scan patterns, retransmissions), and converted into labelled system states. On top of that state sequence we train:

1. **A baseline classifier** — per-window attack probability (logistic regression).
2. **A temporal sequence model** — learns how attack campaigns *progress* across windows.
3. **A forecaster** — projects K windows ahead: attack probability per horizon, the predicted next **attack stage** (mapped to MITRE ATT&CK tactics with human-readable evidence), and honest *insufficient-evidence* states instead of forced guesses.

Every prediction carries its evidence; every metric in the UI is labelled **OBSERVED vs FORECAST**. The pipeline runs fully offline — no cloud AI, no data leaves the machine.

## Validation — what is actually measured

**On synthetic data, which is what this repository can currently reproduce.**
Every number below is printed by a script in this repo; see `docs/CLAIMS.md` for
the command behind each one.

All figures below are on `synthetic-recon-lateral-v3`, seed 42, 10 scenarios
split 60/20/20 **by scenario** so no window from a training scenario appears at
test time, 60 s windows with a 30 s stride, 98 features per window.

- Logistic baseline, test split: F1 **0.702**, precision 0.635, recall 0.786,
  PR-AUC **0.662**
- Per-horizon GRU, h+1: F1 **0.817**, precision 0.745, recall 0.905,
  PR-AUC **0.885**
- World model (RSSM) risk head, test split: F1 **0.826**, PR-AUC **0.918**,
  attack-stage accuracy **0.880**, stage macro-F1 **0.877**
- World-model **open-loop skill ≈ -0.001** against persistence
  (per step -0.282, +0.122, +0.156)
- Per-rule detector precision/recall on held-out windows, including the
  unflattering parts: lateral movement F1 0.591, reconnaissance F1 0.794

**Two of these are worse than this project previously reported, and that is the
honest result.** The first synthetic corpus was trivially separable: the label
was recoverable from one scalar, a *single* feature scored ROC-AUC 0.9833
against a full 98-feature model's 0.9933 — a gap of 0.0072, meaning 97 of the 98
features were decoration and every headline number was measuring the shortcut.
The generator was reworked to overlap the classes deliberately; the same
protocol now gives a single-feature ROC-AUC of **0.741** against a full-model
**0.930**, a gap of **0.113**. The figures above are from the corrected corpus.

The open-loop skill of roughly zero is reported rather than tuned away: the
world model is not yet beating "repeat the last window" when it has to imagine
the future without observations. `docs/KNOWN_LIMITATIONS.md` records this, along
with the fact that the linear transition baseline it is compared against is
barely a simulator.

**On real CIC-IDS2017 traffic: not measured.** No CIC-IDS2017 CSV is present in
this repository and none is downloaded by it; `data/raw/` holds only a synthetic
schema fixture. An earlier draft of this abstract quoted ~900k real flows and a
cross-day benchmark with a false-early rate of 0.12-0.18. Those numbers have been
withdrawn: they were not backed by a committed artifact, and this project does
not publish a measurement it cannot reproduce. The dataset's licence is
research-use and it is cited correctly (Sharafaldin et al., ICISSP 2018) — a
correct citation is not evidence that the run happened.

To make the real-data claim: place the licensed CSVs in
`data/raw/cic-ids2017/TrafficLabelling/` and run `make bench-real`.

**Also worth stating plainly:** the linear transition baseline that the world
model is compared against is barely a simulator — its stability projection
discards ~99.999% of the fitted map — so that comparison is not like-for-like,
and the forecast says so on its face. The lateral-movement detector rule has
precision 0.194 on held-out windows. Neither is hidden. See
`docs/KNOWN_LIMITATIONS.md`.

## Engineering Discipline

- **797 test functions across 83 files** (`uv run pytest -q` collects ~1,020
  cases including parametrised ones; all pass, 4 skipped), lint and format gates,
  SHA-256 checksums on every model artifact, and a reachability gate that fails the
  build if any module becomes unreachable
- **Leak-safe by construction:** scenario/temporal held-out splits audited by dedicated tests
- **Honest adapters:** four real defects in the CIC-IDS2017 distribution (12-hour clock defect, mixed encodings, mis-split packaging rows, header variants) are handled explicitly and pinned by tests — the timestamp correction was validated against the published UNB attack schedule
- **Deterministic replay:** fixed seeds; identical runs on any machine

## Demo

A Streamlit dashboard trains the models live (~4 s) and streams a **localhost-safe scripted attack** (recon → credential attempts → lateral transfer). During rehearsal: benign traffic reads P = 0.12, the scan burst triggers an **alert at P = 0.97 with MITRE evidence in ~33 s**, and the stage escalates to **Lateral Movement (TA0008) by ~63 s** — the same trained artifacts as the offline benchmark. A pre-rendered backup animation with identical numbers is included in case venue infrastructure fails. The dashboard can also replay genuine CIC-IDS2017 attack traffic from CSV or passively sniff a local interface.

---

*All numbers in this abstract are generated by the repository's scripts from measured results — none are hand-typed. Claim-status banners in every report separate what is proven from what is out of scope.*
