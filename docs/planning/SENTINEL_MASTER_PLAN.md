# SENTINEL — Master Analysis & 10-Sprint Execution Plan

> **Historical snapshot.** Written before the package rename `trajectory` → `sentinel` (commit `9effab5`); paths below reflect the plan as written. The current package is `src/sentinel/`, current state in [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).
### SIH 2026 · PS **26153** · *AI-Based Network Attack Forecasting from Network Traffic Data* · NTRO

> **Audience:** the human team **and** the AI coding agent (OpenCode + MiMo v2.5) that will execute this plan.
> **Status of this document:** derived from a full static + partial dynamic analysis of the uploaded repository snapshot (`-SENTINEL.rar`, 228 files, 58 commits, 10,603 LOC of `src/`, 236 test functions across 39 test files, 52 Markdown documents).
> **Rule of the repo:** this codebase has an unusually strong *honesty culture* (it refuses to call linear attribution "SHAP", it labels synthetic numbers as non-benchmarks). **Preserve that culture in every change.** Never let the agent inflate a claim.

---

# TABLE OF CONTENTS

| Part | Contents |
|---|---|
| **0** | How to use this document (agent operating manual) |
| **1** | What SENTINEL is today — verified codebase analysis |
| **2** | SIH 26153 compliance matrix (requirement → status → evidence → fix) |
| **3** | The 16 gaps, ranked by cost-to-score |
| **4** | The 10-Sprint plan (S1 → S10), task-by-task |
| **5** | Enhancements beyond the spec (the winning margin) |
| **6** | Deliverables checklist |
| **7** | Demo script + judge Q&A preparation |
| **8** | Appendices — commands, feature spec, glossary |

---

# PART 0 — HOW TO USE THIS DOCUMENT

## 0.1 The addressing scheme (so humans and the agent can talk)

Everything is addressable. Use these IDs in chat, commits, branches, and PRs.

```
S4-T3        → Sprint 4, Task 3
S4-T3-AC2    → Sprint 4, Task 3, Acceptance Criterion 2
G07          → Gap 07 (Part 3)
R-DEMO-PCAP  → a named requirement from the compliance matrix (Part 2)
```

**Branch naming:** `s4/t3-latent-transition-head`
**Commit format:** `S4-T3: add Gaussian transition head to world model`
**PR title:** `[S4-T3] Latent transition head — closes G01`

When you tell the agent to work, say: *"Execute S4-T3. Read Part 4 → Sprint 4 → T3. Do not start T4."*
When the agent reports back, it must state: *"S4-T3 complete. AC1 ✅ AC2 ✅ AC3 ❌ (reason). Tests: N added, M passing. Docs updated: X, Y."*

## 0.2 Operating rules for the AI coding agent (OpenCode / MiMo v2.5)

These are **hard constraints**. Put this section in the agent's system prompt or `AGENTS.md` at repo root.

### Non-negotiable rules

1. **One task per branch, one task per session.** MiMo v2.5 degrades on long multi-file sessions. Finish `S4-T3`, run tests, commit, then start a fresh session for `S4-T4`.
2. **Never fabricate a measurement.** If a number is not produced by a script that actually ran, it does not go in a Markdown file. Write `PENDING` instead. This repo already enforces this — do not break it.
3. **Never delete an honesty caveat** to make a result look better. If a caveat becomes untrue, prove it with a test and *then* edit it.
4. **Read before write.** Before editing a module, read the module *and* its test file *and* its section in `DATA_CONTRACTS.md` / `FEATURE_SPECIFICATION.md`.
5. **Tests are part of the task, not a follow-up.** No task is complete without tests. Target: every new public function has at least one happy-path test and one failure-path test.
6. **Contracts are Pydantic, and they are `extra="forbid"`.** Adding a field to a schema is an API change — update `DATA_CONTRACTS.md` and bump the version string in the same commit.
7. **Version strings are load-bearing.** `state-features-v1`, `gru-temporal-v1`, `transition-rollout-v1`, `stage-mapping-v1`, `cic-ids2017-adapter-v1`, `replay-evaluation-v1`, `forecast-inference-v1`, `threshold-calibration-v1`. If behaviour changes, bump to `-v2` and keep the old loader working or fail loudly.
8. **Leakage guards are sacred.** Feature statistics fit on *train only*. Threshold calibration on *validation only*. Test data is touched exactly once, at the end. If a change makes a leak-guard test pass "more easily", that is a bug, not a win.
9. **Offline-first.** `tests/test_offline.py` asserts no network clients in `src/trajectory`. Feed fetching lives in `scripts/`. Do not import `requests`/`httpx` into `src/trajectory/`.
10. **Run the gate before every commit:**
    ```bash
    uv run ruff check src tests scripts && \
    uv run ruff format --check src tests scripts && \
    uv run pytest -q
    ```

### Context-management protocol for MiMo v2.5

- `src/trajectory/dashboard/app.py` is **1,950 lines**. Do not load it whole into context repeatedly. Sprint 1 splits it into modules; until then, use targeted reads (`sed -n 'A,Bp'`) and targeted edits.
- Keep a `SCRATCHPAD.md` (gitignored) where the agent writes its plan before editing. Human reviews the plan, then the agent executes.
- When a task touches >5 files, the agent must first emit a **file-change manifest** (path → what changes → why) and wait for approval.

### The honesty check the agent runs before every doc edit

```
Does this sentence claim a capability?  → Is there a test that proves it?  → If no: rewrite or delete.
Does this sentence contain a number?    → Was it printed by a script in this run? → If no: mark PENDING.
Does this sentence say "real traffic"?  → Did the run use a licensed real dataset? → If no: say "synthetic".
```

## 0.3 Recommended `AGENTS.md` bootstrap

Create `/AGENTS.md` at repo root in Sprint 1 (task S1-T8) containing §0.2 above plus:

```markdown
# Project map
src/trajectory/          core library (offline, no network imports)
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
tests/                   pytest, 236 test functions
configs/                 YAML, strictly validated by config.py
```

---

# PART 1 — WHAT SENTINEL IS TODAY

## 1.1 One-paragraph summary

SENTINEL is an offline-first network-attack *forecasting* prototype. It normalises flow CSVs, PCAPs, syslog and JSONL sensor input into a single `UnifiedEvent` contract, aggregates them into time-windowed `NetworkState` objects, trains a leakage-audited logistic-regression baseline plus a per-horizon GRU classifier, produces a K-window infiltration-probability timeline, maps it to a MITRE-oriented attack stage with cited evidence, runs nine rule-based attack-type detectors, correlates findings into incidents and analyst cases, and presents everything through a nine-tab Streamlit dashboard, a 20-endpoint FastAPI service with API-key RBAC, and a Prometheus/Grafana stack. It ships a deliberately vulnerable local target app plus attack scripts for a live end-to-end demo.

**It is substantially further along than a typical hackathon entry.** The engineering discipline (typed contracts, split audits, checksummed artifacts, documented limitations) is the strongest asset. **The gap is not effort — it is that several of the specific things the problem statement names by word are not actually implemented.** That is what this plan fixes.

## 1.2 Verified repository inventory

| Area | Count / Size | Notes |
|---|---:|---|
| Python source (`src/trajectory`) | 10,603 LOC / 40 modules | Largest: `dashboard/app.py` 1,950 |
| Test functions | 236 across 39 files | |
| Markdown documents | 52 | Unusually complete planning corpus |
| Git commits | 58 | Linear history on `main` |
| Scripts (`scripts/`) | 17 CLIs | benchmark, replay, rollout, sensors, deck build |
| API endpoints | 20 | `/health` … `/metrics` |
| Docker services | API, dashboard, Prometheus, Grafana, vulnerable app, sensors, feed-refresher | 3 compose profiles |
| Deliverables present | `.pptx` (7 slides), `.pdf`, `ABSTRACT.md`, backup-demo GIF + frames | |

### Module-by-module (source of truth for the agent)

| Module | LOC | What it actually does | Health |
|---|---:|---|---|
| `schemas.py` | 293 | `UnifiedEvent`, `NetworkState`, `Forecast`, `StageMapping`, `LeadTimeEstimate`, `SequenceSample`, `SplitManifest`. All `extra="forbid"`. | ✅ Strong |
| `config.py` | 87 | Strict YAML→Pydantic validation, seed, offline flag | ✅ |
| `ingestion.py` | 144 | Flow CSV → events. Required + optional column sets, numeric validation, protocol/flag normalisation | ⚠️ `iterrows()` = slow; flags collapse to one bitmask float |
| `pcap_ingestion.py` | 154 | Scapy PCAP → per-packet events: TTL, window size, frag flags, payload size, flags, ports, dup-seq | ⚠️ Features extracted but lost at aggregation |
| `state_builder.py` | 115 | Events → windowed `NetworkState`; sum-or-mean aggregation; entity list; edge summary; coverage flags | 🔴 O(W×E) scan; **only sum/mean — no variance/max/percentile/entropy** |
| `features.py` | 83 | Fixed-width vectors, train-only z-score, forbidden-name guard | ✅ Clean |
| `targets.py` | 175 | Future-horizon labels, contiguous sequence samples, scenario split manifests | ✅ |
| `baseline.py` | 393 | Logistic regression + split audit + leak refusal + checksums + timing + report render | ✅ Exemplary |
| `temporal.py` | 382 | GRU encoder → linear head, **one model per horizon**, early stopping, class-weighted BCE, per-horizon metrics, weight persistence | 🔴 Import-time torch dependency bug (see G13); it is a *classifier*, not a transition model |
| `rollout.py` | 298 | Linear **ridge** next-state map, recursive K-step simulation, per-step drift diagnostics | 🔴 This is the "world model" — and it is a linear point-estimate map |
| `predict.py` | 494 | Artifact loading, probability timeline, driving features (coef × standardised value), stage attach, lead time, warnings | ⚠️ No SHAP, no attention |
| `calibration.py` | 139 | Validation-only threshold grid search, F1/Youden, audit of every candidate | ✅ |
| `evaluation.py` | 266 | Walk-forward replay, measured lead time, crossing rate, false-early rate | ✅ Good design |
| `stage_mapping.py` | 222 | 5 MITRE tactics via hardcoded absolute thresholds, `Unknown` when no rule fires | 🔴 `bytes > 10_000` will not transfer to real data; no technique IDs |
| `detectors.py` | 589 | 9 attack-type detectors with measured thresholds and explicit insufficient-telemetry returns | ✅ Honest design |
| `correlation.py` | 148 | Findings → incidents, risk fusion | ✅ |
| `assets.py` / `cases.py` / `registry.py` / `drift.py` / `compliance.py` / `federated.py` / `feedback.py` / `ledger.py` | 109–212 each | Asset criticality, case SLA lifecycle, model promote/rollback, PSI drift, NIST/ISO/SOC2 mapping, FedAvg sim, HMAC feedback, hash-chain ledger | ✅ Enterprise surface, honest about what's simulated |
| `live.py` | 655 | Live engine: 5 sources (CSV replay, JSONL, syslog tail, scapy iface, flow sensor) → rolling windows → detectors + forecast | ✅ Impressive |
| `api.py` | 620 | 20 FastAPI endpoints + RBAC deps + Prometheus `/metrics` | ✅ |
| `auth.py` | 288 | API keys (SHA-256 hashed), 4 roles, append-only audit, `org_id` | ✅ |
| `cic_ids2017.py` | 436 | CICFlowMeter CSV adapter; handles 12-hour clock, cp1252 en-dashes, 288k void rows, plural headers; **strict unmapped-label abort** | ✅ Best-in-class adapter |
| `threat_intel.py` | 247 | URLhaus feed enrichment, TTL-bound | ✅ |
| `synthetic.py` | 266 | Deterministic recon→lateral replay generator with precursor signals | ⚠️ No packet-level features; abrupt stage switch (documented cause of lead=0) |
| `dashboard/app.py` | 1,950 | 9 tabs | 🔴 Needs splitting; no PCAP upload |

## 1.3 Dynamic verification I actually ran

Environment: Python 3.12, no `torch`, no `fastapi`, no `scapy`, no `streamlit`.

```
pytest (excluding torch/fastapi-dependent files)
→ 111 passed, 2 skipped, 2 failed
  FAILED tests/test_dashboard_contracts.py::test_forecast_respects_history_cut  (torch missing)
  FAILED tests/test_threat_intel.py::test_create_app_bootstrap_env_grants_admin (fastapi missing)

pytest (full suite)
→ 14 test files FAIL TO COLLECT
  AttributeError: 'NoneType' object has no attribute 'Module'
  at src/trajectory/temporal.py:85  →  class _GRUClassifier(nn.Module)
```

**Interpretation:** the core library is healthy — 111/111 importable tests pass. The two failures and all 14 collection errors are the *same* root cause class: optional dependencies. But `temporal.py` **claims** torch is optional (`_require_torch()` guard, `--extra deep-learning`) while defining a `nn.Module` subclass at module import time. Since `predict.py` imports `temporal.py`, **the entire inference path hard-requires torch**, contradicting the documented optional-extra design. This is a genuine, fixable bug (G13, fixed in S1-T1).

## 1.4 What is genuinely excellent (do not regress these)

1. **Leakage discipline.** `baseline.py` runs a split audit and *refuses to train* on a leaky or single-class split. Feature statistics are train-only. Calibration is validation-only. This is better than most published papers.
2. **Artifact integrity.** SHA-256 on every saved model, runtime versions recorded, deterministic seeds.
3. **Explicit uncertainty.** `Unknown` stage with zero confidence is a first-class outcome. Detectors return `0.0` **with a warning** rather than guessing when telemetry is absent.
4. **The CIC-IDS2017 adapter.** It handles five separate real-world dataset defects and *aborts* on an unmapped label rather than silently dropping rows. This is the single most defensible piece of engineering in the repo — feature it in the demo.
5. **Observed vs Forecast labelling.** The UI and reports never blur what was measured with what was predicted.
6. **Documented failure.** `RESULTS.md` states plainly that lead time is 0.0 and explains *why*. Judges reward this if you show you then fixed it.

---

# PART 2 — SIH 26153 COMPLIANCE MATRIX

Legend: ✅ **MET** · 🟡 **PARTIAL** · 🔴 **GAP**

## 2.1 Core objectives (from "Background" and bullets)

| ID | Requirement (verbatim intent) | Status | Evidence in repo | Gap ID |
|---|---|:--:|---|---|
| R-STATE-VEC | Represent network state using **feature vectors** | ✅ | `features.py`, `state_builder.py` | — |
| R-STATE-GRAPH | …**or graphs** | 🔴 | `edge_summary` list exists; `dashboard/network_graphs.py` draws NetworkX for display only. No graph fed to any model. | G02 |
| R-SEQ-MODEL | Learn state-transition dynamics using **LSTM / Transformer** | 🟡 | GRU (`temporal.py`) — a GRU is a valid RNN, but it is a *per-horizon classifier*, not a transition model. No Transformer. | G01 |
| R-GNN | …**Graph Neural Networks** | 🔴 | None. | G02 |
| R-LATENT | …**latent state models** | 🔴 | None. | G01 |
| R-TRANSITION | Learn **P(S_t+1 \| S_t)** — a *probability distribution over next states* | 🔴 | `rollout.py` learns a **linear ridge point estimate** `S_{t+1} = W·[S_t..S_{t-m}] + b`. No distribution, no variance head, no uncertainty. | G01 |
| R-FORECAST-K | Forecast future states, **roll out K steps** | ✅ | `rollout_forecast()` with `RolloutDiagnostics` per-step drift | — |
| R-PROB | Estimate **probability of attacker progression** | ✅ | `ProbabilityPoint` timeline | — |
| R-MITRE | Map predicted behaviour to **MITRE ATT&CK** stages | 🟡 | 5 tactics, tactic-level IDs only (TA0043/TA0001/TA0008/TA0011/TA0010). Hardcoded absolute thresholds (`bytes > 10_000`). No technique IDs in the forecast path. | G11 |
| R-XAI-ATTN | Explainability via **attention mechanisms** | 🔴 | `grep -i attention src/` → zero hits. GRU has no attention layer. | G03 |
| R-XAI-SHAP | …**feature attribution / SHAP values** | 🔴 | `predict.py:9` explicitly: *"we do not call it SHAP because it is not SHAP."* Attribution = coefficient × standardised value (linear model only). `shap` not in dependencies. | G03 |
| R-GENERALISE | **Generalise to unseen attack patterns** — not memorise signatures | 🔴 | Splits are scenario-held-out and day-held-out, but *never* attack-family-held-out. No cross-dataset transfer test. | G10 |

## 2.2 Input data requirements ("Two Levels of Traffic Feature")

### Flow-level (NetFlow/IPFIX)

| Feature | Required | Status | Where |
|---|:--:|:--:|---|
| src/dst IP | ✔ | ✅ | `source_entity` / `destination_entity` |
| src/dst port | ✔ | 🟡 | Ingested, then **excluded from the model** in `configs/default.yaml` | 
| TCP flag bitmask (SYN/ACK/FIN/RST/PSH/URG) | ✔ | 🔴 | Parsed into a single float bitmask, then **mean-averaged across a window** (meaningless) and **excluded from the model** | 
| Protocol | ✔ | 🟡 | Mean-averaged (meaningless), excluded |
| Bytes per flow | ✔ | ✅ | summed |
| Packets per flow | ✔ | ✅ | summed |
| Flow duration | ✔ | ✅ | averaged |
| **IAT mean / variance / max** | ✔ | 🔴 | `iat_mean` only in synthetic; `iat_variance`/`iat_max` are optional columns **never produced** by any generator or sensor |
| Bidirectional flow ratio | ✔ | 🟡 | Present in synthetic; not computed from PCAP |

**Verdict: the four items the problem statement calls out by name — flag bitmask, ports, IAT statistics, protocol — are either excluded from the model or never computed.** This is the highest-embarrassment gap because a judge can `grep` for it. → **G04, G06.**

### Packet-level (PCAP-derived)

| Feature | Required | Extracted by `pcap_ingestion.py` | Survives into `NetworkState`? | Reaches the model? |
|---|:--:|:--:|:--:|:--:|
| TTL value | ✔ | ✅ | mean only | mean only |
| **TTL variance across a session** | ✔ | ❌ | ❌ | ❌ |
| TCP window size | ✔ | ✅ | mean only | mean only |
| IP fragment flags | ✔ | ✅ | mean (meaningless for flags) | mean |
| **Payload size distribution** | ✔ | size only | mean only — no distribution | ❌ |
| **Port scan signatures (sequential/randomised)** | ✔ | ❌ | ❌ | ❌ |
| Retransmission counts | ✔ | ✅ (dup-seq) | summed | ✅ |

**Verdict:** `state_builder.py` aggregates every feature by **sum** (if in `SUM_FEATURES`) or **mean** (everything else). Variance, max, percentile and entropy — which is where *all* the packet-level signal lives — are structurally impossible in the current design. → **G05.**

> The problem statement says the two levels are required *because* "packet-level features expose timing and sequencing patterns (a slow reconnaissance scan designed to evade flow-based thresholds)". A mean TTL cannot express that. This is the central technical criticism a knowledgeable judge will make.

## 2.3 Expected solution / deliverables

| ID | Deliverable | Status | Notes |
|---|---|:--:|---|
| R-PIPE | Feature pipeline ingesting CIC-IDS-2018 **or** CTU-13 CSV **and/or** raw PCAP (Scapy/PyShark) → timestamped normalised matrix | 🟡 | CIC-IDS**2017** adapter ✅ (2018 shares the CICFlowMeter schema — a thin alias closes this). CTU-13 ❌. PCAP via Scapy ✅. |
| R-TRAINED | Trained world model that **demonstrably learns transition dynamics** — not a static classifier | 🔴 | See G01. The per-horizon GRU is explicitly described in its own docstring as *"multi-horizon prediction without recursive state rollout"* — i.e. a classifier bank. |
| R-WEIGHTS | **Training scripts, model weights, reproducible training config must be included** | 🔴 | `.gitignore` excludes `*.pt`, `*.pth`, `*.onnx`, `reports/generated/`. **No weights ship.** Scripts ✅, configs ✅. |
| R-ENGINE | Infiltration prediction engine: K-step forward sim → probability + MITRE stage + top features | ✅ | `run_forecast.py`, `run_rollout.py` |
| R-XAI-OUT | Explainability output **using SHAP values or attention weights**. *"Black-box outputs without interpretability are not acceptable."* | 🔴 | Neither exists. G03. |
| R-DEMO-UI | Demo interface (Streamlit/Flask/CLI) that **accepts a PCAP or CSV file as input**, runs inference, displays probability timeline + flagged flows + stage annotations, **fully offline** | 🟡 | Streamlit ✅, offline ✅ (test-enforced), timeline ✅, stage ✅. **CSV upload exists only in the Live tab; there is NO PCAP upload anywhere.** `grep file_uploader` → csv, jsonl, syslog only. | 
| R-BENCH | Benchmarks (F1, precision, recall, FPR) **vs a logistic-regression baseline on the same features** | ✅ | `run_comparison.py`, `run_benchmark.py`, `RESULTS.md`. Best-in-class. |
| R-SRC | Source code link | ✅ | Git repo |
| R-README | README with setup instructions | ✅ | Excellent, 15 KB |
| R-ARCH | Architecture document, **max 2 pages** | 🟡 | `ARCHITECTURE_SUBMISSION.md` is a 914-byte draft with an ASCII flow — no diagram, under-uses the 2 pages |
| R-VIDEO | Demo video, **max 2 minutes** | 🔴 | Not present. A backup GIF + 4 frames exist. |
| R-DECK | Technical presentation, **max 5 slides** | 🔴 | `Trajectory_SIH26153_Idea_Deck.pptx` has **7 slides**. Over limit. |
| R-OSS | "A software-based, **fully open-source** solution is expected" | 🔴 | **No `LICENSE` file in the repository.** |

---

# PART 3 — THE 16 GAPS, RANKED BY COST-TO-SCORE

Ranked by *(probability a judge notices) × (points lost)*. The agent works these in the sprint order of Part 4, which is dependency-ordered, not severity-ordered.

| # | Gap | Severity | Why it costs you | Closed in |
|---|---|:--:|---|:--:|
| **G01** | **The "world model" is a linear ridge regression.** Required: a learned *distribution* `P(S_t+1\|S_t)` via LSTM/Transformer/GNN/latent model. | 🔴🔴🔴 | This is the *entire premise* of the problem statement. `rollout.py`'s own docstring calls it "a linear ridge map… sufficient to demonstrate the mechanism". A judge reading that sees "we did not build the thing you asked for." | **S4** |
| **G02** | **No graph representation reaches any model; no GNN.** | 🔴🔴🔴 | Named explicitly twice in the PS. Lateral movement *is* a graph phenomenon. | **S3** |
| **G03** | **No SHAP, no attention.** PS says black-box is "not acceptable". | 🔴🔴🔴 | Two named techniques, zero implemented. Trivially grep-able. | **S6** |
| **G04** | **TCP flags & ports are excluded from the model** (`configs/default.yaml`), and a flag bitmask is mean-averaged. | 🔴🔴 | PS demands "which specific **flags, ports** … are contributing most". You cannot attribute to a feature you excluded. | **S2** |
| **G05** | **Packet-level features collapse to sum/mean.** No variance, max, percentile, entropy. TTL variance, payload distribution, port-scan signature unimplemented. | 🔴🔴 | PS mandates these by name and explains *why* they matter (slow-scan evasion). | **S2** |
| **G09** | **Measured lead time = 0.0 windows.** The product promise is "before compromise is completed". | 🔴🔴 | Your own `RESULTS.md` says the forecast never fires early. This is the demo-killer question. | **S5** |
| **G07** | **Demo UI cannot accept a PCAP file.** | 🔴🔴 | Literally the evaluated artifact: "accepts a PCAP or CSV file as input". 10 minutes of judge time is spent here. | **S9** |
| **G08** | **No model weights ship** (`.gitignore` blocks `*.pt`, `reports/generated/`). | 🔴🔴 | PS: "model weights … must be included". Also means a judge cloning the repo gets nothing runnable without a full retrain. | **S1** |
| **G10** | **Generalisation to unseen attacks never tested.** | 🔴🔴 | PS: "Generalise to unseen attack patterns — not merely memorize signatures." Unverified = assumed false. | **S8** |
| **G11** | **MITRE mapping = 5 hardcoded absolute byte thresholds, tactic-level only.** Stage macro-F1 reported as `n/a`. | 🔴 | `bytes > 10_000` is a synthetic-data constant. It will misfire on real traffic and a judge may test exactly that. | **S7** |
| **G12** | **Only one dataset adapter (CIC-IDS2017).** PS lists CTU-13, UNSW-NB15, CICIoT2023, LANL auth. | 🔴 | PS names CTU-13 in the *expected solution* bullet. Single-dataset results are not credible. | **S8** |
| **G13** | **Broken optional-dependency contract:** `temporal.py:85` defines `nn.Module` subclass at import; `predict.py` imports it → all inference needs torch. 14 test files fail to collect without it. | 🔴 | If a judge installs the documented `uv sync` (core only), **nothing works**. | **S1** |
| **G14** | **`state_builder` is O(windows × events);** `ingestion.py` uses `iterrows()`. | 🟡 | CIC-IDS2017 is 2.8M flows. A 20-minute ingest during a 10-minute demo slot is fatal. | **S1** |
| **G16** | **No `LICENSE` file.** PS: "fully open-source solution is expected". | 🟡 | One file. Free points. | **S1** |
| **G15** | Deck is **7 slides** (max 5); architecture doc is a thin draft; **no demo video**. | 🟡 | Hard submission limits — an over-length deck can be disqualified or truncated. | **S10** |
| **G06** | IAT variance/max never computed; bidirectional ratio not derived from PCAP. | 🟡 | Named flow feature, absent. Cheap to fix once S2 aggregation exists. | **S2** |

---

# PART 4 — THE 10-SPRINT EXECUTION PLAN

## 4.0 Sprint map and dependency graph

```
S1  Foundation repair & release hygiene      ── unblocks everything
 │
 ├─▶ S2  Feature engineering to specification ── unblocks S3, S4, S6
 │    │
 │    ├─▶ S3  Graph state + GNN encoder ──────┐
 │    │                                        │
 │    └─▶ S4  The real world model ◀───────────┘  (GNN encoder plugs into transition core)
 │            │
 │            ├─▶ S5  Entity-level forecasting & lead time
 │            │
 │            ├─▶ S6  Explainability (SHAP + attention)
 │            │
 │            └─▶ S7  MITRE stage engine
 │                     │
 └────────────────────▶ S8  Datasets & generalisation
                              │
                              ├─▶ S9   Demo interface & operator UX
                              │
                              └─▶ S10  Submission hardening
```

**Suggested cadence:** 10 sprints. If you have 4 weeks, run ~2.5 days/sprint. If you have 6 weeks, 4 days/sprint with S4 and S5 double-length. **S1, S2, S4, S6, S7, S9, S10 are mandatory. S3, S5, S8 are the winning margin — cut S3 first if time collapses, never cut S6.**

### Minimum-viable-compliance cut (if you have only 2 weeks)
`S1 → S2 → S4(reduced: Transformer + Gaussian head only, skip ensemble) → S6 → S7 → S9 → S10`. Skip S3, S5, S8. You will be compliant but not distinctive.

---

## SPRINT 1 — Foundation Repair & Release Hygiene

**Goal:** a judge can `git clone`, run one command, and get a working system with real weights in under 10 minutes — and the agent can work fast for the next 9 sprints.
**Why it scores:** closes G08, G13, G14, G16. Removes the "doesn't run" risk entirely.
**Exit demo:** clean-machine clone → `make demo` → dashboard up with pretrained weights loaded, no training required.

### S1-T1 — Fix the optional-dependency contract (G13)

**Files:** `src/trajectory/temporal.py`, `src/trajectory/predict.py`, `tests/test_optional_deps.py` (new)

**Problem (verified):** `temporal.py:85` executes `class _GRUClassifier(nn.Module)` at module import. When torch is absent `nn is None` → `AttributeError`. `predict.py:44` imports `temporal`, so the whole inference stack is torch-bound, contradicting `--extra deep-learning`.

**Fix:** move the class definition inside a factory.

```python
# temporal.py
def _build_gru_classifier(input_dim: int, hidden_size: int, num_layers: int, dropout: float):
    """Construct the GRU classifier. Imported lazily so torch stays optional."""
    _require_torch()

    class _GRUClassifier(nn.Module):
        def __init__(self) -> None:
            super().__init__()
            self.gru = nn.GRU(input_dim, hidden_size, num_layers=num_layers,
                              batch_first=True,
                              dropout=dropout if num_layers > 1 else 0.0)
            self.head = nn.Linear(hidden_size, 1)
        def forward(self, x):
            _, h = self.gru(x)
            return self.head(h[-1]).squeeze(-1)

    return _GRUClassifier()
```

Also make `TemporalRun.models` typed as `dict[int, object]` (or `TYPE_CHECKING`-guarded) so the dataclass annotation does not touch `nn`.

**Acceptance criteria**
- **AC1** `python -c "import trajectory.predict"` succeeds in an environment with **no torch installed**.
- **AC2** Full `pytest` collects 0 errors with torch absent; torch-requiring tests **skip** via `pytest.importorskip`, never error.
- **AC3** With torch present, all previously-passing temporal tests still pass, byte-identical metrics for seed 42.
- **AC4** New `tests/test_optional_deps.py` asserts importability of `ingestion`, `state_builder`, `features`, `baseline`, `predict`, `stage_mapping`, `detectors`, `evaluation` under a `sys.modules` patch that hides `torch`, `scapy`, `fastapi`, `streamlit`.

**Agent prompt**
> Execute S1-T1. Read `src/trajectory/temporal.py` lines 1–120 and `src/trajectory/predict.py` lines 1–60. Move the `_GRUClassifier` definition into a `_build_gru_classifier()` factory guarded by `_require_torch()`. Update every construction site. Add `tests/test_optional_deps.py` that hides torch/scapy/fastapi/streamlit via `monkeypatch.setitem(sys.modules, ...)` and asserts the eight core modules import. Run `uv run pytest -q`. Do not change any model maths.

---

### S1-T2 — Ship model weights and a release artifact bundle (G08)

**Files:** `.gitignore`, `models/release/` (new), `scripts/export_release_artifacts.py` (new), `scripts/verify_release_artifacts.py` (new), `README.md`

**Design:** create a versioned, checksummed, committed bundle.

```
models/release/v1/
  MANIFEST.json            # versions, seeds, config hash, dataset id, SHA-256 of every file
  feature_schema.json      # names, means, scales, excluded
  split_manifest.json
  baseline.joblib
  calibration.json
  weights/model_h1.pt … model_h5.pt
  transition_model.json
  world_model.pt           # (arrives in S4)
  TRAINING_CONFIG.yaml     # exact config used
  PROVENANCE.md            # dataset licence, command line, git SHA, timestamp
```

`.gitignore` changes: keep the global `*.pt` ignore but add negations:
```gitignore
!models/release/**/*.pt
!models/release/**/*.json
!models/release/**/*.joblib
```
If total bundle > 50 MB, use Git LFS (`git lfs track "models/release/**"`) and document it. CPU GRU weights at `hidden_size=32` are ~KB, so plain git is fine today; the S4 world model may be a few MB — still fine.

**Acceptance criteria**
- **AC1** `scripts/export_release_artifacts.py --run-dir reports/generated --out models/release/v1` writes the bundle with a `MANIFEST.json` containing a SHA-256 per file and the git SHA.
- **AC2** `scripts/verify_release_artifacts.py models/release/v1` re-hashes every file and exits non-zero on mismatch. Wired into CI.
- **AC3** `predict.load_artifacts("models/release/v1")` loads without any training step.
- **AC4** Weights are committed and visible in `git ls-files models/release`.
- **AC5** README gains a "Run with pretrained weights (no training)" section as the **first** runnable instruction.

---

### S1-T3 — Make ingestion and windowing fast enough for real datasets (G14)

**Files:** `src/trajectory/state_builder.py`, `src/trajectory/ingestion.py`, `tests/test_performance.py` (new)

**Problem A — `state_builder.build_network_states`:** for each window it scans *all* events:
```python
window_events = [e for e in ordered_events if start <= e.timestamp < end]
```
→ O(windows × events). With 60 s windows / 30 s stride over a 9-hour CIC day and 500k flows, this is ~10⁹ comparisons.

**Fix:** precompute a sorted timestamp array and use `bisect_left`/`bisect_right` to slice:
```python
import bisect
stamps = [e.timestamp for e in ordered_events]   # already sorted
lo = bisect.bisect_left(stamps, start)
hi = bisect.bisect_left(stamps, end)
window_events = ordered_events[lo:hi]
```
This is exact for half-open `[start, end)` and is O(windows × log n + total slice size).

**Problem B — `ingestion.read_flow_csv`:** `for row_number, row in frame.iterrows()` builds a dict per row (slow, ~10k rows/s) and indexes `timestamps.iloc[row_number]`, which silently assumes a `RangeIndex`.

**Fix:** vectorise. Build column arrays with `frame[col].to_numpy(dtype=float)`, then construct events in one list comprehension over `zip(*arrays)`. Use `frame.reset_index(drop=True)` immediately after read to make the positional assumption explicit and safe.

**Acceptance criteria**
- **AC1** `build_network_states` output is **byte-identical** (compare `model_dump_json()`) to the old implementation on the existing fixture and on a randomised 10k-event property test.
- **AC2** New `tests/test_performance.py`: 200,000 synthetic events, 60 s/30 s windows → `build_network_states` completes in **< 5 s** on CI.
- **AC3** `read_flow_csv` on a 200,000-row CSV completes in **< 10 s**; output events identical to the old path on the fixture.
- **AC4** A test asserts correctness under a non-RangeIndex DataFrame.

---

### S1-T4 — Add `LICENSE` and open-source compliance (G16)

**Files:** `LICENSE` (new), `README.md`, `NOTICE` (new), `THIRD_PARTY.md` (new)

- Choose **Apache-2.0** (patent grant, government-friendly, permissive). MIT is acceptable; do not use GPL — it complicates NTRO/CII adoption.
- `THIRD_PARTY.md`: table of every dependency → licence → purpose. Generate with `pip-licenses` and commit.
- Add dataset licence attributions: CIC-IDS2017 requires citing *Sharafaldin, Lashkari & Ghorbani, ICISSP 2018* (already in `cic_ids2017.py` docstring — promote it to `PROVENANCE.md` and README).
- Add SPDX headers to `src/trajectory/*.py`: `# SPDX-License-Identifier: Apache-2.0`.

**AC1** `LICENSE` present. **AC2** `THIRD_PARTY.md` lists every runtime dep with a licence. **AC3** No copyleft dependency in the runtime set. **AC4** README states the licence in the first 20 lines.

---

### S1-T5 — Split `dashboard/app.py` (1,950 lines) into modules

**Files:** `src/trajectory/dashboard/` → new `tabs/` package

```
dashboard/
  app.py                 # ≤ 250 lines: config, sidebar, data loading, tab wiring
  state.py               # session-state helpers, cache, invalidation
  tabs/overview.py
  tabs/forecast.py
  tabs/states.py
  tabs/comparison.py
  tabs/replay.py
  tabs/demo.py
  tabs/live.py
  tabs/metrics.py
  tabs/story.py
  tabs/analyze.py        # created in S9 — the PCAP/CSV upload tab
```

Each tab module exposes `def render(ctx: DashboardContext) -> None`. `DashboardContext` is a frozen dataclass carrying config, artifacts, manifest, states, scenario ids.

**Why this is a Sprint-1 task:** MiMo v2.5 will be editing the dashboard in S6, S7 and S9. A 1,950-line file will blow context and cause regressions. Pay this cost now.

**AC1** No dashboard module exceeds 400 lines. **AC2** `tests/test_dashboard_contracts.py` still passes plus a new Streamlit `AppTest` smoke test that renders all tabs. **AC3** No behaviour change — capture a before/after screenshot set.

---

### S1-T6 — `Makefile` + one-command paths

**Files:** `Makefile` (new), `run_all.sh` (align)

```makefile
setup:      ## install everything
	uv sync --all-extras
gate:       ## lint + format-check + tests  (run before every commit)
	uv run ruff check src tests scripts
	uv run ruff format --check src tests scripts
	uv run pytest -q
demo:       ## dashboard with pretrained release weights, no training
	uv run streamlit run src/trajectory/dashboard/app.py -- --artifacts models/release/v1
train:      ## full reproducible training run
	uv run python scripts/run_benchmark.py --config configs/default.yaml
reproduce:  ## train, then verify metrics match RESULTS.md within tolerance
	uv run python scripts/run_benchmark.py --config configs/default.yaml
	uv run python scripts/verify_results.py --results RESULTS.md --run reports/generated/benchmark
bench-real: ## CIC-IDS2017 cross-day benchmark
	uv run python scripts/run_real_benchmark.py --data-dir data/raw/cic-ids2017/TrafficLabelling
```

**AC1** `make gate` is green. **AC2** `make demo` works on a machine that has never trained. **AC3** `make reproduce` exits non-zero if any headline metric drifts > 0.01 from `RESULTS.md`.

---

### S1-T7 — CI hardening

**Files:** `.github/workflows/ci.yml`

Add: (a) a matrix `python-version: [3.11, 3.12, 3.13]`; (b) a **core-only** job (`uv sync` without extras) that proves S1-T1; (c) `verify_release_artifacts.py`; (d) a `pytest --cov=trajectory --cov-fail-under=70` gate; (e) `pip-audit` for dependency CVEs; (f) upload `reports/generated/benchmark/BENCHMARK.md` as a build artifact.

**AC1** All jobs green on `main`. **AC2** The core-only job fails if anyone re-introduces an import-time torch dependency.

---

### S1-T8 — Author `AGENTS.md`

**Files:** `AGENTS.md` (new)

Contents: §0.2 of this document + the project map + the version-string registry + "never fabricate a number" + the pre-commit gate. This is what OpenCode reads at session start.

**AC1** File exists and is referenced from README. **AC2** The agent's first action in every subsequent session is to read it.

### Sprint 1 Definition of Done
- [ ] `pytest` collects and runs clean with **and** without optional extras
- [ ] `models/release/v1/` committed, checksum-verified in CI
- [ ] 200k-event windowing < 5 s; 200k-row CSV ingest < 10 s
- [ ] `LICENSE`, `NOTICE`, `THIRD_PARTY.md` present
- [ ] No dashboard file > 400 lines
- [ ] `make demo` works from a cold clone
- [ ] `AGENTS.md` committed
- [ ] `IMPLEMENTATION_STATUS.md` updated with Sprint 1 section

---

## SPRINT 2 — Feature Engineering to Specification

**Goal:** every flow-level and packet-level feature the problem statement names by word is computed, aggregated with statistics that preserve signal, and *reaches the model*.
**Why it scores:** closes G04, G05, G06. Makes G03 (explainability) meaningful — you cannot attribute to features you do not have.
**Exit demo:** a side-by-side table: "PS-required feature → our feature name → aggregation → present in model input? ✅".

### S2-T1 — Rich aggregation in `state_builder` (G05)

**Files:** `src/trajectory/state_builder.py`, `src/trajectory/schemas.py`, `FEATURE_SPECIFICATION.md`

Replace the binary `SUM_FEATURES` / else-mean rule with a declarative **aggregation policy**:

```python
from enum import Enum

class Agg(str, Enum):
    SUM = "sum"; MEAN = "mean"; STD = "std"; VAR = "var"
    MAX = "max"; MIN = "min"; P50 = "p50"; P90 = "p90"; P99 = "p99"
    ENTROPY = "entropy"; NUNIQUE = "nunique"; RATIO = "ratio"

# feature name -> tuple of aggregations to emit
AGGREGATION_POLICY: dict[str, tuple[Agg, ...]] = {
    "bytes":            (Agg.SUM, Agg.MEAN, Agg.STD, Agg.MAX, Agg.P90),
    "packets":          (Agg.SUM, Agg.MEAN, Agg.MAX),
    "duration":         (Agg.MEAN, Agg.STD, Agg.MAX),
    "ttl":              (Agg.MEAN, Agg.STD, Agg.VAR, Agg.MIN, Agg.MAX, Agg.NUNIQUE),
    "tcp_window_size":  (Agg.MEAN, Agg.STD, Agg.MIN, Agg.MAX),
    "payload_size":     (Agg.SUM, Agg.MEAN, Agg.STD, Agg.P50, Agg.P90, Agg.ENTROPY),
    "iat":              (Agg.MEAN, Agg.VAR, Agg.MAX, Agg.MIN, Agg.P90),
    ...
}
```

Emitted feature names become `f"{base}_{agg}"` → `ttl_var`, `payload_size_p90`, `iat_max`. **Bump `FEATURE_VERSION` to `state-features-v2`.**

Backward compatibility: keep a `LEGACY_ALIASES` map (`bytes` → `bytes_sum`, `duration` → `duration_mean`) so `stage_mapping.py` and `detectors.py` keep working until S7 migrates them. Emit a `DeprecationWarning` when an alias is read.

**AC1** `NetworkState.features` contains `ttl_var`, `iat_var`, `iat_max`, `payload_size_p90`, `payload_size_entropy` when the corresponding events are present.
**AC2** Absent inputs produce **absent keys**, never `0.0` — the existing "represent insufficient evidence, never fabricate" rule must hold. Add a test that asserts key absence.
**AC3** Single-event windows produce `std`/`var` as absent (not `0.0`), with a documented rationale.
**AC4** Feature count per window is deterministic given the input feature set; recorded in `coverage`.

### S2-T2 — TCP flag decomposition and port behaviour features (G04)

**Files:** `src/trajectory/ingestion.py`, `src/trajectory/pcap_ingestion.py`, `src/trajectory/state_builder.py`, `configs/default.yaml`

**Stop mean-averaging a bitmask.** At event level, decompose:

```python
FLAG_BITS = {"FIN": 1, "SYN": 2, "RST": 4, "PSH": 8, "ACK": 16, "URG": 32}
# per event, emit six 0/1 indicators:
features |= {f"flag_{name.lower()}": float(bool(mask & bit)) for name, bit in FLAG_BITS.items()}
```

At window level, emit **counts and ratios** (this is the "flag distribution" the PS asks for):

| Feature | Definition | Detects |
|---|---|---|
| `flag_syn_count` | Σ SYN | scan / flood volume |
| `flag_syn_ratio` | SYN / total flags | **SYN flood, half-open scan** |
| `flag_syn_ack_ratio` | SYN / max(ACK,1) | unanswered SYNs → stealth scan |
| `flag_rst_ratio` | RST / total | closed-port probing |
| `flag_fin_ratio`, `flag_psh_ratio`, `flag_urg_ratio` | — | FIN/XMAS scans |
| `flag_no_ack_share` | share of flows with SYN and no ACK | **the PS's "SYN flags precede ACK floods" pattern** |

**Port behaviour** (this is the PS's "port scan signatures (sequential or randomised port access patterns)"):

| Feature | Definition |
|---|---|
| `dst_port_nunique` | distinct destination ports per source in the window |
| `dst_port_entropy` | Shannon entropy of the destination-port distribution |
| `dst_port_sequential_score` | fraction of consecutive (by time) dst-port deltas equal to ±1 → **sequential scan** |
| `dst_port_randomness` | normalised entropy ÷ log(nunique) → **randomised scan** |
| `dst_port_low_share` | share of dst ports < 1024 |
| `dst_port_wellknown_share` | share in {22,23,25,53,80,135,139,443,445,3389} |
| `src_port_ephemeral_share` | share of src ports > 32768 |
| `ports_per_host_max` | max distinct ports hit on a single destination host |

Implement `dst_port_sequential_score` as a dedicated function with its own test — it is the most demo-able feature in the whole project:

```python
def sequential_port_score(ports_in_time_order: Sequence[int]) -> float:
    """Fraction of consecutive probes whose destination port differs by exactly ±1.

    1.0 => textbook sequential scan (nmap default without -r randomisation)
    ~0.0 => random or normal traffic
    Returns 0.0 for fewer than 3 probes (insufficient evidence, documented).
    """
```

**Then re-enable flags and ports in the model.** Change `configs/default.yaml`:
```yaml
baseline_config:
  # v2: raw identifiers stay excluded (entity memorisation risk),
  # but derived behavioural flag/port features are now eligible inputs.
  excluded_features: [source_port_mean, destination_port_mean, protocol_mean, tcp_flags_mean]
```
Keep excluding **raw mean-aggregated identifiers** (`destination_port_mean` really is meaningless and memorisation-prone) but **include** every derived ratio/entropy/count feature. Document this distinction in `FEATURE_SPECIFICATION.md` — it is a defensible, sophisticated answer to "why did you exclude ports?"

**AC1** A synthetic sequential nmap-style scan yields `dst_port_sequential_score > 0.9`; randomised scan `< 0.2`; benign web traffic `< 0.1`.
**AC2** A SYN-flood fixture yields `flag_syn_ratio > 0.8` and `flag_syn_ack_ratio > 10`.
**AC3** `FEATURE_SPECIFICATION.md` has a table: PS-named feature → implemented name → aggregation → eligible for model (Y/N) → rationale if N.
**AC4** The baseline retrains and reports feature weights that **include** flag/port features, proving they reach the model.

### S2-T3 — IAT statistics and bidirectional ratio from real sources (G06)

**Files:** `scripts/flow_sensor.py`, `src/trajectory/pcap_ingestion.py`, `src/trajectory/synthetic.py`

- In the PCAP path, group packets by 5-tuple, compute per-flow inter-arrival deltas → `iat_mean`, `iat_var`, `iat_max`, `iat_min`, `iat_p90`. Attach to the flow-summary event emitted at teardown.
- Compute `bidirectional_ratio` = reverse-direction bytes ÷ (forward + reverse) per 5-tuple.
- Add `retransmission_count` properly (currently a duplicate-sequence indicator) — count repeated `(seq, len)` pairs per flow.
- Extend `synthetic.py` to emit packet-level features (`ttl`, `tcp_window_size`, `fragment_flags`, `payload_size`) so the synthetic benchmark actually exercises the packet path. **Give the recon phase a low-and-slow signature:** high `iat_mean`, high `iat_var`, high `dst_port_nunique`, near-zero bytes — this is the pattern that will produce lead time in S5.

**AC1** `read_pcap` on a generated PCAP returns flow-summary events carrying all five IAT statistics.
**AC2** Synthetic states report `coverage["packet"] == True` and contain TTL/window/payload features.
**AC3** A "slow scan" synthetic scenario has `iat_mean` at least 10× the benign scenario.

### S2-T4 — Regenerate the feature catalogue

**Files:** `FEATURE_CATALOG.md`, `scripts/dump_feature_catalog.py` (new)

Auto-generate `FEATURE_CATALOG.md` from the aggregation policy + ingestion column sets so it can never drift from code. CI fails if the committed catalogue differs from the generated one.

**AC1** `scripts/dump_feature_catalog.py --check` exits non-zero on drift; wired into CI.

### Sprint 2 Definition of Done
- [ ] Every PS-named flow and packet feature is computed, with a test
- [ ] Flags and ports are *in* the model input, with derived behavioural features
- [ ] `state-features-v2` bumped; legacy aliases documented and deprecation-warned
- [ ] Sequential/randomised port-scan scores implemented and tested
- [ ] `FEATURE_CATALOG.md` auto-generated and drift-checked
- [ ] Baseline retrained; new `RESULTS.md` row recorded (expect F1 to move — report honestly either way)

---

## SPRINT 3 — Graph State Representation & GNN Encoder

**Goal:** the network state *is* a graph, and a graph neural network encodes it.
**Why it scores:** closes G02 — a requirement named twice in the PS and currently at zero.
**Exit demo:** "here is the host graph at t=14:22; the GAT attention says the model is watching host 192.168.10.50's fan-out to 47 destinations."

> **Dependency note:** prefer **PyTorch Geometric** if it installs cleanly on CPU; otherwise implement GraphSAGE/GAT message passing in ~150 lines of plain PyTorch (`torch.index_add_` scatter + softmax). **Do not block the sprint on a dependency.** A hand-rolled GAT is ~120 lines and removes all install risk — recommended.

### S3-T1 — `graph_state.py`: window → typed graph

**Files:** `src/trajectory/graph_state.py` (new), `src/trajectory/schemas.py`

```python
class NetworkGraph(BaseModel):
    """Host-level graph for one time window. Version: network-graph-v1."""
    model_config = ConfigDict(extra="forbid")
    version: str = "network-graph-v1"
    window_start: datetime
    window_end: datetime
    node_ids: list[str]                      # host identifiers, stable ordering
    node_features: list[list[float]]         # [n_nodes, node_dim]
    node_feature_names: list[str]
    edge_index: list[list[int]]              # [2, n_edges] COO, src→dst
    edge_features: list[list[float]]         # [n_edges, edge_dim]
    edge_feature_names: list[str]
    node_roles: list[str]                    # internal | external | gateway | unknown
    coverage: dict[str, bool]
```

**Node features (per host, per window):** out-degree, in-degree, bytes sent/received, packets sent/received, `dst_port_nunique`, `dst_port_entropy`, `dst_port_sequential_score`, `flag_syn_ratio`, `flag_rst_ratio`, failed-auth count, `iat_mean`/`iat_var` of its flows, new-peer count vs previous window, `is_internal`, asset criticality (from `assets.py`).

**Edge features (per directed host pair):** flow count, bytes, packets, duration mean, flag ratios, `dst_port_nunique` on that edge, `is_new_edge` (unseen in the last N windows — the existing lateral-movement signal, promoted to a graph feature), mean IAT.

**Critical:** node identity must **not** leak. Do not one-hot IPs. Use only behavioural features + an `is_internal` flag. Add this to `FORBIDDEN_FEATURE_NAMES` logic and test it.

**AC1** `build_network_graph(events, window) -> NetworkGraph` with deterministic node ordering (sorted by host id).
**AC2** Node/edge counts match the `edge_summary` produced by `state_builder` on the same window (consistency test).
**AC3** No feature encodes an IP address, hostname, or MAC. Test asserts this by scanning `node_feature_names`.
**AC4** Empty window → graph with zero nodes and a coverage flag, not an exception.

### S3-T2 — GAT encoder

**Files:** `src/trajectory/gnn.py` (new)

```python
class GraphAttentionEncoder(nn.Module):
    """Multi-head GAT over the host graph. Returns (graph_embedding, node_embeddings, attention).

    attention: list per layer of (edge_index, alpha[n_edges, n_heads]) — exported for explainability.
    """
```

- 2 layers, 4 heads, `hidden=64`, ELU, dropout 0.1.
- Readout: concatenate `mean(node_emb)`, `max(node_emb)`, and a learned attention-weighted sum → graph embedding of fixed width.
- **Export attention.** `alpha` is exactly the "attention mechanism" explainability the PS asks for. Store it; S6 renders it.
- Provide a `GraphSAGE` alternative behind a config flag for an ablation row.

**AC1** Forward pass on a 50-node/200-edge graph runs on CPU in < 50 ms.
**AC2** Attention weights per layer sum to 1.0 across each node's incoming edges (softmax invariant test).
**AC3** Deterministic under a fixed seed.
**AC4** Permuting node order (with the same graph) yields an identical graph embedding within 1e-5 — **permutation-invariance test**. This is the single most important GNN correctness test.

### S3-T3 — Wire the encoder into the sequence path

**Files:** `src/trajectory/graph_sequence.py` (new)

Produce, per window, a fused state vector: `concat(tabular_features_v2, graph_embedding)`. This is the input `S_t` that the S4 world model consumes. Keep tabular-only as a config-selectable ablation so you can report "GNN adds +X F1".

**AC1** Config flag `model.state_encoder: tabular | graph | fused`, all three train end-to-end.
**AC2** `RESULTS.md` gains a three-row ablation table.

### Sprint 3 Definition of Done
- [ ] `NetworkGraph` contract, documented in `DATA_CONTRACTS.md`
- [ ] Hand-rolled or PyG GAT with exported attention; permutation-invariance test passes
- [ ] No identity leakage, test-enforced
- [ ] Ablation: tabular vs graph vs fused, numbers in `RESULTS.md`
- [ ] Dashboard "Network States" tab renders the graph with attention-weighted edge thickness

---

## SPRINT 4 — The Real World Model ⭐ *most important sprint*

**Goal:** replace the linear ridge map with a learned **latent state-space model** that outputs a **probability distribution** over the next state, supports free-running K-step rollout with calibrated uncertainty, and comes in LSTM / Transformer / GNN-fused variants.
**Why it scores:** closes G01 — the premise of the entire problem statement.
**Exit demo:** "given the last 8 windows, here are 100 sampled futures; 73 of them cross the infiltration boundary by step 3; here is the mean trajectory with a 90% band."

### S4-T1 — The architecture: `world_model.py`

**Files:** `src/trajectory/world_model.py` (new, expect ~500 LOC), `MODEL_PLAN.md`

Build a **recurrent state-space model (RSSM-lite)**, the standard world-model formulation, adapted to network telemetry:

```
Observation  o_t ∈ R^d        (fused tabular + graph features from S2/S3)
Encoder      e_t = Enc(o_t)                        MLP, d → 128
Recurrent    h_t = GRU/Transformer(h_{t-1}, [z_{t-1}, e_t])   deterministic path
Posterior    q(z_t | h_t, e_t) = N(mu_q, sigma_q)  "what the state is, given evidence"
Prior        p(z_t | h_t)      = N(mu_p, sigma_p)  "what the state should be, predicted"
Decoder      o_hat_t ~ p(o_t | h_t, z_t)           reconstruct observation
Risk head    P(infiltration_t) = sigma(MLP([h_t, z_t]))
Stage head   softmax over MITRE stages             (used by S7)
```

**Loss:**
```
L = recon_nll(o_hat_t, o_t)                 # learn the dynamics
  + beta * KL(q(z_t|h_t,e_t) || p(z_t|h_t)) # make the PRIOR able to predict without evidence
  + lambda * BCE(risk_t, y_t)               # tie latent state to the security outcome
  + gamma * CE(stage_t, stage_label_t)      # optional, from S7
```

**This is what makes it a world model, and you must be able to say it in one sentence to a judge:**
> "The KL term forces the prior — which sees no future observation — to match the posterior, which does. That is exactly how the model learns to imagine the next state instead of classifying the current one."

**Three interchangeable transition cores**, selected by config:
1. `lstm` — `nn.LSTM`, satisfies the PS's named "LSTM".
2. `transformer` — causal `nn.TransformerEncoder` with **learned temporal attention**, satisfies the PS's named "Temporal Transformer" *and* provides attention weights for S6. **Make this the default.**
3. `gnn_fused` — the S3 GAT encoder feeding either core.

**Free-running rollout (`imagine`):**
```python
def imagine(self, history: Tensor, k: int, n_samples: int = 100, temperature: float = 1.0):
    """Roll the PRIOR forward k steps without observations, sampling z each step.

    Returns
    -------
    states : [n_samples, k, d]        decoded imagined observations
    risk   : [n_samples, k]           infiltration probability per sample per step
    stages : [n_samples, k, n_stages] stage distribution per step
    """
```
This gives you the **probability distribution over future states** the PS demands — not a point estimate — and the sample spread is your uncertainty band.

**AC1** `WorldModel` trains on the synthetic dataset and the loss decreases; a test asserts final loss < 0.8 × initial.
**AC2** `imagine(k=5, n_samples=100)` returns correctly-shaped tensors and is reproducible under a fixed seed.
**AC3** All three cores train and are selectable by `configs/*.yaml`.
**AC4** The **prior** alone (no observations) predicts the next observation better than a persistence baseline (`o_{t+1} = o_t`) — measured as one-step MSE on the test split. *This is the empirical proof that dynamics were learned.* Report it as `one_step_prediction_mse` in `RESULTS.md`.
**AC5** `model_version = "world-model-rssm-v1"`, checksummed, saved to `models/release/`.

### S4-T2 — Uncertainty and calibration

**Files:** `src/trajectory/world_model.py`, `src/trajectory/calibration.py`

- **Epistemic:** train a 5-member ensemble with different seeds; ensemble disagreement = epistemic uncertainty.
- **Aleatoric:** the learned `sigma` of the prior.
- Report both per timeline point. Extend `ProbabilityPoint` with `probability_lower`, `probability_upper`, `epistemic`, `aleatoric` (bump `Forecast` version).
- Add **reliability diagrams** and **Expected Calibration Error (ECE)** to `metrics.py`. A forecast that says 0.7 should be right 70% of the time. Existing threshold calibration handles decisions; this handles honesty of the probability itself.
- Add **Brier score** — the standard metric for probabilistic forecasts, and one no competing team will report.

**AC1** `ProbabilityPoint` carries an uncertainty band; the dashboard renders it as a shaded region.
**AC2** `metrics.expected_calibration_error(probs, labels, n_bins=10)` implemented and tested on synthetic perfectly-calibrated and perfectly-miscalibrated inputs.
**AC3** `RESULTS.md` reports Brier score and ECE for baseline, GRU, and world model.
**AC4** Ensemble spread widens monotonically with rollout step `k` (a test asserts this — it is the physically correct behaviour and proves the uncertainty is real).

### S4-T3 — Rollout comparison harness

**Files:** `scripts/run_world_model.py` (new), `src/trajectory/evaluation.py`

`evaluate_replay` already accepts a `forecast_fn` override — reuse it. Produce a single table on identical windows:

| Forecaster | F1 | Precision | Recall | FPR | PR-AUC | Brier | ECE | Median lead | Crossing rate | False-early | 1-step MSE |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Logistic baseline | | | | | | | | | | | — |
| GRU per-horizon | | | | | | | | | | | — |
| Linear ridge rollout | | | | | | | | | | | |
| **World model (LSTM)** | | | | | | | | | | | |
| **World model (Transformer)** | | | | | | | | | | | |
| **World model (GNN-fused)** | | | | | | | | | | | |
| Persistence (`o_{t+1}=o_t`) | — | — | — | — | — | — | — | — | — | — | |

**Keep the linear ridge model.** Do not delete `rollout.py`. It becomes your ablation row and proves you measured rather than assumed. That is a strong signal to technical judges.

**AC1** One command produces the full table as `reports/generated/world-model/COMPARISON.md`.
**AC2** Identical splits, identical windows, identical feature schema across every row — asserted by a test.
**AC3** `RESULTS.md` updated with the real numbers. **If the world model loses on some metric, report it and explain why.**

### Sprint 4 Definition of Done
- [ ] `world_model.py` with posterior/prior/decoder/risk head and KL term
- [ ] LSTM, Transformer, and GNN-fused cores all train
- [ ] `imagine()` produces sampled future trajectories with uncertainty
- [ ] Prior beats persistence on one-step prediction — **the proof of learned dynamics**
- [ ] Brier + ECE + reliability diagram in `metrics.py` and `RESULTS.md`
- [ ] Full 7-row comparison table, identical windows
- [ ] `MODEL_PLAN.md` rewritten with the equations above
- [ ] Weights exported to `models/release/`

---

## SPRINT 5 — Entity-Level Forecasting & Positive Lead Time

**Goal:** make the headline promise true — fire the alert **before** the compromise window, with measured lead > 0.
**Why it scores:** closes G09. This is the demo moment that wins or loses the room.
**Exit demo:** "At 14:19 the model raised host 192.168.10.8 to 0.81 with stage *Reconnaissance*. The dataset's ground-truth infiltration begins at 14:33. Lead time: 14 minutes."

### S5-T1 — Diagnose the real cause (do this first, do not guess)

The repo's own explanation is *"the synthetic generator switches stage features abruptly"*. That is true but **almost certainly not the whole story.** The stronger hypothesis:

> **Global window aggregation destroys the signal.** One attacker host slow-scanning inside a window containing 5,000 benign flows contributes < 0.1% of the summed bytes. The model literally cannot see it until the attack is loud enough to move a network-wide aggregate — by which time it is no longer early.

**Task:** write `scripts/diagnose_lead_time.py` that, for a real CIC-IDS2017 attack day, plots for the attacker host and for the network aggregate: `flag_syn_ratio`, `dst_port_nunique`, `bytes_sum`, `iat_mean` over time, with the ground-truth attack onset marked. **Measure how many windows before onset each signal becomes separable.** That number is your achievable lead-time ceiling.

**AC1** The diagnostic produces a figure and a printed table: per feature, "windows before onset at which a 2-sigma deviation first appears", for host-level vs network-level aggregation.
**AC2** A written conclusion committed to `EVALUATION_PLAN.md`.

### S5-T2 — Entity-level states and forecasts

**Files:** `src/trajectory/entity_states.py` (new), `src/trajectory/state_builder.py`

Add `build_entity_states(events, window, stride) -> dict[str, tuple[NetworkState, ...]]` producing a per-host time series. Forecast per host. Aggregate to a network-level risk as `max` (or top-k mean) over hosts.

This is also *far* better product design: an analyst wants "host X is at risk", not "the network is at 0.6".

**AC1** Per-host forecasts produced for every active host in a window.
**AC2** Network risk = top-3 host mean; both reported.
**AC3** Lead time measured **per host against that host's own attack onset** — the correct evaluation unit.
**AC4** On CIC-IDS2017, median host-level lead time is reported. **Target: > 0. If it is still 0 after S5-T1's diagnosis, report it and state the measured ceiling from S5-T1 as the reason.** Honesty beats a fake win.

### S5-T3 — Precursor-aware labelling and a lead-optimised objective

**Files:** `src/trajectory/targets.py`, `src/trajectory/world_model.py`

- **Soft horizon labels:** instead of binary "infiltration within K", use a decaying label `y_t = max_k(gamma^k · 1[attack at t+k])` with `gamma≈0.85`. This rewards the model for firing early rather than only at onset.
- **Lead-weighted loss:** weight positive examples by how far they are ahead of onset, so an early correct fire is worth more than a late one.
- **Stage-aware positives:** treat Reconnaissance windows as *positive for the "progression" head* even though they are not yet infiltration. The repo currently labels recon as non-infiltration, which mathematically forbids early firing — this is the precise root cause named in `RESULTS.md`, and this is the fix.
- Keep the strict binary label as a second reported metric so the comparison with prior results stays valid.

**AC1** `TargetConfig` gains `label_mode: strict | decayed`, `decay_gamma`, `lead_weighting: bool`.
**AC2** Both label modes are evaluated and reported side by side.
**AC3** A test proves a recon-then-infiltrate synthetic scenario yields a positive decayed label at the recon window.
**AC4** Measured median lead time under `decayed` labelling is reported, with the false-early rate alongside it. **Never report lead without false-early rate** — that pairing is what makes the claim credible.

### S5-T4 — Slow-attack scenarios in the synthetic generator

**Files:** `src/trajectory/synthetic.py`

Add three scenario families with genuine dwell time:
- `slow-scan-v1`: 20 windows of low-rate sequential port probing (1 probe / 3 s) before exploitation.
- `beacon-c2-v1`: periodic low-byte callbacks with low IAT variance (the classic beaconing signature) for 15 windows before exfiltration.
- `credential-creep-v1`: slowly rising failed-auth rate across 12 windows before lateral movement.

These give the model something to be early *about*, and they are realistic. Keep `synthetic-recon-lateral-v1` unchanged for backwards comparability; bump the new set to `synthetic-dwell-v1`.

**AC1** Three new deterministic scenario generators with tests.
**AC2** On `synthetic-dwell-v1`, median lead time > 2 windows. **If not, the model or features are wrong — debug before moving on.**

### Sprint 5 Definition of Done
- [ ] Lead-time root cause diagnosed with data, not assumed
- [ ] Per-host states and per-host forecasts
- [ ] Decayed/lead-weighted labelling implemented and compared to strict
- [ ] Slow-attack synthetic families with dwell time
- [ ] Measured lead time > 0 on at least one dataset, reported with false-early rate
- [ ] `RESULTS.md` lead-time section rewritten with real numbers

---

## SPRINT 6 — Explainability: SHAP + Attention ⭐ *non-negotiable*

**Goal:** every prediction carries a real SHAP attribution **and** a real attention map, at feature, host, and timestep granularity.
**Why it scores:** closes G03. The PS says black-box output is "not acceptable" — this is a pass/fail criterion, not a nice-to-have.
**Exit demo:** a single screen: waterfall of the top-8 SHAP contributions, a temporal attention heatmap over the last 8 windows, and a graph with attention-weighted edges.

### S6-T1 — `explain.py`: real SHAP

**Files:** `src/trajectory/explain.py` (new), `pyproject.toml` (add `shap>=0.46`)

```python
class AttributionMethod(str, Enum):
    EXACT_LINEAR = "exact-linear"      # existing coef × value — keep, it is exact for logistic
    KERNEL_SHAP  = "kernel-shap"
    DEEP_SHAP    = "deep-shap"
    GRADIENT_SHAP = "gradient-shap"
    INTEGRATED_GRADIENTS = "integrated-gradients"
    ATTENTION    = "attention"

def explain_forecast(
    artifacts, states, *, method: AttributionMethod, background: np.ndarray, n_samples: int = 200
) -> Explanation: ...
```

- **Logistic baseline:** `shap.LinearExplainer` — exact and instant. Cross-check it equals the existing `coef × standardised value` attribution to 1e-9 and **add that as a test**. This is a beautiful validation story for judges: "our hand-derived attribution and SHAP agree exactly, which is the correctness proof for the linear case."
- **World model / GRU:** `shap.GradientExplainer` or `DeepExplainer` over the sequence input. Falls back to Integrated Gradients (pure torch, no extra dep) if SHAP is unavailable — implement IG yourself in ~30 lines so there is no hard dependency.
- **Background set:** sample 100 *training-split* benign windows. Never use test data as background — that is leakage, and a knowledgeable judge will ask.
- **Caching:** KernelSHAP is slow. Cache per `(state_key, model_version, method)` in `reports/generated/explanations/`. The dashboard must stay responsive.

**Output contract:**
```python
class Explanation(BaseModel):
    version: str = "explanation-v1"
    method: AttributionMethod
    base_value: float                     # E[f(x)] over background
    feature_attributions: list[FeatureAttribution]   # name, value, shap_value, rank
    timestep_attributions: list[float] | None        # per window in the sequence
    entity_attributions: list[EntityAttribution] | None  # per host, from GAT attention
    edge_attributions: list[EdgeAttribution] | None
    background_size: int
    n_samples: int
    computation_seconds: float
    warnings: list[str]
```

**AC1** `sum(shap_values) + base_value ≈ model_output` within 1e-3 — the **SHAP additivity property**. Test it. This is the single most important explainability test.
**AC2** LinearExplainer output equals the existing exact attribution to 1e-9.
**AC3** Attributions are computed against a train-only background; a test asserts no test-split window enters the background.
**AC4** Cached explanation retrieval < 50 ms.
**AC5** `predict.py` `Forecast.driving_features` gains an `attribution_method` field so the UI never mislabels which method produced a number.

### S6-T2 — Attention: temporal and graph

**Files:** `src/trajectory/world_model.py`, `src/trajectory/gnn.py`, `src/trajectory/explain.py`

- **Temporal attention:** the Transformer core's attention weights, averaged over heads, give "which of the last 8 windows drove this forecast". Export as `[n_layers, n_heads, seq_len, seq_len]`, and provide a reduced `[seq_len]` vector = attention paid by the final position to each earlier window.
- **Graph attention:** the GAT `alpha` per edge = "which host-to-host connections the model is watching".
- **Head-importance:** report which attention head correlates most with the positive class — a nice depth signal.

**AC1** Attention weights are exported, sum to 1.0 along the attended axis, and are stored in `Explanation`.
**AC2** A test builds a scenario where window 6 of 8 contains the attack burst and asserts the model assigns it the highest temporal attention. *(If it does not, that is a real finding — investigate, do not fudge the test.)*
**AC3** The graph attention identifies the attacker host as the top-attention node in a synthetic lateral-movement scenario.

### S6-T3 — Explanation quality metrics (the differentiator)

**Files:** `src/trajectory/explain.py`, `EXPLAINABILITY_PLAN.md`

Almost no hackathon team measures whether their explanations are *correct*. Implement:

- **Deletion curve / AOPC:** remove the top-k attributed features (replace with background mean) and measure how fast the prediction drops. Faster drop = more faithful explanation. Report AUC.
- **Insertion curve:** the inverse.
- **Sanity check (Adebayo et al.):** randomise the model weights; attributions must change substantially. If they do not, the explanation is not reading the model. **Implement this and report the result — it demonstrates genuine ML literacy.**
- **Stability:** perturb the input by 1% noise; attributions should not reorder wildly. Report rank correlation.

**AC1** Deletion/insertion AUC computed for each attribution method and reported in `RESULTS.md`.
**AC2** The model-randomisation sanity check passes (attribution rank correlation between real and randomised model < 0.3).
**AC3** `EXPLAINABILITY_PLAN.md` rewritten with the methods, the metrics, and the measured results.

### S6-T4 — Explainability in the UI and reports

**Files:** `dashboard/tabs/forecast.py`, `dashboard/tabs/analyze.py`, `src/trajectory/report.py`

- SHAP **waterfall** (top 8 positive + top 4 negative contributions) and a **force-plot-style** bar.
- **Temporal attention heatmap** over the input sequence.
- **Graph with attention-weighted edge thickness**, attacker host highlighted.
- Plain-English generated sentence:
  > *"Infiltration probability 0.87 in 2 windows. Driven by `dst_port_nunique` (47 distinct ports, +0.31), `flag_syn_ratio` (0.94, +0.22) and `iat_var` (+0.11) on host 192.168.10.8. The model is attending most to windows t-1 and t-2."*
  Generate this template-mechanically from the top SHAP features — **do not use an LLM**, it breaks the offline requirement.
- Every number in the report labelled with its `attribution_method`.

**AC1** The analyst report (`report.py`) contains a SHAP section with method, base value, and top contributions.
**AC2** The plain-English sentence is generated deterministically and tested.
**AC3** The UI never shows an attribution without naming the method that produced it.

### Sprint 6 Definition of Done
- [ ] Real SHAP (Linear + Deep/Gradient) with additivity test passing
- [ ] Integrated Gradients fallback with no hard dependency
- [ ] Temporal attention + graph attention exported and rendered
- [ ] Deletion/insertion AUC + model-randomisation sanity check reported
- [ ] Every attribution labelled with its method
- [ ] `EXPLAINABILITY_PLAN.md` rewritten with measured results
- [ ] The `predict.py:9` disclaimer ("we do not call it SHAP because it is not SHAP") can finally be replaced with "both exact-linear and SHAP attributions are available and agree to 1e-9"

---

## SPRINT 7 — MITRE ATT&CK Stage Engine

**Goal:** replace five hardcoded byte thresholds with a learned, technique-level, dataset-grounded stage engine that reports a real macro-F1.
**Why it scores:** closes G11. `RESULTS.md` currently says `Stage macro-F1: n/a` — that blank is a visible hole.
**Exit demo:** "predicted stage: Lateral Movement (TA0008), technique T1021.002 SMB/Windows Admin Shares, confidence 0.78; evidence: 3 new internal edges on port 445 with SYN ratio 0.9."

### S7-T1 — Ground-truth stage labels from datasets

**Files:** `src/trajectory/mitre/` (new package), `src/trajectory/cic_ids2017.py`

```
src/trajectory/mitre/
  __init__.py
  tactics.py         # TA00xx enum with names and descriptions
  techniques.py      # technique registry: id, name, tactic, data sources, detection features
  mapping.py         # dataset label -> (tactic, technique[], confidence, rationale)
  navigator.py       # export to ATT&CK Navigator layer JSON
data/mitre/enterprise-attack-<version>.json   # pinned offline snapshot
```

**Pin an offline ATT&CK snapshot.** Download the Enterprise ATT&CK STIX bundle once, commit a reduced JSON (tactics + the ~40 network-observable techniques), and record the ATT&CK version. This preserves the offline requirement while being genuinely grounded — not a hand-typed table.

Extend the CIC-IDS2017 label mapping from tactic-only to technique-level:

| CICFlowMeter label | Tactic | Technique |
|---|---|---|
| `PortScan` | TA0007 Discovery | T1046 Network Service Discovery |
| `FTP-Patator` / `SSH-Patator` | TA0006 Credential Access | T1110.001 Password Guessing |
| `DoS Hulk/GoldenEye/slowloris/Slowhttptest` | TA0040 Impact | T1499.002 Service Exhaustion Flood |
| `DDoS` | TA0040 Impact | T1498.001 Direct Network Flood |
| `Bot` | TA0011 C2 | T1071.001 Web Protocols |
| `Infiltration` | TA0001 Initial Access / TA0008 | T1190 / T1021 |
| `Web Attack – Brute Force` | TA0006 | T1110.001 |
| `Web Attack – XSS` | TA0001 | T1189 Drive-by Compromise |
| `Web Attack – Sql Injection` | TA0001 | T1190 Exploit Public-Facing Application |
| `Heartbleed` | TA0006 | T1040 / CVE-2014-0160 |

Keep the existing **strict unmapped-label abort** — extend the table deliberately, never drop rows. That rule is one of the repo's best decisions.

**AC1** Every published CIC-IDS2017 label maps to at least one technique ID with a cited rationale.
**AC2** `mitre.navigator.export_layer(findings) -> dict` produces a valid ATT&CK Navigator layer JSON that loads in the official Navigator. **Demo this — it is visually spectacular and takes 20 seconds.**
**AC3** ATT&CK version recorded in every export and in `MITRE_MAPPING_PLAN.md`.

### S7-T2 — Learned multi-class stage head

**Files:** `src/trajectory/world_model.py`, `src/trajectory/stage_mapping.py`

- Add a softmax stage head to the world model, trained on the dataset-derived stage labels from S7-T1, with class weighting for the heavy imbalance.
- **Keep the rule engine.** Combine: `final_stage = argmax(w · learned_probs + (1-w) · rule_evidence_scores)`, `w` tuned on validation. Report all three (rules only, learned only, hybrid) — an honest ablation, and the hybrid usually wins.
- Report **stage macro-F1, per-class F1, and a confusion matrix**. Fill the `n/a` in `RESULTS.md`.

**AC1** Stage macro-F1 reported on the test split for rules / learned / hybrid.
**AC2** A confusion matrix is rendered in the dashboard and the report.
**AC3** `Unknown` remains a valid, first-class output when max probability < a documented threshold — do not force a label. Test it.

### S7-T3 — Relative, transferable rule thresholds

**Files:** `src/trajectory/stage_mapping.py`

Replace absolute constants (`bytes > 10_000`, `retransmission > 2`) with **quantile-relative thresholds fitted on the training split** and stored in the artifact bundle:

```python
class StageThresholds(BaseModel):
    version: str = "stage-thresholds-v1"
    fitted_on: str                 # dataset id + split
    quantiles: dict[str, float]    # feature -> the training-split quantile value used
    quantile_level: float = 0.95
```

A rule then reads "bytes above the training-split p95" rather than "bytes above 10,000". This transfers across datasets; the current constants do not.

**AC1** No absolute magic number remains in `STAGE_RULES`; a test greps the module for numeric literals > 100 and fails.
**AC2** Thresholds are fitted train-only, persisted, and loaded at inference.
**AC3** The same rule set fires sensibly on both synthetic and CIC-IDS2017 without code changes — demonstrated by a cross-dataset test.

### S7-T4 — Kill-chain progression model

**Files:** `src/trajectory/stage_mapping.py`, `src/trajectory/killchain.py` (new)

Model stage progression as a transition matrix `P(stage_{t+1} | stage_t)` estimated from labelled data, and use it to constrain rollout: if the current stage is Reconnaissance, Exfiltration in one step is improbable. Report the learned matrix as a heatmap — it is a compelling visual and directly demonstrates "anticipating attacker progression".

**AC1** Transition matrix estimated from training labels, rendered as a heatmap.
**AC2** Rollout stage predictions are re-weighted by the matrix; the ablation is measured.
**AC3** The matrix does **not** assume a strictly linear kill chain — dwelling and skipping are permitted. The existing docstring rule ("never imply a guaranteed linear kill chain") is preserved.

### Sprint 7 Definition of Done
- [ ] Offline ATT&CK snapshot pinned, version recorded
- [ ] Technique-level (not just tactic-level) mapping for every dataset label
- [ ] Navigator layer export working
- [ ] Learned stage head + hybrid with rules; macro-F1 and confusion matrix reported
- [ ] All absolute thresholds replaced by fitted quantiles
- [ ] Kill-chain transition matrix estimated and visualised
- [ ] `RESULTS.md` stage macro-F1 `n/a` replaced with a real number

---

## SPRINT 8 — Datasets & Generalisation

**Goal:** prove the model learned *behaviour*, not *signatures* — across attack families and across datasets.
**Why it scores:** closes G10 and G12. The PS explicitly demands generalisation to unseen attacks.
**Exit demo:** "we trained with the port-scan family removed entirely and it still detected port scans at F1 0.7x. It has never seen one."

### S8-T1 — CTU-13 adapter (named in the PS)

**Files:** `src/trajectory/datasets/ctu13.py` (new), tests

CTU-13 ships Argus `.binetflow` files: `StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label`.

Key handling:
- `Dir` (`->`, `<->`, `<-`, `?>`) encodes directionality → derive `bidirectional_ratio` from `SrcBytes / TotBytes`.
- `State` carries TCP flag summaries (`CON`, `FSPA_FSPA`, `S_`, `SR_`) → **parse into the S2 flag features.** Document the mapping.
- Labels are substring-based: `flow=From-Botnet-*` = malicious, `flow=Background-*` = unknown (**not benign** — this is the classic CTU-13 mistake; background is unlabelled). Treat background as unlabelled and **exclude it from supervised loss**, or label it benign only with an explicit documented decision. Say which you chose and why.
- 13 scenarios with different botnet families → perfect for leave-one-family-out.

**AC1** `read_ctu13(path) -> FlowIngestionResult` with the same contract as `read_flow_csv`.
**AC2** Flag features derived from the `State` column, tested against a hand-checked fixture.
**AC3** Background-flow policy documented in the module docstring and `DATASET_PLAN.md`.
**AC4** Strict unmapped-label abort, matching the CIC-IDS2017 adapter's discipline.

### S8-T2 — UNSW-NB15 and LANL adapters

**Files:** `src/trajectory/datasets/unsw_nb15.py`, `src/trajectory/datasets/lanl_auth.py`

- **UNSW-NB15:** 49 features, 9 attack categories (`Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms`). Rich `sttl`/`dttl`/`swin`/`dwin`/`sload`/`dload` columns map **directly** onto the packet-level features the PS demands — use this dataset to prove the packet path works on real data.
- **LANL auth:** the PS names "authentication logs" and the LANL dataset. Map to `UnifiedEvent` with `failed_auth`, `auth_attempt`, user/host entities. This closes "authentication logs" as an input source and is the *only* dataset here with true multi-day attacker dwell time — **use it for the lead-time claim.**
- Also add a thin `cic_ids2018.py` alias — CIC-IDS2018 shares the CICFlowMeter schema, so the PS's literally-named dataset is one file away.

**AC1** Three adapters with tests on synthetic schema fixtures (commit no dataset content).
**AC2** Each records its licence and citation in the module docstring and `PROVENANCE.md`.
**AC3** `DATASET_PLAN.md` gains a table: dataset → size → attack families → dwell time → what we use it to prove.

### S8-T3 — Leave-One-Attack-Out (LOAO) protocol

**Files:** `src/trajectory/evaluation.py`, `scripts/run_generalisation.py` (new)

For each attack family `f`: train with **all windows containing `f` removed from train and validation**, test only on `f`. Report per-family F1 and the degradation versus the in-distribution model.

**This is the direct, measurable answer to "Generalise to unseen attack patterns — not merely memorize signatures."** No other single experiment answers the PS bullet as cleanly.

**AC1** `scripts/run_generalisation.py --protocol loao --dataset cic-ids2017` produces a per-family table.
**AC2** A leakage test asserts zero windows of the held-out family appear in train or validation.
**AC3** Results in `RESULTS.md` with honest interpretation — **including the families where it fails.** A model that generalises to 6/9 families and says so is far more credible than one claiming 9/9.

### S8-T4 — Cross-dataset transfer

**Files:** `scripts/run_transfer.py` (new)

Train on CIC-IDS2017 → test on CTU-13 and UNSW-NB15 without retraining. Report zero-shot metrics and metrics after fitting only the feature-normalisation statistics (a fair domain-adaptation step). Expect a large drop — that is the honest, expected result, and reporting it demonstrates scientific maturity.

**AC1** A transfer matrix: rows = train dataset, cols = test dataset, cells = F1.
**AC2** The drop is quantified and explained (feature-distribution shift, measured with the existing PSI code in `drift.py` — a nice reuse that shows the enterprise modules are not decoration).

### S8-T5 — Unified benchmark harness

**Files:** `scripts/run_benchmark.py`

Extend the existing one-command benchmark to sweep `{dataset} × {model} × {protocol}`, write one `BENCHMARK.md`, and cache intermediate artifacts so a re-run is fast. Emit a machine-readable `benchmark.json` for `verify_results.py`.

**AC1** One command reproduces every number in `RESULTS.md`.
**AC2** `make reproduce` verifies the committed results against a fresh run within tolerance.

### Sprint 8 Definition of Done
- [ ] CTU-13, UNSW-NB15, LANL auth, CIC-IDS2018 adapters, all tested
- [ ] LOAO protocol with per-family results, leakage-tested
- [ ] Cross-dataset transfer matrix with PSI-quantified shift
- [ ] Single-command reproducible benchmark
- [ ] `DATASET_PLAN.md` and `RESULTS.md` fully updated

---

## SPRINT 9 — Demo Interface & Operator UX

**Goal:** the thing the judge actually touches. Drop in a PCAP → get a forecast timeline, flagged flows, stage annotations, and SHAP — offline, in under 30 seconds.
**Why it scores:** closes G07. This is the deliverable the PS describes most concretely.
**Exit demo:** the demo itself.

### S9-T1 — The "Analyze File" tab ⭐ *the single highest-value UI task*

**Files:** `src/trajectory/dashboard/tabs/analyze.py` (new)

```
┌─ Analyze a capture ────────────────────────────────────────────┐
│ [ Drop a .pcap / .pcapng / .csv here ]     ( max 200 MB )       │
│ Model: [ world-model-rssm-v1 ▾ ]  Horizon: [5]  Threshold: 0.40 │
│                                                                 │
│ ── Coverage ────────────────────────────────────────────────    │
│ 24,881 packets → 3,402 flows → 57 windows (60 s / 30 s)         │
│ flow ✅   packet ✅   auth ❌  (no auth telemetry in this file)   │
│                                                                 │
│ ── Infiltration probability timeline ───────────────────────    │
│ [ line chart, shaded uncertainty band, threshold line,          │
│   OBSERVED (solid) | FORECAST (dashed) split clearly marked,    │
│   stage bands coloured beneath the axis ]                       │
│                                                                 │
│ ── Predicted stage ─────────────────────────────────────────    │
│ Reconnaissance → TA0043 / T1046   confidence 0.81               │
│ Evidence: dst_port_nunique=47, flag_syn_ratio=0.94, ...         │
│                                                                 │
│ ── Why (SHAP) ──────────────────────────────────────────────    │
│ [ waterfall ]        [ temporal attention heatmap ]             │
│                                                                 │
│ ── Flagged flows ───────────────────────────────────────────    │
│ [ sortable table: time, src, dst, port, flags, score, stage ]   │
│ [ Download: report.md | forecast.json | navigator_layer.json ]  │
└─────────────────────────────────────────────────────────────────┘
```

Implementation requirements:
- Accept `.pcap`, `.pcapng`, `.csv` (canonical flow schema **and** CICFlowMeter schema — auto-detect by header).
- Write the upload to a `tempfile`, process, **delete it**. Never persist a user's capture.
- Guard against huge files: cap at a configurable size, stream-parse PCAPs with `PcapReader` (already streaming — good), show a progress bar, and cap the window count with an explicit warning rather than hanging.
- If the file has no packet layer, say so in Coverage rather than silently producing `packet: false`.
- **Everything offline.** `tests/test_offline.py` must still pass.

**AC1** A judge can upload a PCAP and get a full result with zero configuration.
**AC2** Auto-detection of CSV schema (canonical vs CICFlowMeter) with a clear error on an unknown schema listing the expected columns.
**AC3** A 25 MB PCAP processes in < 30 s on a laptop CPU.
**AC4** The uploaded file is deleted after processing — test asserts the temp path does not exist afterwards.
**AC5** Streamlit `AppTest` covers the tab; a malformed file produces a friendly error, never a stack trace.

### S9-T2 — CLI parity

**Files:** `scripts/sentinel_analyze.py` (new), console entry point in `pyproject.toml`

```bash
sentinel analyze capture.pcap --horizon 5 --format json --out result.json
sentinel analyze flows.csv --explain shap --report report.md
sentinel serve --port 8501
```
The PS explicitly allows CLI — having both is strictly better, and a CLI is what a real CII operator would actually deploy. It is also your fallback if Streamlit misbehaves on demo day.

**AC1** `sentinel analyze` produces the same `Forecast` JSON as the dashboard for the same input (byte-comparable test).
**AC2** Exit codes: 0 = below threshold, 1 = alert raised, 2 = error. Makes it scriptable into a SOC pipeline.

### S9-T3 — Ship a demo PCAP

**Files:** `data/fixtures/demo_capture.pcap` (new, small), `scripts/make_demo_pcap.py` (new)

Generate a small (< 2 MB) synthetic PCAP with scapy containing benign traffic, then a sequential port scan, then a lateral-movement burst. Commit it. **A judge who does not have a dataset must still be able to press one button and see the system work.** Add `.gitignore` negation for this one file.

**AC1** `make demo` loads the shipped PCAP and produces a non-trivial alert.
**AC2** The generator is deterministic and its script is committed.

### S9-T4 — Performance and resilience pass

**Files:** dashboard modules, `live.py`

- Cache expensive computations with `@st.cache_data` keyed on a content hash of the input.
- Every long operation gets a spinner and a progress bar.
- Every `except` shows an actionable message, not a traceback.
- Stale-result invalidation (already present for Replay) extended to the Analyze tab.
- A "Reset session" control everywhere.

**AC1** No operation blocks the UI for > 3 s without a progress indicator.
**AC2** Fuzz test: random bytes, empty file, truncated PCAP, CSV with wrong columns, CSV with 1 row — all produce friendly errors.

### Sprint 9 Definition of Done
- [ ] PCAP **and** CSV upload → full analysis, offline, < 30 s for 25 MB
- [ ] Flagged-flow table, stage annotations, uncertainty band, SHAP, attention all rendered
- [ ] Downloadable report.md, forecast.json, Navigator layer
- [ ] CLI with parity and meaningful exit codes
- [ ] Demo PCAP committed
- [ ] Fuzz-tested against malformed input

---

## SPRINT 10 — Submission Hardening

**Goal:** every deliverable meets its hard limit, every claim is backed, and the demo cannot fail.
**Why it scores:** closes G15. Format violations lose points that the engineering already earned.
**Exit demo:** a rehearsed 2-minute run, twice, on two machines, with a video backup.

### S10-T1 — Architecture document (max 2 pages)

**Files:** `ARCHITECTURE_SUBMISSION.md` → `deliverables/ARCHITECTURE.pdf`

Current state is a 914-byte draft with an ASCII arrow diagram. Rewrite to use the full two pages:

**Page 1:** (a) problem in two sentences; (b) **a real architecture diagram** — ingestion → state/graph → world model (encoder/prior/posterior/decoder) → rollout → risk + stage heads → explainability → UI/API; (c) the world-model equations (`q(z_t|h_t,e_t)`, `p(z_t|h_t)`, the KL term) — judges want to see the actual model, not a box labelled "AI".
**Page 2:** (a) feature table mapping PS-named features → implementation; (b) results table including the persistence and logistic baselines; (c) explainability sample output; (d) limitations, honestly; (e) deployment and licence.

Draw the diagram in `scripts/build_arch_diagram.py` using `matplotlib` or Graphviz so it regenerates — never a screenshot from a slide.

**AC1** Exactly 2 pages as rendered PDF. **AC2** Diagram is generated by a committed script. **AC3** Every number cites the script that produced it.

### S10-T2 — Technical presentation (max 5 slides)

**Files:** `scripts/build_deck.py`, `deliverables/`

**Current deck is 7 slides — over the limit.** Cut to exactly 5:

| # | Slide | Content |
|---|---|---|
| 1 | **The gap** | Static IDS classifies one flow. An infiltration is a process. Show the kill-chain timeline with the one window a classifier sees vs the trajectory we model. |
| 2 | **The world model** | The RSSM diagram + the one-line claim: *"the prior predicts the next state without seeing it — that is why it can forecast."* Include the one-step-MSE-vs-persistence number. |
| 3 | **Results** | The comparison table (logistic / GRU / ridge rollout / world model), lead time with false-early rate, LOAO generalisation, Brier + ECE. |
| 4 | **Explainability** | SHAP waterfall + attention heatmap + the plain-English sentence + the model-randomisation sanity-check result. |
| 5 | **Deployment & honesty** | Offline architecture, API/dashboard/CLI, CII fit, and an explicit **Limitations** box. |

**AC1** `python scripts/build_deck.py` outputs exactly 5 slides in `.pptx` and `.pdf`; a test asserts the slide count.
**AC2** No slide has more than ~40 words of body text.
**AC3** Every result number on slide 3 traces to `benchmark.json`.

### S10-T3 — Demo video (max 2 minutes)

**Files:** `deliverables/demo.mp4`, `DEMO_SCRIPT.md`

**Shot list (target 1:50, leaving margin):**

| Time | Shot | Narration beat |
|---|---|---|
| 0:00–0:12 | Title + problem | "An intrusion is a process. Classifiers see one frame." |
| 0:12–0:30 | Drop `demo_capture.pcap` into Analyze | "Everything runs locally. No cloud." |
| 0:30–0:50 | Timeline rises; alert crosses threshold **before** the labelled onset | "The model flags this 4 windows — 3 minutes — before compromise." |
| 0:50–1:10 | Stage panel: TA0043 → T1046 with evidence | "Mapped to ATT&CK, with the evidence that drove it." |
| 1:10–1:30 | SHAP waterfall + attention heatmap | "47 distinct ports, SYN ratio 0.94. Not a black box." |
| 1:30–1:45 | Results table + LOAO row | "It detects attack families it was never trained on." |
| 1:45–1:55 | Limitations slide | "And here is what it does not do." |

Record at 1920×1080, 30 fps. Use OBS. **Record twice.** Add subtitles — judges often watch muted. Ending on limitations is unusual and memorable, and it makes every preceding claim more believable.

**AC1** ≤ 2:00, 1080p, subtitled, audio normalised.
**AC2** The run shown is a real run, not a mock-up.
**AC3** A backup GIF/frame sequence is retained (the repo already has `deliverables/backup_demo/` — regenerate it).

### S10-T4 — README and cold-clone verification

**Files:** `README.md`

Restructure so the **first** runnable block is the zero-training path:
```bash
git clone <repo> && cd sentinel
make setup
make demo          # opens the dashboard with pretrained weights + demo PCAP
```
Then: reproduce results, train from scratch, run the API, run the real-data benchmark.

**Verify on a genuinely clean machine** — a fresh container or a teammate's laptop that has never seen the repo. Time it. If it is over 10 minutes, fix it.

**AC1** A person who has never seen the repo reaches a working dashboard in < 10 minutes, timed and recorded.
**AC2** README states the licence, the ATT&CK version, dataset citations, and the limitations, in the first screen.

### S10-T5 — The claim audit

**Files:** `CLAIM_AUDIT.md` (new)

Go through **every** superlative and every number in README, `RESULTS.md`, the deck, the architecture doc, and the video script. For each: claim → evidence (script + output file + line) → verdict (backed / soften / delete).

This repo already has this instinct — formalise it into a signed-off table. Then have one teammate who did **not** write the code try to break every claim.

**AC1** `CLAIM_AUDIT.md` covers 100% of numeric and capability claims in submission material.
**AC2** Zero claims marked "unbacked" remain in any submitted artifact.

### S10-T6 — Demo-day failure plan

**Files:** `DEMO_PLAN.md`

- Rehearse 5 times; record the timings (the repo already does this — `alert ~31 s; lateral movement ~61 s`).
- Prepare for: no internet (already fine — offline-first is a *selling point*, say so out loud), no GPU (CPU-only already), a laptop that will not run Docker (have `make demo` work without Docker), the projector resizing the window (test at 1280×720), and the dashboard crashing (have the CLI and the video ready).
- A one-page cheat sheet of the numbers you will be asked for.

**AC1** Five rehearsals logged with timings. **AC2** Three fallback paths tested: dashboard → CLI → video.

### Sprint 10 Definition of Done
- [ ] Architecture PDF: exactly 2 pages, generated diagram
- [ ] Deck: exactly 5 slides, count-tested
- [ ] Video: ≤ 2:00, real run, subtitled
- [ ] Cold-clone verified < 10 min by someone outside the team
- [ ] `CLAIM_AUDIT.md` complete, zero unbacked claims
- [ ] Three fallback demo paths tested
- [ ] `LICENSE`, `PROVENANCE.md`, `THIRD_PARTY.md`, dataset citations all present

---

# PART 5 — ENHANCEMENTS BEYOND THE SPEC (the winning margin)

Compliance gets you shortlisted. These get you remembered. **Only attempt these after the sprint they attach to is green** — an unfinished differentiator is worth less than a finished requirement.

| # | Enhancement | Attach to | Effort | Why judges care |
|---|---|:--:|:--:|---|
| **E1** | **Counterfactual explanation.** "If `dst_port_nunique` had stayed below 12, infiltration probability would be 0.14 instead of 0.87." Compute by perturbing the input along the top SHAP feature until the prediction crosses the threshold. | S6 | M | Turns explanation into *action*. No other team will have this. |
| **E2** | **Attack-path prediction on the graph.** Use the GNN to rank which host the attacker reaches next. Render as a directed path over the topology. | S3+S5 | M | The most visually compelling possible output for "attacker progression". |
| **E3** | **Time-to-compromise estimate with a confidence interval.** From the sampled rollout: "median 4 windows (≈2 min); 90% CI 2–9 windows." | S4 | S | Reframes the output from a score into an operational decision. |
| **E4** | **Adversarial robustness evaluation.** Test against evasion: packet padding, timing jitter, scan rate reduction, source-IP rotation. Report degradation. `tests/test_adversarial.py` already exists — extend it into a measured evaluation. | S8 | M | NTRO is a technical intelligence organisation. They will ask. Having an answer is a large edge. |
| **E5** | **Encrypted-traffic handling.** State explicitly which features survive TLS (IAT, packet sizes, flag ratios, fan-out — all of them do) and which do not (payload content — which you never used). `KNOWN_LIMITATIONS.md` already flags this; turn it into a *strength*. | S2 | S | Pre-empts the most common objection to network-based detection. |
| **E6** | **ATT&CK Navigator layer export.** Already scheduled as S7-T1-AC2. Load it live in the official Navigator during the demo. | S7 | S | 20 seconds of demo, enormous credibility. |
| **E7** | **Analyst feedback → active learning queue.** `feedback.py` exists with a deliberate no-auto-retrain policy. Add a *reviewed* retraining queue with human approval. Keep the no-auto-retrain guarantee. | S9 | M | Shows you understand why auto-retrain from analyst clicks is a poisoning vector. |
| **E8** | **Streaming/online mode benchmark.** Report throughput (flows/sec) and p50/p99 latency per window. `live.py` and `/metrics` already exist — just measure and publish. | S9 | S | Proves enterprise/CII viability, which the PS asks for explicitly. |
| **E9** | **Model card** (`MODEL_CARD.md`). Intended use, training data, evaluation, failure modes, out-of-scope use, ethical considerations. | S10 | S | Standard practice in serious ML; almost unheard of in hackathons. |
| **E10** | **Deterministic full reproduction.** `make reproduce` regenerates every number in `RESULTS.md` and fails on drift. Scheduled as S1-T6/S8-T5. | S8 | S | "Run this and check us" is the most powerful sentence you can say to a judge. |
| **E11** | **Federated/multi-site framing for CII.** `federated.py` has a FedAvg simulation. Frame it: "power grid and telecom operators share model weights, never traffic." Keep the "this is simulated" caveat. | S10 | S | Directly addresses "Critical Information Infrastructure" in the PS. |
| **E12** | **Tamper-evident alert ledger.** `ledger.py` already implements a hash chain. Frame it for forensic chain-of-custody in a regulated environment. | S10 | S | An unusual, defensible feature that fits NTRO's context. |

**Recommended picks if you can only do four: E1, E3, E4, E6.** They are cheap, demo-able, and each answers a question a judge is likely to actually ask.

---

# PART 6 — DELIVERABLES CHECKLIST

Tick these in order. Anything unticked at T-48h gets triaged.

### Hard submission requirements
- [ ] **Source code link** (GitHub) — public, with `LICENSE` (Apache-2.0), clean history, no secrets (`git log -p | grep -iE "api[_-]?key|password|token"` → clean)
- [ ] **README with setup instructions** — cold-clone verified in < 10 min by an outsider
- [ ] **Architecture document — max 2 pages** — generated diagram, world-model equations, results, limitations
- [ ] **Demo video — max 2 minutes** — 1080p, subtitled, real run, ends on limitations
- [ ] **Technical presentation — max 5 slides** — count-tested in CI

### PS-mandated technical artifacts
- [ ] Feature extraction pipeline: CIC-IDS-2017/2018 **or** CTU-13 CSV **and/or** raw PCAP (Scapy) → timestamped normalised matrix
- [ ] Trained world model **demonstrably learning transition dynamics** (prior beats persistence on one-step MSE — this is your proof)
- [ ] **Training scripts + model weights + reproducible training configuration, all committed**
- [ ] Infiltration prediction engine: K-step forward simulation → probability + MITRE stage + top features
- [ ] Explainability output per prediction: **SHAP values and/or attention weights**
- [ ] Demo interface accepting **PCAP or CSV**, running **fully offline**, showing timeline + flagged flows + stage annotations
- [ ] Benchmarks (F1, precision, recall, FPR) **vs logistic regression on identical features**

### Quality bar
- [ ] `make gate` green on 3 Python versions, with and without optional extras
- [ ] Test coverage ≥ 70% on `src/trajectory`
- [ ] `make reproduce` regenerates every published number
- [ ] `CLAIM_AUDIT.md` complete, zero unbacked claims
- [ ] `MODEL_CARD.md`, `KNOWN_LIMITATIONS.md`, `PROVENANCE.md`, `THIRD_PARTY.md` present
- [ ] Every dataset used is cited with its licence

---

# PART 7 — DEMO SCRIPT & JUDGE Q&A

## 7.1 The 5-minute live demo (if you get more than the video)

| Min | Action | Say |
|---|---|---|
| 0:00 | Open Analyze tab, drop `demo_capture.pcap` | "Everything you're about to see runs on this laptop with no network." |
| 0:45 | Timeline appears, alert fires before onset | "The model crosses threshold here. Ground-truth compromise is here. That gap is the lead time — X windows." |
| 1:30 | Stage panel | "It maps to ATT&CK Reconnaissance, technique T1046, and it shows the evidence — 47 distinct destination ports, SYN ratio 0.94." |
| 2:15 | SHAP + attention | "This is the attribution. And this heatmap is the model's temporal attention — it's looking at windows t-1 and t-2." |
| 3:00 | Results tab | "Against a logistic-regression baseline on identical features and identical splits: F1 X vs Y. And here's the generalisation test — we removed this attack family from training entirely." |
| 4:00 | Limitations | "Here is what it does not do." |
| 4:30 | Q&A | — |

## 7.2 The questions you will be asked — and the answers

**Q: "Why is this a world model and not just a classifier?"**
> Because the prior distribution `p(z_t | h_t)` is trained to predict the next latent state *without seeing the next observation*, and the KL term forces it to match the posterior that does see it. We measure that directly: the prior's one-step prediction error is X versus Y for a persistence baseline. A classifier has no such quantity. And we can roll it forward with no observations at all — that is the `imagine()` path behind the forecast.

**Q: "Your lead time was 0 windows. Is it still?"**
> It was, and we published that. We diagnosed it: network-wide aggregation drowned a single slow-scanning host, and reconnaissance was labelled non-infiltration, which mathematically forbade early firing. We moved to per-host states and decayed horizon labels. It is now X windows median, with a false-early rate of Y. Here is the diagnostic that found it.

**Q: "How do I know it isn't memorising signatures?"**
> Leave-one-attack-out. We retrain with an entire attack family removed from train and validation, then test only on that family. Here is the per-family table — it holds up on these, and it degrades on these, and here is why.

**Q: "Is your SHAP real SHAP?"**
> Yes, and we validate it two ways. For the logistic model, SHAP's LinearExplainer agrees with our closed-form attribution to 1e-9. For the neural model we use GradientSHAP and assert the additivity property — attributions plus base value equal the model output. We also run the model-randomisation sanity check: randomise the weights and the attributions must change. They do.

**Q: "What happens on encrypted traffic?"**
> Nothing changes. We never used payload content. Every feature we rely on — inter-arrival timing, packet size distributions, TCP flag ratios, port fan-out, connection graph structure — survives TLS intact.

**Q: "False positive rate in a real SOC?"**
> Our measured FPR is X on this test split, and we report it at both the calibrated and a pinned 0.50 threshold so you can see the trade-off. We also do not auto-block anything — this is decision support. And we publish the calibration curve, so a 0.7 from us means roughly 70%.

**Q: "Could an attacker evade it?"**
> Yes, and we measured how hard. We tested timing jitter, scan-rate reduction, packet padding and source rotation. Rate reduction is the most effective evasion — it costs the attacker X× more time, which is itself a defensive win. We publish the degradation curve.

**Q: "Why should NTRO care versus a commercial IDS?"**
> Three things: it runs fully offline with no cloud dependency, which a commercial SaaS IDS cannot offer for CII; every alert carries auditable evidence and a tamper-evident hash chain; and it is Apache-2.0, so it can be deployed, audited and modified without a vendor relationship.

**Q: "What doesn't it do?"** *(Have this answer ready and be first to say it.)*
> It does not block traffic. It does not replace a SOC. It has not been validated on operational CII traffic — only public datasets. Encrypted payload inspection is out of scope by design. Federated learning is simulated, not deployed. Those are in `KNOWN_LIMITATIONS.md` and on our final slide.

---

# PART 8 — APPENDICES

## 8.1 Command reference

```bash
# Setup
uv sync --all-extras
make setup

# Quality gate — run before every commit
make gate

# Zero-training demo
make demo

# Training
uv run python scripts/run_baseline.py     --config configs/default.yaml
uv run python scripts/run_temporal.py     --config configs/default.yaml
uv run python scripts/run_world_model.py  --config configs/default.yaml   # S4
uv run python scripts/run_calibration.py
uv run python scripts/run_benchmark.py                                     # everything

# Evaluation
uv run python scripts/run_replay.py --threshold 0.40
uv run python scripts/run_rollout.py
uv run python scripts/run_generalisation.py --protocol loao                # S8
uv run python scripts/run_transfer.py                                      # S8
uv run python scripts/diagnose_lead_time.py                                # S5
uv run python scripts/run_real_benchmark.py --data-dir data/raw/cic-ids2017/TrafficLabelling

# Interfaces
uv run streamlit run src/trajectory/dashboard/app.py
uv run uvicorn trajectory.api:create_app --factory --port 8000
sentinel analyze capture.pcap --explain shap --report report.md            # S9

# Artifacts
uv run python scripts/export_release_artifacts.py --out models/release/v1
uv run python scripts/verify_release_artifacts.py models/release/v1
make reproduce
```

## 8.2 Version-string registry (bump these when behaviour changes)

| Version string | Module | Bumps in |
|---|---|---|
| `state-features-v1` → **`v2`** | `features.py` | S2 (new aggregations) |
| `network-graph-v1` (new) | `graph_state.py` | S3 |
| `world-model-rssm-v1` (new) | `world_model.py` | S4 |
| `gru-temporal-v1` | `temporal.py` | unchanged (kept as ablation) |
| `transition-rollout-v1` | `rollout.py` | unchanged (kept as ablation) |
| `forecast-inference-v1` → **`v2`** | `predict.py` | S4 (uncertainty fields) |
| `stage-mapping-v1` → **`v2`** | `stage_mapping.py` | S7 (quantile thresholds) |
| `stage-thresholds-v1` (new) | `stage_mapping.py` | S7 |
| `explanation-v1` (new) | `explain.py` | S6 |
| `threshold-calibration-v1` | `calibration.py` | unchanged |
| `replay-evaluation-v1` | `evaluation.py` | S5 (per-host) → `v2` |
| `cic-ids2017-adapter-v1` | `cic_ids2017.py` | S7 (technique-level labels) → `v2` |
| `ctu13-adapter-v1` (new) | `datasets/ctu13.py` | S8 |
| `report-v1` → **`v2`** | `report.py` | S6 (SHAP section) |

## 8.3 PS-feature → implementation map (fill this in as you go; it becomes a deck slide)

| PS-named feature | Level | Implemented as | Aggregations | In model? | Sprint |
|---|---|---|---|:--:|:--:|
| src/dst IP | flow | `source_entity`/`destination_entity` | — (identity, never a model input) | N by design | ✅ |
| src/dst port | flow | `dst_port_nunique`, `dst_port_entropy`, `dst_port_low_share`, … | count/entropy/share | **Y** | S2 |
| TCP flag bitmask | flow | `flag_{syn,ack,fin,rst,psh,urg}_{count,ratio}` | count/ratio | **Y** | S2 |
| Protocol | flow | `proto_{tcp,udp,icmp}_share` | share | **Y** | S2 |
| Bytes per flow | flow | `bytes_{sum,mean,std,max,p90}` | 5 | **Y** | S2 |
| Packets per flow | flow | `packets_{sum,mean,max}` | 3 | **Y** | S2 |
| Flow duration | flow | `duration_{mean,std,max}` | 3 | **Y** | S2 |
| IAT mean/var/max | flow | `iat_{mean,var,max,min,p90}` | 5 | **Y** | S2 |
| Bidirectional ratio | flow | `bidirectional_ratio_{mean,std}` | 2 | **Y** | S2 |
| TTL + variance | packet | `ttl_{mean,std,var,min,max,nunique}` | 6 | **Y** | S2 |
| TCP window size | packet | `tcp_window_size_{mean,std,min,max}` | 4 | **Y** | S2 |
| IP fragment flags | packet | `frag_{df,mf}_share`, `frag_offset_nunique` | share/count | **Y** | S2 |
| Payload size distribution | packet | `payload_size_{sum,mean,std,p50,p90,entropy}` | 6 | **Y** | S2 |
| Port scan signatures | packet | `dst_port_sequential_score`, `dst_port_randomness`, `ports_per_host_max` | derived | **Y** | S2 |
| Retransmission counts | packet | `retransmission_{count,rate}` | count/rate | **Y** | S2 |

## 8.4 Risk register

| Risk | Likelihood | Impact | Mitigation |
|---|:--:|:--:|---|
| World model underperforms the GRU baseline | Medium | High | Keep every baseline. Report honestly. A well-measured negative result with the persistence comparison still satisfies "demonstrably learns dynamics". |
| Lead time stays 0 after S5 | Medium | High | S5-T1 measures the achievable ceiling *first*. If the ceiling is 0 for a dataset, say so and demonstrate on LANL/CTU-13 where dwell time exists. |
| PyTorch Geometric will not install | Medium | Medium | Hand-roll GAT in plain torch (~120 LOC). Recommended default. |
| SHAP too slow for the live UI | High | Medium | LinearExplainer for the baseline (instant), GradientSHAP for the neural model, cache everything, background of 100. |
| CIC-IDS2017 download/licence delay | Medium | High | Synthetic dwell-time scenarios (S5-T4) carry the demo; real-data results are a bonus row. Start the download **today**. |
| Agent context collapse on `dashboard/app.py` | High | Medium | S1-T5 splits it before any dashboard work begins. |
| Scope creep into Part 5 before Part 4 is green | High | High | Hard rule: no enhancement until its parent sprint's DoD is fully ticked. |
| Demo fails on the day | Low | Critical | Three tested fallbacks: dashboard → CLI → video. |

## 8.5 Glossary for the team

| Term | Meaning here |
|---|---|
| **World model** | A model that learns environment dynamics `P(S_t+1 \| S_t)` and can simulate futures without new observations — as opposed to a classifier that maps one input to one label. |
| **RSSM** | Recurrent State-Space Model. A deterministic recurrent path `h_t` plus a stochastic latent `z_t`, with a prior (no future evidence) and a posterior (with evidence), trained with a KL term. |
| **Prior vs posterior** | Posterior sees the current observation; prior does not. Forcing them together is what teaches the model to imagine. |
| **Free-running rollout** | Feeding the model's own prediction back as input for K steps. Error accumulates — `RolloutDiagnostics` already measures this. |
| **Lead time** | Windows between the first threshold crossing and the ground-truth attack onset. Only meaningful when reported with **false-early rate**. |
| **LOAO** | Leave-One-Attack-Out: hold out an entire attack family from training, test only on it. The generalisation proof. |
| **SHAP additivity** | `base_value + Σ shap_values == model_output`. The correctness test for any SHAP implementation. |
| **ECE / Brier** | Expected Calibration Error and Brier score — whether a stated probability of 0.7 actually means 70%. |
| **PSI** | Population Stability Index; measures feature-distribution drift. Already implemented in `drift.py`. |
| **Leakage guard** | Fitting statistics, thresholds or splits using data the model should not have seen. This repo's guards are its best asset — never weaken them. |

---

## FINAL WORD TO THE AGENT

This repository is already good. The failure mode is **not** "not enough features" — it is **"built adjacent to the specification rather than on it."** There is a linear ridge model where a world model was asked for, a coefficient product where SHAP was asked for, a NetworkX drawing where a GNN was asked for, and no PCAP upload where a PCAP upload was the named deliverable.

Every one of those is a bounded, well-understood piece of work, and the surrounding engineering — the contracts, the leak guards, the checksums, the honest limitations — is strong enough to carry them.

**Work the sprints in order. Ship one task per branch. Test everything. Never fabricate a number. When something fails, publish the failure and then fix it — that is the habit that already makes this repository unusual, and it is the habit that will win the round.**
