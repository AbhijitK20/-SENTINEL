# SENTINEL — Production Engineering Plan

> **Historical snapshot.** Written before the package rename `trajectory` → `sentinel` (commit `9effab5`); paths below reflect the plan as written. The current package is `src/sentinel/`, current state in [`../IMPLEMENTATION_STATUS.md`](../IMPLEMENTATION_STATUS.md).
### From SIH prototype → a platform that can be deployed, sold, audited, and operated
**20 sprints · full-stack · production-grade backend + world-class analyst UX**

> **Base commit audited:** `12fc8f1` · 86 commits · 10,902 LOC in `src/` · 249 test functions across 41 files
> **Verified in sandbox:** `219 passed, 1 failed, 4 skipped, 7 errors` — every failure/error is a missing optional dependency (`fastapi`), not a logic defect.
> **Predecessor document:** `SENTINEL_MASTER_PLAN.md` (10 hackathon sprints). This document **supersedes sprints S3–S10 of that plan** and absorbs their remaining scope into P1–P5 below. S1 and S2 of that plan are done or nearly done — see §0.2.

---

## TABLE OF CONTENTS

| Part | Contents |
|---|---|
| **0** | Audit: what changed, what's done, what's still open |
| **1** | Target architecture — what "production" actually means here |
| **2** | **Toolchain, Skills, plugins and MCP servers to install** |
| **3** | The 20 sprints (P1 → P20) |
| **4** | Design system & UX specification |
| **5** | Backend specification (API, data model, streaming) |
| **6** | Non-functional targets and SLOs |
| **7** | Definition of Production Ready |
| **8** | Appendices — repo layout, commands, glossary, risk register |

---

# PART 0 — AUDIT OF THE CURRENT STATE

## 0.1 What you shipped since the last review — verified, not claimed

I checked each item against the actual files, not against `ChangesUltra.md`.

| Item | Claimed | Verified | Notes |
|---|:--:|:--:|---|
| **G13** torch import bug fixed | ✅ | ✅ **Confirmed** | Full `pytest` now collects with torch absent. Only 3 files error, all on `fastapi`. This was the single worst structural bug — it's gone. |
| **G16** Apache-2.0 LICENSE | ✅ | ✅ | `LICENSE` (11,283 bytes) + `THIRD_PARTY.md` + SPDX headers |
| **G08** release bundle | ✅ | ✅ | `models/release/v1/` with `MANIFEST.json`, `PROVENANCE.md`, `TRAINING_CONFIG.yaml`, `baseline_model.joblib`, `calibration.json`, `feature_schema.json`, `split_manifest.json`, `weights/` |
| **G14** performance | ✅ | ✅ | `bisect_left/right` windowing; vectorised ingestion; `tests/test_performance.py` with 200k-event budgets |
| **S1-T5** dashboard split | ✅ | 🟡 **Partial** | 1,951 → 1,388 lines. Only the Live tab was extracted. `app.py` is still 1,388 lines — 3.5× the 400-line target. |
| **S1-T6** Makefile | ✅ | ✅ | `setup, gate, lint, test, format, demo, train, reproduce, bench-real, clean` |
| **S1-T7** CI matrix | ✅ | ✅ | lint / test (3.11–3.13) / core-only / coverage≥70 / pip-audit / verify-release |
| **S1-T8** AGENTS.md | ✅ | ✅ | 4,443 bytes, merged with ponytail rules |
| **S2-T1** rich aggregation | ✅ | ✅ | `Agg` StrEnum (12 types), `AGGREGATION_POLICY` (21 features → 53 slots), `_UNDEFINED_FOR_SINGLE`, `LEGACY_ALIASES` + deprecation warnings, `FEATURE_VERSION = "state-features-v2"` |
| **S2-T2** flags + ports | ✅ | 🟡 **Partial — see 0.2** | Flag bitmask decomposition ✅. Port behaviour = **only `high_port_ratio`**. |
| **S2-T3** IAT stats | ✅ | 🟡 | Aggregations over `iat_mean` exist, but nothing **produces** `iat_variance`/`iat_max` from PCAP or the sensors. Aggregating a field nobody writes is a no-op. |
| **S2-T4** feature catalog | ✅ | ✅ | `scripts/generate_feature_catalog.py` → `docs/FEATURE_CATALOG.md` |
| Retrain on v2 | ✅ | ✅ | Baseline F1 0.816 → **0.831**; temporal F1 0.923 → **0.957** (best horizon moved h+5 → h+1) |
| Ponytail refactor | ✅ | ✅ | `SPLIT_NAMES`/`split_assignment` deduped into `schemas.py`; dead `_split_audit_from_loaded` deleted; O(n²)→O(n) dedup in `predict.py` |

**Honest verdict: this was a genuinely good sprint.** The torch fix alone converted a repo that couldn't be installed as documented into one that can. Feature version v2 with a legacy-alias bridge and deprecation warnings is exactly the right migration pattern.

## 0.2 What is still open — read this before starting P1

Five things from the previous plan are marked done but are not.

### ① `configs/default.yaml` still excludes ports and flags
```yaml
excluded_features: [source_port, destination_port, protocol, tcp_flags]
```
Unchanged in both `default.yaml` and `slow-windows.yaml`. The whole point of S2-T2 was to replace *raw mean-aggregated identifiers* with *derived behavioural features* and then let those into the model. The derived features are mostly missing, so the exclusion still stands. **The problem statement's "which specific flags, ports … are contributing most" is still unanswerable.**

### ② Port behaviour is one feature, not eight
`state_builder.py` computes exactly one: `high_port_ratio = fraction of source_port > 1024`. That is the *least* informative port feature of the set. Still missing, and all specified in the previous plan:

| Missing | Why it matters |
|---|---|
| `dst_port_nunique` | the primary scan signal |
| `dst_port_entropy` | distinguishes scan from service traffic |
| `dst_port_sequential_score` | **sequential nmap scan** — the PS's "sequential port access pattern" |
| `dst_port_randomness` | **randomised scan** — the PS's other named pattern |
| `dst_port_wellknown_share`, `dst_port_low_share` | service-targeting behaviour |
| `ports_per_host_max` | per-target fan-out |
| `flag_syn_ratio`, `flag_syn_ack_ratio`, `flag_no_ack_share` | the PS's "SYN flags precede ACK floods" |

Note the flag work produced `syn_count_sum` / `syn_count_mean` — **counts, not ratios**. A count is volume-dependent and won't transfer across networks; the ratio is the invariant. Both are needed.

### ③ `AGGREGATION_POLICY` still contains meaningless entries
```python
"source_port": (Agg.MEAN, Agg.NUNIQUE),
"destination_port": (Agg.MEAN, Agg.NUNIQUE),
```
`destination_port_mean` is the arithmetic mean of port numbers. It has no semantics. `nunique` is excellent and should be promoted; `mean` should be deleted, not excluded downstream.

### ④ A test was skipped rather than fixed
`tests/test_live.py::test_fast_attack_shaped_windows_cross_threshold` is `@pytest.mark.skip`'d because "v2 enriched features change model decision boundaries." That may be a legitimate behaviour change — but a skipped detection test on the live path is a silent hole. It needs re-baselining with a documented new threshold, or the live path is now unverified.

### ⑤ Nothing from S3–S10 exists yet
No `world_model.py`, `explain.py`, `graph_state.py`, `gnn.py`, `entity_states.py`, no `mitre/` package, no `datasets/` adapters, no `tabs/analyze.py`. **The four requirement-level gaps (G01 world model, G02 GNN, G03 SHAP/attention, G07 PCAP upload) are all still fully open.** They are P1–P5 below.

## 0.3 The honest gap between "this" and "production"

You have an excellent **research prototype with enterprise-shaped decoration**. The decoration is real code — `registry.py`, `drift.py`, `cases.py`, `compliance.py`, `federated.py`, `ledger.py` — and it is honestly labelled as in-process simulation. But:

| Dimension | Today | Production needs |
|---|---|---|
| **Persistence** | Python dicts, JSON files on local disk | Postgres + TimescaleDB, migrations, backups, PITR |
| **Ingestion** | File replay, tcpdump pipe, in-process queue | Kafka/Redpanda, schema registry, watermarks, backpressure, replay from offset |
| **API** | 20 sync FastAPI endpoints, custom API keys | Versioned async API, OIDC, RFC 9457 errors, idempotency, rate limits, pagination, SSE/WS |
| **Frontend** | Streamlit, 1,388-line `app.py` | A real product: Next.js + TypeScript + design system + a11y + < 2 s TTI |
| **Multi-tenancy** | `org_id` field on API keys | Row-level isolation enforced in the database, tested for cross-tenant leakage |
| **Serving** | Model loaded in the Streamlit/uvicorn process | Dedicated inference workers, warm pools, batching, canary, rollback |
| **Observability** | Prometheus `/metrics` + Grafana | OTel traces + structured logs + metrics, SLOs, error budgets, runbooks |
| **Security** | Hashed API keys, offline default | SBOM, signed images, secret management, SAST/DAST, pen test, CVE SLA |
| **Deploy** | `docker compose` | Helm chart, K8s, HA, blue/green, DR, *plus* a single-node appliance mode for air-gapped CII |
| **MLOps** | Checksums + a manual registry | Experiment tracking, feature store, automated eval gates, drift→retrain with human approval |

None of this is a criticism of the prototype. It's the normal distance between the two things. Twenty sprints closes it.

---

# PART 1 — TARGET ARCHITECTURE

## 1.1 The product, stated plainly

> **SENTINEL is a network attack forecasting platform.** It watches network telemetry, maintains a learned model of how the network behaves, simulates where the current trajectory leads, and tells a defender — with evidence — which host is about to be compromised, by which technique, and how long they have.

Two deployment shapes, one codebase:

- **Appliance mode** — single node, air-gapped, Docker Compose or a systemd bundle. For CII operators who cannot connect anything to anything. This is your differentiator and must never regress.
- **Platform mode** — Kubernetes, multi-tenant, horizontally scaled. For MSSPs and large enterprises.

## 1.2 Target system architecture

```
┌─ COLLECTION ────────────────────────────────────────────────────────────┐
│  Packet sensor (tcpdump/AF_PACKET)   Flow sensor (5-tuple aggregation)   │
│  Syslog / auth-log tail              NetFlow/IPFIX collector             │
│  File upload (PCAP / CSV)            Agent-less span/tap                 │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │  UnifiedEvent (Avro/Protobuf, versioned)
┌─ STREAM ──────────────────────▼─────────────────────────────────────────┐
│  Redpanda/Kafka  topics: events.raw → events.normalised → states.windowed│
│  Schema Registry · watermarks · exactly-once windowing · replay by offset│
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌─ PROCESSING ──────────────────▼─────────────────────────────────────────┐
│  Windowing service  ──▶  Feature service  ──▶  Graph builder            │
│       (event-time)        (v3 feature set)      (host graph per window)  │
│                                   │                                      │
│                          Online feature store (Redis)                    │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌─ INFERENCE ───────────────────▼─────────────────────────────────────────┐
│  World model workers (RSSM: encoder→prior/posterior→decoder→heads)       │
│    ├─ risk head        P(infiltration) over K windows, with uncertainty  │
│    ├─ stage head       MITRE tactic/technique distribution               │
│    └─ imagine(K, N)    N sampled future trajectories                     │
│  Rule detectors (9) · Stage rules · Threat-intel enrichment              │
│  Explainability workers (SHAP · attention · counterfactual)              │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌─ DECISION & STATE ────────────▼─────────────────────────────────────────┐
│  Correlation → Incidents → Cases (SLA) → Notifications → Response hooks  │
│  Postgres + TimescaleDB (hypertables for states/forecasts/findings)      │
│  Object store (captures, artifacts, reports)  ·  Tamper-evident ledger   │
└──────────────────────────────┬──────────────────────────────────────────┘
                               │
┌─ ACCESS ──────────────────────▼─────────────────────────────────────────┐
│  API v2 (async FastAPI) · OIDC · RBAC/ABAC · SSE + WebSocket · webhooks  │
│  Next.js analyst console  ·  CLI  ·  ATT&CK Navigator / STIX / SIEM out  │
└─────────────────────────────────────────────────────────────────────────┘
       OpenTelemetry traces + metrics + structured logs throughout
```

## 1.3 Technology decisions (opinionated, with reasons)

| Layer | Choice | Why this and not the alternative |
|---|---|---|
| Language (backend) | **Python 3.12** | The ML stack lives here. Don't split the codebase. |
| API framework | **FastAPI (async)** | Already in use; ASGI, OpenAPI, Pydantic v2 native. |
| Validation | **Pydantic v2** | Already the contract layer. Keep `extra="forbid"`. |
| Database | **PostgreSQL 16 + TimescaleDB** | Time-series hypertables for windows/forecasts, plus real relational integrity for cases and tenants. One database instead of Postgres+Influx. |
| Migrations | **Alembic** | Non-negotiable. Manual schema changes are how you lose data. |
| Cache / online store | **Redis 7** | Feature lookups and rolling baselines need sub-ms reads. |
| Streaming | **Redpanda** (Kafka API) | Kafka semantics without ZooKeeper/JVM. Single binary → works in appliance mode. |
| Task queue | **Arq** (async, Redis) | Celery is heavier and sync-first. Arq matches an async FastAPI stack. |
| Object storage | **MinIO** (S3 API) | Runs air-gapped; identical API to S3 in cloud. |
| Identity | **Keycloak** (OIDC) | Self-hostable, SAML bridge for enterprise SSO, no vendor lock. |
| Frontend | **Next.js 15 (App Router) + TypeScript** | Server components for heavy data views, one framework for app + docs. |
| UI primitives | **Radix UI + Tailwind v4** | Accessible unstyled primitives; you own the visual layer, so it won't look like every other shadcn dashboard. |
| Data viz | **visx** (D3 primitives for React) + **deck.gl** for the graph canvas | Recharts can't do a 5,000-node force graph or brushed multi-series timelines. |
| State/data | **TanStack Query** + **Zustand** | Server cache separated from UI state. |
| Tables | **TanStack Table + virtualiser** | 100k flagged flows must scroll at 60 fps. |
| Testing (FE) | **Vitest + Testing Library + Playwright** | Unit, component, and real-browser E2E. |
| Component docs | **Storybook 8** | The design system needs a living catalogue or it decays. |
| Observability | **OpenTelemetry → Tempo/Prometheus/Loki, Grafana** | You already have Prometheus+Grafana; add traces and logs. |
| Packaging | **Helm chart** + **Docker Compose appliance bundle** | Both deployment shapes from one artifact set. |
| IaC | **Terraform** (cloud) | Reviewable infrastructure. |
| Supply chain | **syft** (SBOM) + **grype**/**trivy** (scan) + **cosign** (sign) | Required for any government-adjacent procurement. |

**Rejected on purpose, with reasons** — write these into an ADR so they don't get relitigated:
- *Streamlit as the production UI.* It is a superb demo and prototyping tool. It cannot deliver keyboard-first navigation, virtualised tables, real routing, SSR, or accessibility compliance. **Keep it** as `sentinel-lab` for researchers and demos; build the product UI separately.
- *Microservices from day one.* Start as a **modular monolith** with enforced internal boundaries (P6). Extract the inference workers (P10) and nothing else until load data says otherwise.
- *A graph database.* The graph is per-window and ephemeral. Postgres + in-memory graph construction is faster and simpler than Neo4j here.
- *MongoDB.* Your contracts are strict and relational. Don't.

---

# PART 2 — TOOLCHAIN, SKILLS, PLUGINS AND MCP SERVERS TO INSTALL

This is the section you asked for. Install these **before P1**, not when you first need them.

## 2.1 Agent Skills to enable

Skills are folders of instructions that load on demand. Availability differs between Claude.ai, Claude Code, Claude Cowork and OpenCode — **check your own environment's skill list rather than assuming a name exists.** These are the ones that matter for this project.

### Built-in skills to make sure are enabled

| Skill | Use it for | Sprints |
|---|---|---|
| **`frontend-design`** | Visual direction, type scale, palette, avoiding generic-AI-dashboard look. **This is the most important skill for P11–P15.** | P11–P15 |
| **`skill-creator`** | Authoring the custom skills in §2.2 and measuring whether their descriptions actually trigger | P0, ongoing |
| **`pptx`** | Board decks, customer decks, the SIH 5-slider | P20 |
| **`docx`** | Architecture docs, security questionnaires, procurement responses | P17, P20 |
| **`pdf`** | Generating and filling compliance forms, exporting analyst reports | P19, P20 |
| **`xlsx`** | Benchmark result workbooks, risk registers, cost models | P18, P20 |
| **`file-reading`** / **`pdf-reading`** | Ingesting dataset documentation, ATT&CK STIX bundles, RFCs | P5, P8 |

> In Claude Code / Cowork, check `/mnt/skills/public/` and your plugin catalogue. If a skill you want isn't there, author it with `skill-creator` rather than pasting a long prompt every time.

### Custom skills to author for this repo (the real win)

Write these with `skill-creator`. Each one turns a recurring, error-prone task into a repeatable one. Put them in `.claude/skills/` (or your agent's equivalent) and commit them.

| # | Skill name | What it encodes | Why it pays for itself |
|---|---|---|---|
| **C1** | `sentinel-contracts` | Every Pydantic contract, the `extra="forbid"` rule, the version-string registry, how to add a field and what else must change | The agent breaks contracts constantly without this |
| **C2** | `sentinel-leakage-guard` | Train-only fitting, validation-only calibration, test-touched-once, the split audit, how to write a leakage test | Your single most valuable engineering asset; protect it mechanically |
| **C3** | `sentinel-honesty` | "No number without a script that printed it", the claim-audit procedure, the PENDING convention | Prevents the slow drift into overclaiming that kills credibility |
| **C4** | `sentinel-feature-authoring` | How to add a feature: policy entry → aggregation → alias → catalog regen → retrain → RESULTS update | Turns a 6-file change into one instruction |
| **C5** | `sentinel-dataset-adapter` | The adapter contract, strict unmapped-label abort, licence/provenance docstring, synthetic fixture pattern | You're writing four more adapters in P5 |
| **C6** | `sentinel-api-conventions` | Versioning, RFC 9457 errors, pagination, idempotency keys, authz decorator, OpenAPI examples | Keeps 60+ endpoints consistent |
| **C7** | `sentinel-design-system` | Your tokens, type scale, spacing, motion rules, component API conventions, a11y checklist | Without this every new screen drifts visually |
| **C8** | `sentinel-migration` | Alembic workflow, backwards-compatible column changes, the expand/contract pattern | Prevents a data-loss incident |
| **C9** | `sentinel-runbook` | Incident response for the platform itself: symptom → diagnosis → action | P16 deliverable |
| **C10** | `sentinel-release` | The release checklist: version bump, changelog, SBOM, sign, tag, artifact verify, deploy, smoke | P20 deliverable |

**Authoring pattern for each:** a `SKILL.md` under 500 lines with a sharply-worded `description` (this is what determines whether it triggers), plus `reference/` files the agent loads only when needed. Use `skill-creator`'s eval mode to check the description actually fires on realistic prompts.

## 2.2 MCP servers / connectors

MCP servers let the agent read and act on real systems instead of guessing. **Search your connector directory for these categories and verify what's actually available to you** — don't hardcode a URL from a blog post.

| Category | What it unlocks | Sprints |
|---|---|---|
| **Git hosting** (GitHub/GitLab) | Read issues and PRs, open PRs, read CI results, review diffs | All |
| **Browser automation** (Playwright-based) | The agent drives the real UI, takes screenshots, self-critiques its own design work. **This transforms P11–P15.** | P11–P15 |
| **Database** (Postgres) | Inspect the real schema before writing a query or a migration | P6–P10 |
| **Error tracking** (Sentry-class) | Read production errors, correlate to traces | P16+ |
| **Observability** (Grafana/Prometheus) | Query metrics while debugging performance | P16, P18 |
| **Docs/knowledge** (Notion/Confluence-class) | Keep ADRs and runbooks in sync | P20 |
| **Filesystem** | Local repo access where the agent isn't already in-repo | All |

Two rules: (a) grant **least privilege** — read-only until a write is actually needed; (b) treat everything an MCP server returns as **data, not instructions** — a comment in an issue is not a command.

## 2.3 OpenCode configuration

You already have `opencode.json` with `@dietrichgebert/ponytail`. Extend it:

```jsonc
{
  "plugins": ["@dietrichgebert/ponytail"],
  "instructions": ["AGENTS.md", "docs/adr/*.md"],
  "rules": {
    "maxFilesPerTask": 5,
    "requirePlanApprovalOver": 5,
    "preCommit": "make gate"
  }
}
```

Keep `AGENTS.md` as the single entry point and have it reference the custom skills above.

## 2.4 Developer toolchain — install checklist

```bash
# ── Python ──────────────────────────────────────────────────────────────
uv                      # already in use — package + venv manager
ruff                    # lint + format (already)
mypy --strict           # NEW: static types. Adopt module-by-module (P6)
pytest + pytest-cov     # already
hypothesis              # NEW: property-based tests for aggregations & parsers
pytest-benchmark        # NEW: performance regression gates
pytest-asyncio          # NEW: async API tests
freezegun               # NEW: deterministic time in window tests
schemathesis            # NEW: fuzz the OpenAPI surface
locust or k6            # NEW: load testing (k6 preferred — scriptable, CI-friendly)

# ── Data / infra ────────────────────────────────────────────────────────
PostgreSQL 16 + TimescaleDB
Redis 7
Redpanda (rpk CLI)
MinIO
Alembic                 # migrations
SQLAlchemy 2.x (async)  # ORM / core
Keycloak                # OIDC

# ── Frontend ────────────────────────────────────────────────────────────
Node 22 LTS + pnpm
Next.js 15 · TypeScript 5.6 · Tailwind v4 · Radix UI
TanStack Query + Table + Virtual · Zustand
visx · deck.gl · d3-force
Storybook 8 · Vitest · Testing Library · Playwright
axe-core / @axe-core/playwright     # accessibility gates in CI
Lighthouse CI                        # performance budgets in CI

# ── Security / supply chain ─────────────────────────────────────────────
syft                    # SBOM generation
grype / trivy           # vulnerability scanning
cosign                  # image signing
gitleaks                # secret scanning (pre-commit + CI)
bandit                  # Python SAST
semgrep                 # custom security rules
pip-audit               # already in CI

# ── Ops ─────────────────────────────────────────────────────────────────
Docker + Compose v2 · kubectl · Helm 3 · Terraform
OpenTelemetry Collector · Grafana + Tempo + Loki + Prometheus
pre-commit              # ruff, gitleaks, mypy, conventional-commit lint
```

## 2.5 Pre-commit hooks (set this up in P1, hour one)

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    hooks: [{id: ruff, args: [--fix]}, {id: ruff-format}]
  - repo: https://github.com/gitleaks/gitleaks
    hooks: [{id: gitleaks}]
  - repo: https://github.com/pre-commit/mirrors-mypy
    hooks: [{id: mypy, additional_dependencies: [pydantic, types-PyYAML]}]
  - repo: local
    hooks:
      - id: no-network-in-src
        name: forbid network clients in src/trajectory
        entry: python scripts/check_offline_imports.py
        language: system
        files: ^src/trajectory/
```

That last hook mechanises your offline-first guarantee at commit time instead of at test time.

---

# PART 3 — THE 20 SPRINTS

## 3.0 Phase map

```
PHASE A · INTELLIGENCE        P1  P2  P3  P4  P5     "the model is actually a world model"
PHASE B · BACKEND             P6  P7  P8  P9  P10    "it can hold state, scale, and be trusted"
PHASE C · FRONTEND            P11 P12 P13 P14 P15    "an analyst would choose to use it"
PHASE D · HARDENING           P16 P17 P18            "it can be operated and defended"
PHASE E · MLOPS & GA          P19 P20                "it can be shipped and sold"
```

**Cadence:** 2 weeks per sprint = 40 weeks for the full programme. At 1 week per sprint with an AI agent doing the mechanical work and a human doing review and judgement, 20 weeks is achievable — but **do not compress P3, P9, P13 or P17**. Those four are where a rushed decision costs a rewrite.

**Sprint ritual (every sprint, no exceptions):**
1. Day 0 — human writes the sprint goal in one sentence; agent produces a file-change manifest; human approves.
2. Daily — one task per branch, `make gate` before every commit.
3. Day N-1 — demo the exit criterion to someone outside the team.
4. Day N — update `IMPLEMENTATION_STATUS.md`, `RESULTS.md`, `CHANGELOG.md`, and the relevant ADR. Retrospective: what surprised us?

**Every sprint's Definition of Done includes these six, in addition to its own:**
- [ ] `make gate` green (lint + format + types + tests) on all supported Python versions
- [ ] New code covered ≥ 80%; overall coverage does not decrease
- [ ] Docs updated in the same PR as the code
- [ ] No new claim without a test that proves it
- [ ] Appliance mode (single node, offline) still works — verified, not assumed
- [ ] An ADR recorded for every decision that would be expensive to reverse

---

# PHASE A — INTELLIGENCE
*The four requirement-level gaps from the problem statement are still open. Close them first: everything downstream renders, stores, and serves whatever this phase produces.*

---

## P1 — Feature Science: finish what S2 started

**Goal:** the feature set is complete, semantically meaningful, transferable across networks, and **actually reaches the model**.
**Closes:** G04, G05 (residual), G06.
**Exit demo:** run a real nmap sequential scan and a `-r`-randomised scan against the lab target; show `dst_port_sequential_score` at 0.94 vs 0.11 while `high_port_ratio` is identical for both. That contrast is the whole argument.

### P1-T1 · Port behaviour features (the eight that are missing)

**Files:** `src/trajectory/features/ports.py` (new), `src/trajectory/state_builder.py`

Create a dedicated module — these are real algorithms and they deserve their own tests.

```python
def dst_port_nunique(ports: Sequence[int]) -> float: ...
def dst_port_entropy(ports: Sequence[int]) -> float:
    """Shannon entropy in bits over the destination-port distribution."""
def dst_port_randomness(ports: Sequence[int]) -> float:
    """Normalised entropy: H / log2(nunique). ~1.0 => uniformly random targeting."""
def dst_port_sequential_score(ports_in_time_order: Sequence[int]) -> float:
    """Fraction of consecutive probes whose destination port differs by exactly ±1.

    1.0  => textbook sequential scan (nmap without -r)
    ~0.0 => random targeting or normal traffic
    Returns None for fewer than 3 probes — insufficient evidence, never 0.0.
    """
def ports_per_host_max(pairs: Sequence[tuple[str, int]]) -> float: ...
def dst_port_wellknown_share(ports: Sequence[int]) -> float: ...
def dst_port_low_share(ports: Sequence[int]) -> float: ...
def src_port_ephemeral_share(ports: Sequence[int]) -> float: ...
```

**Critical detail the previous attempt missed:** `dst_port_sequential_score` needs **time-ordered ports per source host**, not a flat bag of ports for the window. Thread the ordering through `_build_state`.

**AC1** Sequential-scan fixture → `> 0.9`; randomised-scan fixture → `< 0.2`; benign web traffic → `< 0.1`; three separate tests.
**AC2** Fewer than 3 probes → the feature key is **absent**, not zero. (Consistent with `_UNDEFINED_FOR_SINGLE`.)
**AC3** Property tests with Hypothesis: entropy ∈ [0, log2(n)]; randomness ∈ [0,1]; permuting a port bag leaves entropy unchanged but may change the sequential score.
**AC4** Every function is pure, typed, and has a docstring stating its range and its insufficient-evidence behaviour.

### P1-T2 · Flag ratios, not just counts

**Files:** `src/trajectory/features/flags.py` (new), `state_builder.py`

Keep the existing `*_count_sum` / `*_count_mean`. **Add the ratios** — counts are volume-dependent, ratios are the network-invariant signal:

`flag_syn_ratio`, `flag_ack_ratio`, `flag_fin_ratio`, `flag_rst_ratio`, `flag_psh_ratio`, `flag_urg_ratio`, `flag_syn_ack_ratio` (SYN ÷ max(ACK,1)), `flag_no_ack_share` (share of flows with SYN and no ACK), `flag_xmas_share` (FIN+PSH+URG together).

Also add `proto_tcp_share` / `proto_udp_share` / `proto_icmp_share` and **delete** `protocol` from the aggregation policy — a mean protocol number is noise.

**AC1** SYN-flood fixture → `flag_syn_ratio > 0.8`, `flag_syn_ack_ratio > 10`.
**AC2** XMAS-scan fixture → `flag_xmas_share > 0.9`.
**AC3** `destination_port_mean`, `source_port_mean`, `protocol_mean`, `tcp_flags_nunique` removed from `AGGREGATION_POLICY`; a test asserts they are not emitted.

### P1-T3 · Packet-level completion

**Files:** `src/trajectory/pcap_ingestion.py`, `src/trajectory/features/packets.py` (new)

- **Fragment flags:** `frag_df_share`, `frag_mf_share`, `frag_offset_nunique` (replace the meaningless mean).
- **Retransmissions:** count repeated `(src, dst, sport, dport, seq, len)` tuples per flow → `retransmission_count`, `retransmission_rate`.
- **Real IAT stats from the wire:** group packets by 5-tuple, compute inter-arrival deltas, emit `iat_mean/var/max/min/p90` **and** `iat_cv` (coefficient of variation — low CV with regular spacing is the classic **beaconing** signature; this single feature is worth more than the rest of the packet set for C2 detection).
- **Bidirectional ratio from PCAP:** reverse bytes ÷ total bytes per 5-tuple.
- **TTL:** you already aggregate `ttl_var`; add `ttl_nunique_per_src` — multiple TTLs from one source indicates spoofing or a NAT'd botnet.

**AC1** A generated PCAP yields flow-summary events with all five IAT statistics plus `iat_cv`.
**AC2** A synthetic beacon (callback every 30 s ±0.5 s) → `iat_cv < 0.05`; bursty human traffic → `iat_cv > 0.6`.
**AC3** A PCAP with deliberate retransmissions → correct `retransmission_count`, hand-verified fixture.
**AC4** `coverage["packet"] == True` and the packet features appear in `NetworkState`.

### P1-T4 · Un-exclude the features and re-baseline

**Files:** `configs/*.yaml`, `FEATURE_SPECIFICATION.md`, `RESULTS.md`

```yaml
baseline_config:
  # v3: raw identifiers remain ineligible (no semantics, entity-memorisation risk).
  # All derived behavioural flag/port/timing features are now model inputs.
  excluded_features: []      # the meaningless aggregations no longer exist to exclude
```

Bump `FEATURE_VERSION` to `state-features-v3`. Retrain baseline + temporal. **Report the delta honestly, including if it gets worse** — more features can hurt a small-sample logistic model, and saying so is more credible than a suspiciously monotonic improvement story.

**AC1** Baseline feature weights include at least three port/flag features in the top ten — proof they reach the model.
**AC2** `RESULTS.md` has a v2→v3 comparison table with the honest delta.
**AC3** `docs/FEATURE_CATALOG.md` regenerated; CI drift check passes.

### P1-T5 · Un-skip the live test

**Files:** `tests/test_live.py`

Re-baseline `test_fast_attack_shaped_windows_cross_threshold` against v3 features with a documented threshold, or replace it with a test that asserts the *ordering* property (attack window scores above benign window) rather than an absolute threshold — ordering is stable across feature versions, thresholds are not. **Remove the skip either way.**

**AC1** No `@pytest.mark.skip` remains on any detection-path test.
**AC2** The replacement test is version-robust and documented as such.

### P1-T6 · Feature store contract

**Files:** `src/trajectory/features/registry.py` (new), `docs/adr/0001-feature-versioning.md`

A single registry object that knows: every feature name, its base field, its aggregation, its dtype, its valid range, its insufficient-evidence rule, its introduced-in version, and whether it is model-eligible. Everything downstream (catalog generation, drift monitoring, SHAP labelling, the UI's feature glossary) reads from this one place.

**AC1** `FeatureRegistry.all()` is the single source of truth; `generate_feature_catalog.py` reads it.
**AC2** A test asserts every feature emitted by `_build_state` is registered — you cannot ship an undocumented feature.

### P1 Definition of Done
- [ ] 8 port features, 10 flag/protocol features, 8 packet features — all tested
- [ ] `iat_cv` beaconing signature implemented and demonstrated
- [ ] Meaningless aggregations deleted, not excluded
- [ ] `state-features-v3`, retrained, honest delta published
- [ ] Zero skipped detection tests
- [ ] `FeatureRegistry` is the single source of truth
- [ ] ADR-0001 records the feature-versioning policy

---

## P2 — Graph State & GNN Encoder

**Goal:** the network state *is* a graph and a graph neural network encodes it.
**Closes:** G02.
**Exit demo:** a live host graph where edge thickness is GAT attention, with the scanning host visibly pulling the model's attention.

### P2-T1 · `NetworkGraph` contract and builder
**Files:** `src/trajectory/graph/state.py`, `schemas.py`, `DATA_CONTRACTS.md`

Per window: nodes = hosts, edges = directed host pairs. Node features from P1 computed **per host** (fan-out, port entropy, sequential score, flag ratios, failed auth, IAT stats, new-peer count, `is_internal`, asset criticality). Edge features: flow count, bytes, packets, flag ratios, ports touched, `is_new_edge` (unseen in last N windows), mean IAT.

**Identity must not leak.** No one-hot IPs, no hostname embeddings. Behavioural features plus `is_internal` only.

**AC1** Deterministic node ordering (sorted host id). **AC2** Node/edge counts reconcile with `edge_summary`. **AC3** A test scans `node_feature_names` and fails on anything identity-shaped. **AC4** Empty window → zero-node graph with a coverage flag, not an exception.

### P2-T2 · GAT encoder
**Files:** `src/trajectory/graph/gnn.py`

Hand-rolled multi-head GAT in plain PyTorch (~150 LOC using `index_add_` + segment softmax). **Do not take a PyTorch Geometric dependency** — it is a recurring install-failure source and you need appliance-mode reliability more than you need PyG's convenience. 2 layers, 4 heads, hidden 64, ELU. Readout: `concat(mean, max, attention-weighted sum)`.

**Export `alpha` per edge per head.** This is simultaneously the PS's required "attention mechanism" and your best visualisation.

**AC1** 50-node/200-edge forward pass < 50 ms CPU.
**AC2** Attention sums to 1.0 over each node's incoming edges.
**AC3** **Permutation invariance:** shuffle node order, graph embedding identical within 1e-5. *This is the one test that proves the GNN is correct — write it first.*
**AC4** A GraphSAGE variant behind a config flag for the ablation row.

### P2-T3 · Fusion and ablation
**Files:** `src/trajectory/graph/sequence.py`, `configs/`

`state_encoder: tabular | graph | fused`. All three train end-to-end; `RESULTS.md` gets a three-row ablation.

**AC1** Three configurations train. **AC2** Ablation published with the honest delta.

### P2 Definition of Done
- [ ] `NetworkGraph` contract, no identity leakage, test-enforced
- [ ] Dependency-free GAT with exported attention; permutation-invariance test green
- [ ] Three-way ablation published
- [ ] ADR-0002: why hand-rolled GAT over PyG

---

## P3 — The World Model ⭐ *do not compress this sprint*

**Goal:** a learned latent state-space model that outputs a **distribution** over future states and can simulate forward without observations.
**Closes:** G01 — the premise of the entire problem statement.
**Exit demo:** "Here are 100 sampled futures from the current state. 73 cross the infiltration boundary by step 3. Here is the mean with a 90% band, and here is the same rollout with the attacker's traffic removed — it doesn't."

### P3-T1 · RSSM architecture
**Files:** `src/trajectory/world_model/` (package: `model.py`, `heads.py`, `train.py`, `imagine.py`)

```
o_t  = fused observation (tabular v3 ⊕ graph embedding)
e_t  = Enc(o_t)                                   MLP d → 128
h_t  = Core(h_{t-1}, [z_{t-1}, e_t])              LSTM | Transformer | GRU
q(z_t | h_t, e_t) = N(μ_q, σ_q)                   posterior — sees evidence
p(z_t | h_t)      = N(μ_p, σ_p)                   prior — does not
ô_t  ~ p(o_t | h_t, z_t)                          decoder
risk  = σ(MLP([h_t, z_t]))                        P(infiltration)
stage = softmax(MLP([h_t, z_t]))                  MITRE distribution (P5 trains it)
```

```
L = recon_nll(ô_t, o_t) + β·KL(q ‖ p) + λ·BCE(risk, y) + γ·CE(stage, s)
```

**The one sentence you must be able to say:** *"The KL term forces the prior — which never sees the future observation — to match the posterior that does. That is how the model learns to imagine rather than classify."*

Three interchangeable cores by config: `lstm` (PS-named), `transformer` (causal, **default**, gives temporal attention for free), `gnn_fused`.

**AC1** Trains; final loss < 0.8 × initial (tested). **AC2** Three cores all train and are config-selectable. **AC3** `model_version = "world-model-rssm-v1"`, checksummed, exported to `models/release/`. **AC4** β-annealing schedule implemented and documented (KL collapse is the standard failure mode — guard against it and test that `KL > 0` at convergence).

### P3-T2 · `imagine()` — the forward simulation
```python
def imagine(self, history, k: int, n_samples: int = 100, temperature: float = 1.0
           ) -> ImaginedRollout:
    """Roll the PRIOR forward k steps with no observations, sampling z each step."""
```
Returns decoded states, per-sample risk, per-sample stage distribution, and per-step divergence diagnostics.

**AC1** Correct shapes, reproducible under seed.
**AC2** **The proof of learned dynamics:** the prior's one-step prediction MSE beats a persistence baseline (`ô_{t+1} = o_t`) on the test split. Report as `one_step_prediction_mse` in `RESULTS.md`. *A classifier has no such number. This single metric is your answer to "is this really a world model?"*
**AC3** Sample spread widens monotonically with k — physically correct, and it proves the uncertainty is real.

### P3-T3 · Uncertainty and probabilistic calibration
**Files:** `world_model/ensemble.py`, `metrics.py`, `schemas.py`

5-member seed ensemble → epistemic uncertainty; learned σ → aleatoric. Extend `ProbabilityPoint` with `probability_lower`, `probability_upper`, `epistemic`, `aleatoric`; bump `Forecast` to v2.

Add to `metrics.py`: **Brier score**, **Expected Calibration Error**, **reliability diagram** data. A forecast that says 0.7 must be right 70% of the time — nobody else in this space will report this.

**AC1** Uncertainty band on every timeline point, rendered. **AC2** ECE tested against synthetic perfectly-calibrated and perfectly-miscalibrated inputs. **AC3** Brier + ECE in `RESULTS.md` for every model.

### P3-T4 · The comparison table
**Files:** `scripts/run_world_model.py`, `evaluation.py`

Identical windows, identical splits, identical feature schema:

| Forecaster | F1 | P | R | FPR | PR-AUC | Brier | ECE | Median lead | False-early | 1-step MSE |
|---|---|---|---|---|---|---|---|---|---|---|
| Logistic baseline | | | | | | | | | | — |
| GRU per-horizon | | | | | | | | | | — |
| Linear ridge rollout | | | | | | | | | | |
| World model (LSTM) | | | | | | | | | | |
| **World model (Transformer)** | | | | | | | | | | |
| World model (GNN-fused) | | | | | | | | | | |
| Persistence | — | — | — | — | — | — | — | — | — | |

**Keep `rollout.py` and `temporal.py`.** They are your ablation rows and they prove you measured rather than assumed.

**AC1** One command produces the whole table. **AC2** Identical-windows assertion is a test. **AC3** Honest publication, including rows where the world model loses.

### P3 Definition of Done
- [ ] RSSM with prior/posterior/decoder/risk/stage heads and a guarded KL term
- [ ] LSTM, Transformer, GNN-fused cores
- [ ] `imagine()` with sampled trajectories and widening uncertainty
- [ ] **Prior beats persistence on one-step MSE** — the proof
- [ ] Brier, ECE, reliability diagram
- [ ] 7-row comparison, identical windows
- [ ] `MODEL_PLAN.md` rewritten with the equations; ADR-0003 on the architecture choice

---

## P4 — Explainability Engine

**Goal:** every prediction carries a real SHAP attribution, a real attention map, and a counterfactual — at feature, host, and timestep granularity.
**Closes:** G03. The PS calls black-box output "not acceptable", so this is pass/fail.
**Exit demo:** one screen — SHAP waterfall, temporal attention heatmap, attention-weighted host graph, and a plain-English sentence, all for the same prediction.

### P4-T1 · `explain/` package with real SHAP
**Files:** `src/trajectory/explain/` (`shap_engine.py`, `attention.py`, `counterfactual.py`, `metrics.py`, `contracts.py`)

Methods: `EXACT_LINEAR` (keep — it's exact for logistic), `KERNEL_SHAP`, `DEEP_SHAP`, `GRADIENT_SHAP`, `INTEGRATED_GRADIENTS`, `ATTENTION`.

- Logistic → `shap.LinearExplainer`. **Cross-check it equals your existing `coef × standardised value` to 1e-9 and make that a test.** That's a correctness proof, and it's a beautiful thing to show a judge or a customer.
- World model → `GradientExplainer` over the sequence, with a **hand-written Integrated Gradients fallback** (~30 lines, pure torch) so SHAP is never a hard dependency in appliance mode.
- Background: 100 sampled **training-split** benign windows. Never test data — that's leakage and someone will ask.
- Cache by `(state_key, model_version, method)`.

**AC1** **SHAP additivity:** `base_value + Σ shap ≈ model_output` within 1e-3. The single most important explainability test.
**AC2** LinearExplainer ≡ exact attribution to 1e-9.
**AC3** A test asserts no test-split window enters the background set.
**AC4** Cached retrieval < 50 ms. **AC5** `Forecast.driving_features` gains `attribution_method` so the UI can never mislabel a number.

### P4-T2 · Attention export
Temporal attention from the Transformer core (`[layers, heads, seq, seq]`, plus a reduced `[seq]` vector = attention from the final position). Graph attention from the GAT `alpha`.

**AC1** Weights exported, sum to 1.0 along the attended axis, stored in `Explanation`.
**AC2** Scenario where window 6 of 8 holds the burst → highest temporal attention on window 6. *If it fails, that's a real finding — investigate, don't weaken the test.*
**AC3** Lateral-movement scenario → attacker host is the top-attention node.

### P4-T3 · Counterfactuals (the feature analysts will actually use)
```python
def minimal_counterfactual(state, model, *, target_probability: float) -> Counterfactual:
    """Smallest change to the top-k features that brings P below target.

    "If dst_port_nunique had stayed below 12, this would be 0.14 instead of 0.87."
    """
```
Constrain to *actionable* features (fan-out, port count, transfer volume) — a counterfactual on `ttl_var` is not something a defender can act on.

**AC1** Produces a valid counterfactual within 3 feature changes for ≥ 80% of positive test windows. **AC2** Feasibility constraints respected (no negative byte counts). **AC3** Rendered as a sentence in the UI and the report.

### P4-T4 · Explanation quality metrics — the differentiator
Nobody measures whether their explanations are *correct*. You will.

- **Deletion / insertion curves + AUC** — remove top-k attributed features and measure how fast the prediction falls. Faster = more faithful.
- **Model-randomisation sanity check (Adebayo et al.)** — randomise the weights; attributions *must* change. If they don't, the explanation isn't reading the model.
- **Stability** — 1% input noise; attribution rank correlation should stay high.

**AC1** Deletion/insertion AUC per method in `RESULTS.md`. **AC2** Sanity check passes (rank correlation vs randomised model < 0.3). **AC3** `EXPLAINABILITY_PLAN.md` rewritten with measured results.

### P4-T5 · Natural-language explanation (deterministic, no LLM)
Template-generated from the top SHAP features — an LLM would break the offline guarantee.

> *"Infiltration probability 0.87 within 2 windows. Driven by port fan-out (47 distinct destination ports, +0.31), SYN ratio (0.94, +0.22) and timing variance (+0.11) on 192.168.10.8. The model is weighting the last two windows most heavily. If fan-out had stayed below 12, this would read 0.14."*

**AC1** Deterministic and tested. **AC2** Reads naturally for all five stages. **AC3** Every number in it traces to a named attribution method.

### P4 Definition of Done
- [ ] Real SHAP with additivity test; IG fallback with no hard dependency
- [ ] Temporal + graph attention exported and rendered
- [ ] Actionable counterfactuals
- [ ] Faithfulness + sanity + stability metrics published
- [ ] Deterministic plain-English explanation
- [ ] The `predict.py` disclaimer ("we do not call it SHAP because it is not SHAP") can finally be deleted

---

## P5 — MITRE Engine, Entity Forecasting & Lead Time

**Goal:** technique-level ATT&CK mapping, per-host forecasting, and a **measured lead time > 0**.
**Closes:** G09, G10, G11, G12.
**Exit demo:** "At 14:19 host .8 crossed 0.81 with Reconnaissance/T1046. Ground truth infiltration starts 14:33. Lead: 14 minutes. And we removed this attack family from training entirely."

### P5-T1 · Offline ATT&CK knowledge base
**Files:** `src/trajectory/mitre/` (`tactics.py`, `techniques.py`, `mapping.py`, `navigator.py`), `data/mitre/enterprise-attack-<version>.json`

Pin a reduced STIX snapshot (tactics + ~40 network-observable techniques). Extend every dataset label to technique level (`PortScan` → TA0007/T1046; `FTP-Patator` → TA0006/T1110.001; `Bot` → TA0011/T1071.001; and so on). **Keep the strict unmapped-label abort** — it's one of your best decisions.

**AC1** Every dataset label maps to ≥1 technique with a cited rationale. **AC2** `navigator.export_layer()` produces a layer JSON that loads in the official ATT&CK Navigator — *demo this, it takes 20 seconds and lands hard.* **AC3** ATT&CK version recorded in every export.

### P5-T2 · Learned stage head + hybrid
Train the world model's stage head on dataset-derived labels with class weighting. Combine with rules: `final = argmax(w·learned + (1-w)·rules)`, `w` tuned on validation. Report rules-only / learned-only / hybrid.

**AC1** Stage macro-F1 for all three — **fills the `n/a` in `RESULTS.md`**. **AC2** Confusion matrix rendered. **AC3** `Unknown` stays valid below a documented confidence floor.

### P5-T3 · Relative thresholds (kill the magic numbers)
Replace `bytes > 10_000` with **training-split quantiles** persisted in the artifact bundle.

**AC1** A test greps `STAGE_RULES` for numeric literals > 100 and fails. **AC2** Thresholds fitted train-only, persisted, loaded at inference. **AC3** The same rules fire sensibly on synthetic *and* CIC-IDS2017 without code changes.

### P5-T4 · Entity-level forecasting — the real lead-time fix
**Files:** `src/trajectory/entity_states.py`

**First, diagnose. Don't guess.** `scripts/diagnose_lead_time.py` plots, for the attacker host *and* the network aggregate, each key feature against ground-truth onset, and measures how many windows early each becomes 2σ-separable. **That number is your achievable ceiling.**

The likely finding: network-wide aggregation drowns one slow-scanning host among 5,000 benign flows. The fix is per-host states and per-host forecasts, with network risk = top-3 host mean. This is also better product design — an analyst wants "host X is at risk", not "the network is at 0.6".

**AC1** Diagnostic figure + table committed to `EVALUATION_PLAN.md`. **AC2** Per-host forecasts for every active host. **AC3** Lead measured per host against that host's own onset. **AC4** Median host-level lead reported — **always paired with false-early rate**.

### P5-T5 · Precursor labelling
Decayed horizon labels `y_t = max_k(γ^k · 1[attack at t+k])`, γ≈0.85; lead-weighted positive loss; **treat Reconnaissance as positive for the progression head**. The current strict labelling mathematically forbids early firing — this is the documented root cause and this is its fix.

**AC1** `label_mode: strict | decayed` both evaluated. **AC2** Recon-then-infiltrate scenario yields a positive decayed label at the recon window. **AC3** Lead reported under both modes with false-early rates.

### P5-T6 · Dataset adapters + generalisation
**Files:** `src/trajectory/datasets/` (`ctu13.py`, `unsw_nb15.py`, `lanl_auth.py`, `cic_ids2018.py`)

- **CTU-13** — Argus `.binetflow`; parse the `State` column into flag features; **treat `Background-*` as unlabelled, not benign** (the classic CTU-13 mistake — document your choice). 13 botnet families = ideal for leave-one-out.
- **UNSW-NB15** — `sttl/dttl/swin/dwin/sload/dload` map directly onto the PS's packet features. Use it to prove the packet path on real data.
- **LANL auth** — the PS names authentication logs. **The only dataset here with genuine multi-day dwell time — use it for the lead-time claim.**
- **CIC-IDS2018** — a thin alias over the 2017 adapter (same CICFlowMeter schema).

**Leave-One-Attack-Out:** for each family, remove it entirely from train+validation, test only on it. **This is the direct, measurable answer to "generalise to unseen attack patterns."**

**Cross-dataset transfer:** train CIC-IDS2017 → test CTU-13/UNSW-NB15 zero-shot. Expect a large drop; quantify the distribution shift with your existing PSI code in `drift.py` (nice reuse — it shows the enterprise modules aren't decoration).

**AC1** Four adapters, tested on synthetic schema fixtures, no dataset content committed. **AC2** LOAO table per family, leakage-tested. **AC3** Transfer matrix with PSI-quantified shift. **AC4** Honest publication **including the families where it fails** — 6/9 with an explanation beats a claimed 9/9.

### P5 Definition of Done
- [ ] Offline ATT&CK KB, technique-level mapping, Navigator export
- [ ] Learned + hybrid stage head; macro-F1 published
- [ ] Zero absolute magic thresholds
- [ ] Lead time diagnosed, per-host forecasting, **measured lead > 0 on ≥1 dataset**
- [ ] Four adapters; LOAO and transfer results published honestly
- [ ] Phase A complete — **every problem-statement requirement is now met**

---

# PHASE B — PRODUCTION BACKEND
*Phase A produces intelligence. Phase B makes it durable, scalable, secure and multi-tenant.*

---

## P6 — Data Plane & Persistence

**Goal:** state lives in a real database with migrations, integrity, and backups.
**Exit demo:** kill every container, restart, and every case, incident, forecast and audit record is exactly where it was.

### P6-T1 · Schema design
**Files:** `src/sentinel/db/` (models, session), `alembic/`, `docs/adr/0004-datastore.md`

Core tables (TimescaleDB hypertables marked ⏱):

```
organisations        id, name, slug, tier, created_at, settings jsonb
users                id, org_id, subject (OIDC), email, display_name, role, status
api_keys             id, org_id, key_hash, name, scopes[], expires_at, revoked_at
data_sources         id, org_id, kind, config jsonb, status, last_seen_at
⏱ events_raw         time, org_id, source_id, event_id, payload jsonb        (retention: 7d)
⏱ network_states     time, org_id, window_start, window_end, entity_id NULL,
                     features jsonb, coverage jsonb, feature_version         (retention: 90d)
⏱ forecasts          time, org_id, state_id, model_version, horizon,
                     timeline jsonb, stage, stage_confidence, lead_windows,
                     uncertainty jsonb
⏱ findings           time, org_id, detector, score, confidence, mitre_technique,
                     entity_id, evidence jsonb
incidents            id, org_id, opened_at, closed_at, severity, risk_score,
                     entity_ids[], finding_ids[], stage, status
cases                id, org_id, incident_id, assignee_id, status, sla_due_at,
                     priority, timeline jsonb
explanations         id, org_id, forecast_id, method, base_value,
                     attributions jsonb, computed_at
models               id, org_id NULL, version, kind, checksum, metrics jsonb,
                     status (registered|approved|deployed|rolled_back), approved_by
assets               id, org_id, entity_id, criticality, owner, tags[]
feedback             id, org_id, finding_id, user_id, verdict, signature, created_at
audit_log            id, org_id, actor, action, resource, before, after, at, ip
ledger_entries       id, org_id, seq, payload_hash, prev_hash, at
```

**Every table carries `org_id`. Every query filters on it. Enforce with Postgres Row-Level Security, not just application code** — application-level tenant filtering fails the first time someone forgets a `WHERE`.

**AC1** Full schema in Alembic; `upgrade head` and `downgrade base` both work on an empty and a populated DB.
**AC2** RLS policies on every tenant table. **AC3** A cross-tenant leakage test suite: for every endpoint, org A's token must never see org B's data. *Write this before you write the endpoints.*
**AC4** Hypertables with compression and retention policies configured.

### P6-T2 · Repository layer
Async SQLAlchemy 2.0. **No ORM objects escape the repository** — repositories return Pydantic contracts, so the domain layer never depends on the database. This is what lets you test the domain without a database and swap storage later.

**AC1** `Repository[T]` protocol per aggregate. **AC2** Domain and API layers import zero SQLAlchemy. **AC3** In-memory fake repositories for fast unit tests.

### P6-T3 · Object storage
MinIO/S3 for captures, model artifacts, generated reports. Presigned URLs, server-side encryption, lifecycle rules, per-tenant prefixes.

**AC1** Upload → process → delete lifecycle tested. **AC2** No tenant can presign another tenant's prefix.

### P6-T4 · Backup & recovery
Nightly `pg_dump` + WAL archiving for PITR. **Actually restore it in CI** — an untested backup is not a backup.

**AC1** Documented RPO ≤ 15 min, RTO ≤ 1 h. **AC2** A CI job restores a backup into a scratch DB and runs a smoke query. **AC3** `docs/runbooks/restore.md`.

### P6-T5 · Modular monolith boundaries
```
src/sentinel/
  domain/          pure logic, zero I/O          (the current trajectory/ core moves here)
  application/     use cases, orchestration
  infrastructure/  db, storage, queue, http clients
  interfaces/      api, cli, workers
```
Enforce with `import-linter` in CI: `domain` may not import `infrastructure`; `interfaces` may not import `domain` internals directly.

**AC1** Layer contracts enforced in CI. **AC2** `domain` has no third-party runtime imports beyond pydantic/numpy.

### P6 Definition of Done
- [ ] Postgres+TimescaleDB, full Alembic migrations, up and down tested
- [ ] RLS on every tenant table + cross-tenant leakage suite
- [ ] Repositories return contracts, not ORM rows
- [ ] Object storage with per-tenant isolation
- [ ] Backup restore verified in CI
- [ ] Layer boundaries enforced

---

## P7 — Streaming Ingestion

**Goal:** ingest continuously at production rates without loss, with replay and backpressure.
**Exit demo:** 50,000 events/sec sustained for an hour; kill a consumer mid-stream; restart; zero loss, zero duplicate windows.

### P7-T1 · Event bus + schema registry
Redpanda. Topics: `events.raw` → `events.normalised` → `states.windowed` → `forecasts` → `findings`. Protobuf or Avro schemas in a registry with **backward-compatibility enforcement in CI** — a producer that breaks a consumer must fail the build, not production.

**AC1** Schema evolution test: old consumer reads new producer's messages. **AC2** Partitioning by `(org_id, entity_id)` so a host's events stay ordered. **AC3** DLQ topic for unparseable events with alerting.

### P7-T2 · Event-time windowing with watermarks
The hard, important part. Real telemetry arrives late and out of order.

- Event-time windows with a configurable **allowed lateness** (default 30 s).
- **Watermark** = max observed event time − lateness; a window closes when the watermark passes its end.
- Late arrivals after close → side-output topic + a counter, never silently dropped.
- **Idempotent window keys** `(org_id, entity_id, window_start, feature_version)` so replay can't double-count.

**AC1** Out-of-order test: shuffled input produces identical windows to ordered input. **AC2** Late events are counted and side-outputted. **AC3** Replay from an offset produces byte-identical windows (upsert by idempotent key).

### P7-T3 · Backpressure & flow control
Bounded queues, consumer lag metrics, adaptive batch sizes, **load shedding with an explicit degradation mode** ("sampling at 1:10 — detection sensitivity reduced") surfaced in the UI. Never silently drop.

**AC1** Under 2× capacity, the system degrades measurably and announces it rather than falling over. **AC2** Lag alerting wired. **AC3** Recovery to full fidelity after load drops is automatic and logged.

### P7-T4 · Appliance-mode fallback
Redpanda must be **optional**. In appliance mode, an in-process asyncio queue implements the same `EventBus` protocol. One interface, two implementations.

**AC1** `EventBus` protocol with `RedpandaBus` and `InProcessBus`. **AC2** The full test suite runs against both. **AC3** Appliance mode needs no external broker.

### P7 Definition of Done
- [ ] Redpanda + schema registry + CI compatibility gate
- [ ] Event-time windowing, watermarks, late-arrival handling
- [ ] Idempotent replay, verified byte-identical
- [ ] Backpressure with announced degradation
- [ ] In-process bus keeps appliance mode alive
- [ ] 50k events/sec sustained, documented

---

## P8 — API v2

**Goal:** an API a third party could build a product against.
**Exit demo:** hand someone the OpenAPI spec and a key; they integrate without asking you a question.

### P8-T1 · Design conventions
- `/api/v2/...`, version in the path; v1 deprecated with `Sunset` headers and a 6-month window.
- **Everything async.** No blocking call in a request handler; CPU work goes to workers.
- **RFC 9457 Problem Details** for every error: `type`, `title`, `status`, `detail`, `instance`, plus `trace_id` and `errors[]` for validation. Never a bare 500 with a stack trace.
- **Cursor pagination** (`?cursor=&limit=`), never offset — offset breaks on live-inserting time-series.
- **Filtering/sorting** grammar documented once and applied everywhere.
- **Idempotency-Key** on every POST that creates something.
- **ETag / If-None-Match** on reads; `Retry-After` on 429.
- **Rate limits** per key and per org, with headers.
- Request ID and trace ID on every response.

### P8-T2 · Endpoint surface
```
Auth            POST /auth/token · /auth/refresh · GET /auth/me
Sources         CRUD /data-sources · POST /data-sources/{id}/test
Ingest          POST /events (batch, idempotent) · POST /captures (multipart→S3)
Analysis        POST /analyses (async job for an uploaded PCAP/CSV)
                GET  /analyses/{id} · GET /analyses/{id}/result
States          GET /states?from=&to=&entity= · GET /states/{id}
Forecasts       GET /forecasts?... · GET /forecasts/{id}
                GET /forecasts/{id}/explanation?method=
                GET /forecasts/{id}/counterfactual
Entities        GET /entities · GET /entities/{id}/timeline · /risk
Findings        GET /findings · POST /findings/{id}/feedback
Incidents       GET/POST /incidents · POST /incidents/{id}/status
Cases           CRUD + POST /cases/{id}/transition · /assign · /comment
Models          GET /models · POST /models/{v}/approve · /rollback · /canary
Drift           GET /drift · POST /drift/evaluate
Compliance      GET /compliance/{framework}
Export          GET /export/navigator-layer · /stix · /report.pdf
Realtime        GET /stream (SSE) · WS /ws (bidirectional)
Webhooks        CRUD /webhooks · signed delivery with retry+backoff
Health          /healthz /readyz /livez /metrics
```

### P8-T3 · Realtime
SSE for one-way live updates (simpler, survives proxies, auto-reconnects). WebSocket only where the client must talk back (live investigation, collaborative case notes). Both carry a **resume token** so a reconnect doesn't lose events.

**AC1** SSE reconnect with `Last-Event-ID` resumes without gaps. **AC2** 1,000 concurrent SSE clients on one node. **AC3** Per-connection authz re-checked on resume.

### P8-T4 · Contract testing and fuzzing
**AC1** `schemathesis` fuzzes every endpoint from the OpenAPI spec in CI; zero unhandled 500s. **AC2** OpenAPI has a request and response example for every endpoint. **AC3** A generated TypeScript client is published to the frontend workspace — **the frontend never hand-writes an API type**. **AC4** Breaking-change detection on the spec in CI.

### P8 Definition of Done
- [ ] v2 async, versioned, Problem Details, cursor pagination, idempotency, rate limits
- [ ] Full surface implemented and documented with examples
- [ ] SSE + WS with resume
- [ ] Schemathesis fuzz clean; generated TS client published
- [ ] p99 latency < 200 ms for reads (measured)

---

## P9 — Identity, Multi-Tenancy & Authorization ⭐ *do not compress*

**Goal:** enterprise-grade identity with provably isolated tenants.
**Exit demo:** the cross-tenant leakage suite passes across all 60+ endpoints; a security reviewer reads the authz model in 10 minutes.

### P9-T1 · OIDC + SSO
Keycloak as IdP; SAML bridge for enterprise; keep API keys for machine-to-machine with scopes and expiry. SCIM user provisioning for large customers.

**AC1** Authorization-code + PKCE flow. **AC2** Token refresh and revocation. **AC3** MFA enforceable per org. **AC4** API keys scoped, expiring, rotatable, and never logged.

### P9-T2 · RBAC → ABAC
Roles (viewer / analyst / engineer / admin / owner) as defaults, but the real check is attribute-based: *subject × action × resource × context*. Policies declarative and unit-testable in isolation.

```python
@requires(Permission.FORECAST_READ, resource="forecast")
async def get_forecast(...): ...
```

**AC1** A policy matrix test: every (role × endpoint) pair asserted allow/deny. **AC2** Deny by default — an endpoint without a declared permission fails a CI check. **AC3** Policy decisions are logged with the reason.

### P9-T3 · Tenant isolation, proven
- Postgres RLS with `SET LOCAL app.org_id` per request.
- **Automated cross-tenant test:** for every endpoint, seed org A and org B, authenticate as A, attempt every B resource ID, assert 404 (not 403 — 403 leaks existence).
- Per-tenant object-storage prefixes, per-tenant Redis namespaces, per-tenant Kafka partition keys.
- Per-tenant rate limits and quotas.

**AC1** The cross-tenant suite covers 100% of endpoints and runs in CI. **AC2** A test that *removes* an RLS policy makes the suite fail — proving the suite actually detects leakage.

### P9-T4 · Audit trail
Append-only, tamper-evident (reuse `ledger.py`'s hash chain), covering every authz decision, data access, config change, model promotion and export. Exportable for compliance.

**AC1** Every mutating action produces an audit record with actor, before, after, IP, trace ID. **AC2** Chain verification endpoint + CLI. **AC3** Audit records are immutable at the database level (no UPDATE/DELETE grant).

### P9 Definition of Done
- [ ] OIDC/SAML/SCIM + scoped API keys
- [ ] ABAC with a full policy matrix test, deny-by-default enforced in CI
- [ ] RLS + a cross-tenant suite that is itself proven to detect leaks
- [ ] Tamper-evident audit across all sensitive actions
- [ ] ADR-0005 on the authorization model

---

## P10 — Inference Service & Model Serving

**Goal:** models served by dedicated, warm, observable workers with safe rollout.
**Exit demo:** promote a new model to 5% canary; watch its metrics diverge; auto-rollback; zero user impact.

### P10-T1 · Inference workers
Separate process pool. Models loaded once at startup and kept warm; **request batching** with a max-latency budget (batch up to 32 or 20 ms, whichever first); bounded queues; graceful drain on shutdown.

**AC1** p99 single-window inference < 100 ms; batched throughput > 500 windows/sec/worker. **AC2** Warm start: a new worker is serving within 10 s. **AC3** Graceful drain loses zero in-flight requests.

### P10-T2 · Online feature store
Redis-backed rolling baselines (the per-host history your detectors need), point-in-time correct so training and serving see identical features. **Training/serving skew is the single most common cause of "it worked in the notebook."**

**AC1** A skew test: features computed offline for window W equal features served online for window W, exactly. **AC2** TTL and eviction documented. **AC3** Cold-start behaviour explicit (insufficient history → the existing honest "insufficient evidence" path, never a fabricated score).

### P10-T3 · Canary, shadow and rollback
- **Shadow mode:** new model scores live traffic, results recorded, nothing surfaced. Compare against production for a configurable window.
- **Canary:** route a % of tenants/traffic, compare metrics, auto-rollback on regression against declared guardrails (F1 drop, FPR rise, latency rise).
- **Instant rollback** to the previous approved version, audited.

**AC1** Shadow comparison report generated automatically. **AC2** Canary auto-rollback triggers on a seeded regression in a test. **AC3** Rollback completes in < 30 s and is audited.

### P10-T4 · Resilience
Circuit breakers around model calls; **explicit degraded mode** — if the world model is unavailable, fall back to rule detectors and **say so in the UI and the API response**, never silently. Timeouts everywhere. Bulkheads so one tenant's heavy analysis can't starve another.

**AC1** With the model service down, the system still detects via rules and every response carries a `degraded: true` + reason. **AC2** Chaos test: kill a worker mid-batch, no request lost. **AC3** One tenant saturating analysis doesn't affect another's p99 (bulkhead test).

### P10 Definition of Done
- [ ] Warm, batched, drainable inference workers with measured SLOs
- [ ] Online feature store with a proven zero-skew guarantee
- [ ] Shadow → canary → auto-rollback pipeline
- [ ] Degraded mode is explicit and user-visible
- [ ] Phase B complete — **the backend is production-grade**

---

# PHASE C — THE FRONTEND
*Streamlit got you a demo. It cannot get you a product. This phase builds the analyst console — and it is the difference between "impressive project" and "I would deploy this."*

> **Read `frontend-design` before every sprint in this phase.** The failure mode here is not ugliness, it's genericness: another dark dashboard of identical rounded cards with a bright accent colour. That look is the default, and defaults are invisible.

---

## P11 — Design System & Foundations

**Goal:** a design language derived from *this* product's subject matter, encoded as tokens and components, documented in Storybook.
**Exit demo:** Storybook with 40+ components, a11y-clean, and a one-page design rationale a designer would sign off on.

### P11-T1 · Design direction — decide it deliberately

Before any code, write `docs/design/DIRECTION.md`. Here is a starting proposal that is specific to this product rather than to dashboards in general. **Interrogate it, change it, but don't replace it with a template.**

**The subject.** A defender watching a network they are responsible for, often at 3 a.m., needing to decide *within seconds* whether something is happening and *within minutes* what to do. The material is **time and probability**. Not "data". Not "insights". Time and probability.

**The organising idea: time is the spine.**
Every screen in this product has a horizontal time axis in the same position, at the same scale, synchronised. You scrub time in one place and the whole application moves with you. Most security tools are built out of cards; this one is built out of a timeline. That single decision differentiates the entire interface and it comes from the subject, not from fashion.

**The colour rule: only probability is allowed to be bright.**
The chrome — navigation, panels, tables, labels — is a narrow band of desaturated neutrals. Colour is a *measurement*, reserved for risk encoding, and it uses one perceptually-uniform sequential ramp so that "how red is it" maps monotonically to probability. No decorative gradients. No accent colour on buttons competing with an alert. When everything is quiet, the screen is nearly monochrome; when something is wrong, the colour is unmistakable and it *means* something.

This also solves a real accessibility problem: a single perceptual ramp can be checked for colour-blind safety once, and risk is always double-encoded (colour + position + an explicit numeral), so colour is never the sole carrier.

```
Base (dark)      #0E1116  canvas      #161A21  panel      #1E242D  raised
Base (light)     #FAFAF8  canvas      #FFFFFF  panel      #F0F1EE  raised
Ink              #E6E9EE / #14181E   — primary text per theme
Ink-muted        #8E97A6             — secondary, same in both themes
Hairline         #262C36 / #DFE2E6   — 1px structure, never a shadow
Risk ramp        #3E6C8E → #6FA0B8 → #C9B458 → #D98324 → #B33A3A
                 (0.0 ────────────── 0.5 ────────────── 1.0)
Confirmed        #7A2E2E   — ground truth / realised attack, distinct from forecast
```

Note `Confirmed` is deliberately *outside* the ramp: **observed and forecast must never be confusable**, which is already a core principle of your codebase. Encode it in the palette, not just in a label.

**Typography.** One family with a genuine range, plus a monospace used only where numeric alignment does real work (tables of values, hex, IPs, ports) — not as decoration on labels. Suggested: a grotesque with tight apertures and good small sizes for the interface, and a mono with distinguishable `0/O` and `1/l/I` for data. Avoid the tracked-out all-caps eyebrow above every heading; avoid accenting one word of a headline in a different colour. Set a real type scale and stick to it.

```
Display  28/32  −0.01em    Section  20/28    Body  14/20    Data  13/18 mono tnum
Label    12/16  +0.01em    Micro    11/14    — five sizes, no more
```

**Density.** This is a professional tool used for hours. Default to **compact** density — 28 px table rows, 8 px base spacing unit — with a comfortable mode for presentation and projection. Generous whitespace is correct for a marketing site and wrong here; an analyst wants more rows visible, not more air.

**Motion.** Exactly one orchestrated moment: when a new alert arrives, its row and its point on the timeline resolve together so the eye connects them. Nothing else animates on load. Motion answers actions (open, expand, confirm) and shows what changed. Respect `prefers-reduced-motion` absolutely — some of your users are monitoring at 3 a.m. and motion is fatigue.

**AC1** `DIRECTION.md` written, with a section explaining what was *rejected* and why. **AC2** Reviewed against the generic-AI-design tells; each remaining similarity is a justified choice, in writing.

### P11-T2 · Token system
**Files:** `web/packages/tokens/` — a framework-agnostic source of truth (JSON) compiled to CSS custom properties + TS types.

Colour (semantic, not literal — `--risk-high`, not `--red-500`), spacing (4 px base, 8 px rhythm), radii (**two values only** — a product that uses one radius everywhere reads as templated; use radius to encode hierarchy), elevation (borders and background steps, not soft shadows — shadows on dark UI look muddy), type, motion (durations + easings), z-index scale, breakpoints.

**AC1** Tokens are the only source of colour/spacing values; a lint rule bans hardcoded hex and px in components. **AC2** Light and dark from the same token set. **AC3** Contrast audit: every text/background pair ≥ WCAG AA (4.5:1 body, 3:1 large).

### P11-T3 · Component library
Radix primitives + your own visual layer. Build these (each with all states: default, hover, focus-visible, active, disabled, loading, error, empty):

**Primitives** — Button (4 variants), IconButton, Input, Select, Combobox, DatePicker, DateRangePicker, Checkbox, Radio, Switch, Slider, Textarea, Tooltip, Popover, Dialog, Drawer, Tabs, Accordion, Badge, Avatar, Toast, Skeleton, Spinner, Progress.

**Domain components — this is where the product's identity lives:**
- `<RiskMeter>` — probability with uncertainty band and an explicit numeral
- `<TimeSpine>` — the shared, synchronised time axis every view mounts onto
- `<ProbabilityTimeline>` — observed/forecast split, threshold line, uncertainty band, stage bands
- `<StageBadge>` — MITRE tactic + technique, with confidence and an evidence popover
- `<AttributionWaterfall>` — SHAP contributions
- `<AttentionHeatmap>` — temporal attention
- `<HostGraph>` — force-directed, attention-weighted, WebGL for >500 nodes
- `<FlowTable>` — virtualised, column-configurable, keyboard-navigable
- `<EvidencePanel>` — the feature values behind a claim, linked to the glossary
- `<DegradedBanner>` — the honest "we are running without X" surface
- `<ObservedForecastLegend>` — a persistent, unmissable distinction

**AC1** Every component in Storybook with all states and an interaction test. **AC2** `@axe-core` a11y check per story in CI, zero violations. **AC3** Every interactive component is fully keyboard-operable, verified in Playwright. **AC4** No component imports a token value by literal.

### P11-T4 · Content design
A `docs/design/VOICE.md`: active voice, sentence case, the button that says "Acknowledge" produces a toast that says "Acknowledged". Errors explain what happened and what to do, in the interface's voice, and never apologise. Empty states invite an action. A glossary of every domain term as it will appear in the UI — and it must match `FeatureRegistry` from P1-T6, so the tooltip on `dst_port_entropy` is generated from the same source as the docs.

**AC1** Voice guide written. **AC2** Every empty and error state in the component library has real copy, not lorem. **AC3** Feature tooltips generate from `FeatureRegistry` — one source, no drift.

### P11 Definition of Done
- [ ] `DIRECTION.md` with an explicit, defended point of view
- [ ] Token system, light+dark, contrast-audited, lint-enforced
- [ ] 40+ components in Storybook, all states, a11y-clean, keyboard-complete
- [ ] Domain components that encode the product's core distinctions
- [ ] Voice guide + generated glossary

---

## P12 — Application Shell

**Goal:** the frame — routing, auth, navigation, layout, and the keyboard-first interaction model.
**Exit demo:** navigate the entire application without touching the mouse.

### P12-T1 · Next.js foundation
App Router, TypeScript strict, server components for data-heavy reads, the **generated API client from P8-T4** (never hand-written types), TanStack Query for server cache, Zustand for UI state only. Route groups: `(auth)`, `(app)`, `(admin)`.

**AC1** Strict TS, zero `any` (enforced). **AC2** Types generated from OpenAPI in CI; a spec change that breaks the frontend fails the build. **AC3** SSR for first paint on data views.

### P12-T2 · Auth flows
OIDC redirect, silent refresh, session expiry warning with extend, org switcher for multi-org users, deep-link preservation through login.

**AC1** Expiry never loses unsaved work — warn, offer extend, preserve state. **AC2** Deep links survive the auth round trip. **AC3** Logout clears all client caches (test it — a stale TanStack cache after logout is a real data-exposure bug).

### P12-T3 · Navigation and layout
Persistent left rail (icon + label, collapsible), the **TimeSpine pinned globally** so time context never resets when you change view, a context bar showing the current org/source/time range, and a right-hand inspector drawer that opens for the selected object without leaving the view.

**Views:** Overview · Live · Forecasts · Investigate · Entities · Cases · Explain · Models · Data Sources · Settings · Admin.

**AC1** Time range and selection persist across navigation. **AC2** Layout is stable — no cumulative layout shift (CLS < 0.05). **AC3** Deep-linkable state: every view's filters, time range and selection live in the URL, so an analyst can paste a link into a ticket and a colleague sees exactly the same screen. *This is the single most requested feature in every security tool and most of them don't have it.*

### P12-T4 · Keyboard-first
A command palette (`⌘K`) that reaches every action and every entity. Vim-adjacent navigation in tables (`j/k`, `Enter`, `Esc`). Global shortcuts: `g` then a letter for views, `/` to search, `?` for the shortcut sheet. Focus management on every dialog and drawer.

**AC1** Playwright test completes a full investigation workflow keyboard-only. **AC2** Focus is never lost or trapped; visible focus ring everywhere. **AC3** Shortcut reference is discoverable and complete.

### P12 Definition of Done
- [ ] Next.js + strict TS + generated client
- [ ] Complete auth flows with no work loss
- [ ] Global TimeSpine and persistent context
- [ ] Fully deep-linkable state
- [ ] Keyboard-complete, Playwright-verified

---

## P13 — Core Analyst Surfaces ⭐ *do not compress*

**Goal:** the screens where the work happens.
**Exit demo:** hand the console to a real SOC analyst with no training; they find the attack and explain it back to you.

### P13-T1 · Overview — "is anything happening?"
Answerable in **under three seconds** from across a room. Not a wall of KPI cards.

- One large **risk trajectory** across the selected window — the network's probability over time with the uncertainty band, the threshold, and forecast horizon extending past "now" as a distinct visual region.
- **Top entities at risk** — ranked, sparkline each, current stage, trend arrow. Not a pie chart.
- **Open incidents** with time-in-state and SLA pressure.
- **Coverage & health** — which sources are live, gaps, degraded modes. Honest by default.
- Everything clicks through to the filtered view; nothing is a dead end.

**AC1** A new user answers "is anything wrong?" in < 3 s (usability-tested with 5 people). **AC2** Loads in < 1.5 s on a cold cache. **AC3** Quiet network → visibly quiet screen. No dashboard theatre.

### P13-T2 · Live — the monitoring surface
Streaming via SSE. New windows slide in on the TimeSpine. Alerts resolve as one orchestrated motion (row + timeline point together). Detector grid with per-detector confidence and explicit insufficient-telemetry states — **surface your honesty here; it's a feature**. Pause/resume without losing buffered events. Density toggle for wall-display mode.

**AC1** 60 fps with 100 windows/min. **AC2** Pause holds position; resume catches up without gaps. **AC3** Insufficient-telemetry is visually distinct from "low risk" — they are completely different claims and most tools conflate them.

### P13-T3 · Investigate — the workspace
The screen an analyst lives in during an incident.

- Left: the entity/incident in context with its full history.
- Centre: synchronised **multi-track timeline** — probability, stage, detector firings, raw flow volume, auth events — all on the same time axis, brush to zoom, everything else follows.
- Right: inspector for the selected moment — features, evidence, explanation.
- Bottom: virtualised flow table, filterable, exportable, with saved views.
- Actions: acknowledge, assign, escalate, add note, mark verdict — all keyboard-reachable, all audited.

**AC1** 100k-row flow table scrolls at 60 fps (virtualised). **AC2** Brushing one track moves all tracks within one frame. **AC3** Every action produces an audit record visible in the case timeline. **AC4** State is deep-linkable to the exact moment and selection.

### P13-T4 · Explain — where trust is earned
For any forecast: SHAP waterfall, temporal attention heatmap, host graph with attention-weighted edges, the counterfactual, and the deterministic plain-English sentence — **plus the method label on every number**.

Include an **"is this explanation trustworthy?"** panel showing the faithfulness metrics from P4-T4. Nobody does this. It is the most credible thing you can put in front of a sceptical security engineer.

**AC1** Every attribution displays its method. **AC2** Faithfulness metrics visible, with a plain explanation of what they mean. **AC3** A hover on any feature shows its `FeatureRegistry` definition and valid range. **AC4** Explanations load in < 500 ms (cached) / < 3 s (cold, with progress).

### P13-T5 · Cases
Kanban by status plus a table view, SLA countdown, assignment, comments with @mentions, an immutable timeline of everything that happened, attached evidence, and one-click report export.

**AC1** Full lifecycle with SLA. **AC2** Timeline is immutable and complete. **AC3** Report export contains the forecast, the evidence, the explanation, and the analyst's verdict.

### P13 Definition of Done
- [ ] Five surfaces, each solving one clearly-stated analyst question
- [ ] Multi-track synchronised timeline as the core interaction
- [ ] Explanation surface including explanation-quality metrics
- [ ] Usability-tested with ≥5 people who did not build it
- [ ] Every performance budget met

---

## P14 — Real-Time & Visualization Engine

**Goal:** the visualisations are fast, correct, and genuinely readable at production data volumes.
**Exit demo:** a 5,000-node host graph and a 500k-point timeline, both interactive at 60 fps.

### P14-T1 · Timeline engine
Canvas/WebGL rendering with downsampling (LTTB — preserves visual shape, unlike naive decimation), progressive detail on zoom, brush-and-link across tracks, and a shared scale so tracks are always comparable.

**AC1** 500k points, 60 fps pan/zoom. **AC2** Downsampling never hides a spike (tested: inject a one-point spike, assert it survives at every zoom). **AC3** Synchronised cursor across all tracks.

### P14-T2 · Graph canvas
deck.gl/WebGL force-directed graph. Attention-weighted edges, node size by risk, colour by the risk ramp, clustering above 500 nodes, focus+context (neighbourhood expansion rather than showing everything), and a deterministic layout seed so the same window always draws the same way — **an analyst builds spatial memory of their network, and a graph that re-scrambles every render destroys it.**

**AC1** 5,000 nodes / 20,000 edges at 60 fps. **AC2** Deterministic layout. **AC3** Keyboard-navigable (tab through nodes, expand with Enter) — graphs are usually a total accessibility failure; don't be usual.

### P14-T3 · Streaming client
SSE with resume tokens, exponential backoff, offline detection and a queued-updates indicator, and reconciliation with TanStack Query cache so live and fetched data never disagree.

**AC1** Survives network interruption without data loss or duplication. **AC2** Reconnect state is visible, never silent. **AC3** Memory is bounded under a 24-hour session (test it — leaking streaming clients are the classic long-session bug).

### P14-T4 · Export and reporting
PNG/SVG of any chart, CSV/Parquet of any table, PDF analyst report, ATT&CK Navigator layer, STIX 2.1 bundle. All generated server-side for consistency.

**AC1** Exports are pixel-accurate to the screen. **AC2** The PDF report is presentable to an executive without editing. **AC3** Navigator layer loads in the official tool.

### P14 Definition of Done
- [ ] Timeline and graph engines hitting their frame budgets at scale
- [ ] Spike-preserving downsampling, proven
- [ ] Robust streaming with bounded memory
- [ ] Full export suite

---

## P15 — UX Completion & Polish

**Goal:** the 20% of work that determines whether people keep using it.
**Exit demo:** a full accessibility, performance and usability audit, all green.

### P15-T1 · Every state, everywhere
For every view and component: loading (skeleton matched to real layout, not a spinner), empty (explains what will appear and how to make it appear), error (what happened, what to do, a retry), partial (some sources down — say which), degraded (reduced fidelity — say why), no-permission (explains what access is needed and who grants it).

**AC1** A state matrix in Storybook covering every view × every state. **AC2** Zero raw error strings reach a user. **AC3** Every empty state offers an action.

### P15-T2 · Onboarding
First-run: connect a source or load the sample capture, a 60-second guided tour that can be skipped and resumed, contextual help linked to the docs, and a **sample dataset mode** so a new user sees a populated product immediately instead of an empty one.

**AC1** A new user reaches a meaningful screen in < 5 minutes. **AC2** The tour is skippable, resumable, and never modal-blocking. **AC3** Sample mode is unmistakably labelled as sample data.

### P15-T3 · Accessibility to WCAG 2.2 AA
Full keyboard operation, correct semantics and ARIA, screen-reader tested (NVDA + VoiceOver) on the primary flows, contrast verified, `prefers-reduced-motion` respected, 200% zoom without loss of function, and **no meaning carried by colour alone** — which your risk ramp already handles via double encoding.

**AC1** axe-core clean in CI on every route. **AC2** Manual screen-reader pass documented for the five core flows. **AC3** A VPAT drafted — enterprise and government procurement will ask for it.

### P15-T4 · Performance budgets, enforced
| Metric | Budget |
|---|---|
| LCP | < 1.5 s |
| INP | < 200 ms |
| CLS | < 0.05 |
| JS bundle (initial route) | < 250 KB gzip |
| Time to interactive | < 2.0 s |
| Frame rate during interaction | ≥ 55 fps p95 |

**AC1** Lighthouse CI fails the build on a budget breach. **AC2** Route-level code splitting; the graph/WebGL bundle loads only where used. **AC3** Real-user monitoring wired (P16).

### P15-T5 · Responsive and cross-device
Desktop-first (this is a professional tool) but: a genuinely usable tablet layout for incident response away from a desk, a read-only mobile view for on-call triage (see the alert, acknowledge, escalate — not a cramped version of the full console), and a wall-display mode with large type and no chrome for the SOC screen.

**AC1** Three layouts tested on real devices. **AC2** Mobile is a purpose-built triage view, not a squeezed desktop. **AC3** Wall mode is legible at 3 metres.

### P15 Definition of Done
- [ ] Complete state matrix, no raw errors
- [ ] Onboarding with sample mode
- [ ] WCAG 2.2 AA verified, VPAT drafted
- [ ] Performance budgets enforced in CI
- [ ] Desktop / tablet / mobile-triage / wall modes
- [ ] Phase C complete — **the product is usable by someone who didn't build it**

---

# PHASE D — HARDENING

---

## P16 — Observability & SRE

**Goal:** you know it's broken before a customer tells you, and you know why within minutes.
**Exit demo:** inject a fault; the alert fires, the trace points at the cause, the runbook resolves it.

### P16-T1 · OpenTelemetry end to end
Traces from browser click → API → queue → worker → model → database, with one trace ID visible in the UI. Structured JSON logs with trace correlation, **PII redaction** (IPs may be personal data under GDPR — decide and document your position), and RED metrics (Rate/Errors/Duration) on every service plus domain metrics (windows/sec, forecasts/sec, model latency, queue depth, detection rate).

**AC1** A single trace ID follows a request across every hop. **AC2** No PII in logs (automated scan). **AC3** Every service exports RED metrics.

### P16-T2 · SLOs and error budgets
| SLO | Target |
|---|---|
| API availability | 99.9% |
| API read latency p99 | < 200 ms |
| Ingest→forecast end-to-end p95 | < 30 s |
| Event loss rate | < 0.01% |
| UI LCP p75 | < 1.5 s |

Burn-rate alerts (fast + slow window), not threshold spam. **Alert on symptoms, not causes** — "forecasts are late" not "CPU is 80%".

**AC1** SLOs defined with error budgets and a documented policy for what happens when one is exhausted. **AC2** Every alert links to a runbook. **AC3** Zero alerts without an owner and an action.

### P16-T3 · Runbooks and on-call
`docs/runbooks/` — one per alert: symptom, likely causes, diagnostic commands, remediation, escalation. Plus a game day: simulate an outage and time the response.

**AC1** A runbook per alert. **AC2** Game day run, MTTR recorded, gaps fixed. **AC3** On-call rotation and escalation documented.

### P16-T4 · Real-user monitoring & product analytics
Core Web Vitals from real sessions, frontend error tracking with source maps, and **privacy-respecting** usage analytics (self-hosted, no third-party trackers, opt-out honoured — your Streamlit app already has an analytics opt-out; keep that principle).

**AC1** RUM dashboards live. **AC2** Frontend errors are actionable with source maps. **AC3** Analytics are self-hosted and disclosed.

### P16 Definition of Done
- [ ] Distributed tracing across every hop
- [ ] SLOs with burn-rate alerting and error-budget policy
- [ ] A runbook per alert; game day completed
- [ ] RUM + error tracking + privacy-respecting analytics

---

## P17 — Security Hardening ⭐ *do not compress*

**Goal:** a security product that would survive its own threat model and a third-party penetration test.
**Exit demo:** a clean external pen-test report and a signed, SBOM-attested release.

### P17-T1 · Threat model, properly
Extend `THREAT_MODEL.md` with STRIDE per component, an explicit trust-boundary diagram, and — critically — **adversarial ML threats**: model evasion, data poisoning through the analyst feedback path, model extraction via the API, and inference-time adversarial inputs. You have a `feedback.py` with a deliberate no-auto-retrain policy; that decision is a poisoning mitigation and deserves to be named as one in the threat model.

**AC1** STRIDE per component with mitigations and residual risk. **AC2** Adversarial-ML threats enumerated with mitigations. **AC3** Reviewed by someone outside the team.

### P17-T2 · Application security
OWASP ASVS L2 as the target. Input validation at every boundary (Pydantic gets you most of this). Output encoding. **Parameterised queries only** — a lint rule banning string-built SQL. CSRF on cookie flows. Strict CSP with nonces, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`. Secure cookie flags. Per-endpoint rate limits. File upload: type sniffing, size caps, **PCAP parsing in a sandboxed subprocess with resource limits** — a malicious PCAP crafted to exploit a parser is a completely realistic attack on *this specific product*, and Scapy is not a hardened parser.

**AC1** ASVS L2 checklist completed with evidence. **AC2** CSP with no `unsafe-inline`. **AC3** PCAP parsing is sandboxed with CPU/memory/time limits; fuzzed with malformed captures. **AC4** SAST (bandit + semgrep) and DAST (ZAP) in CI, zero highs.

### P17-T3 · Supply chain
SBOM (syft) per release, vulnerability scan (grype/trivy) with a documented severity SLA, signed container images (cosign), pinned dependencies with hash verification, `gitleaks` in pre-commit and CI, and a dependency-update policy with automated PRs.

**AC1** SBOM published with every release. **AC2** Zero critical/high CVEs in shipped images; medium tracked with dates. **AC3** Images signed, signature verified at deploy. **AC4** No secret has ever been committed (full history scan).

### P17-T4 · Secrets, crypto and data protection
No secrets in env files in production — a secret manager (Vault/cloud KMS) with rotation. TLS 1.3 everywhere including internal hops. Encryption at rest for database and object store. Documented data retention and deletion, GDPR/DPDP subject-access and erasure procedures, and a decision recorded on whether IP addresses are personal data in your jurisdictions.

**AC1** Secret rotation tested without downtime. **AC2** mTLS between internal services. **AC3** Data retention enforced automatically, deletion verified.

### P17-T5 · Hardening and penetration test
Distroless or minimal base images, non-root, read-only root filesystem, dropped capabilities, seccomp profiles, network policies (default deny), resource limits. Then commission a **third-party pen test** and fix everything before GA.

**AC1** Containers pass CIS benchmarks. **AC2** Default-deny network policy. **AC3** External pen test completed; all high/critical remediated and retested. **AC4** `SECURITY.md` with a disclosure policy and response SLA.

### P17 Definition of Done
- [ ] STRIDE + adversarial-ML threat model, externally reviewed
- [ ] ASVS L2 evidenced; sandboxed, fuzzed PCAP parsing
- [ ] SBOM, signed images, zero high CVEs, clean secret history
- [ ] Secret management, mTLS, encryption at rest, data-rights procedures
- [ ] Hardened containers, third-party pen test passed
- [ ] `SECURITY.md` published

---

## P18 — Performance, Scale & Resilience

**Goal:** known limits, graceful degradation, and proven recovery.
**Exit demo:** a capacity model backed by load tests, and a chaos run the system survives.

### P18-T1 · Load and capacity
k6 scenarios: steady state, peak, sustained soak (24 h), and spike. Profile and fix the top bottlenecks. Publish a **capacity model**: "one node handles X events/sec, Y concurrent analysts, Z tenants" — so sales and ops stop guessing.

**AC1** Load test suite in CI (nightly). **AC2** Capacity model published with the measurements behind it. **AC3** 24 h soak with no memory growth or connection leak.

### P18-T2 · Scaling
Stateless API and workers → horizontal scaling. HPA on queue depth and latency (not CPU — CPU is a lagging indicator for queue-driven work). Connection pooling with PgBouncer. Read replicas for analytics queries. Partition/shard strategy documented for the largest tenants.

**AC1** Linear scaling to 10 nodes, measured. **AC2** Autoscaling responds in < 60 s. **AC3** Database connections bounded under maximum scale-out.

### P18-T3 · Resilience and chaos
Kill pods, partition the network, saturate the disk, add 500 ms of database latency, kill the broker. The system must degrade visibly and recover automatically. Timeouts, retries with jitter, circuit breakers, bulkheads, and idempotent consumers throughout.

**AC1** Chaos suite runs in staging; every scenario recovers automatically. **AC2** Degradation is always announced, never silent. **AC3** No retry storm under failure (jittered backoff verified).

### P18-T4 · Disaster recovery
Documented and **rehearsed**: RTO 1 h, RPO 15 min. Cross-region backup replication. A full restore drill, timed, at least once.

**AC1** DR runbook written. **AC2** Full restore drill completed and timed. **AC3** Backup integrity verified continuously, not just on creation.

### P18 Definition of Done
- [ ] Load-tested with a published capacity model
- [ ] Horizontal scaling proven; autoscaling tuned
- [ ] Chaos suite green; all degradation announced
- [ ] DR rehearsed within RTO/RPO

---

# PHASE E — MLOPS & GENERAL AVAILABILITY

---

## P19 — MLOps Lifecycle

**Goal:** models improve continuously and safely, with humans in the loop and full reproducibility.
**Exit demo:** drift detected → retraining triggered → evaluation gate → human approval → canary → promotion, end to end, all audited.

### P19-T1 · Experiment tracking and reproducibility
MLflow (self-hostable, works air-gapped) or a lightweight equivalent. Every run records: git SHA, data version, config, seed, environment, metrics, artifacts. **Data versioning** (DVC or content-hash manifests) so "which data trained this model" is always answerable.

**AC1** Any historical run reproduces to within floating-point tolerance. **AC2** Every model in the registry links to its exact run, data version and config. **AC3** `make reproduce` regenerates every published number and fails on drift.

### P19-T2 · Automated evaluation gates
No model is promotable unless it passes, automatically: minimum F1/PR-AUC, maximum FPR, calibration (ECE below a bound), **fairness across tenants** (no tenant's detection rate materially worse — an important and unusual check), latency budget, LOAO generalisation floor, and explanation faithfulness (from P4-T4). Any gate failure blocks promotion with a reason.

**AC1** Gates run automatically on every candidate. **AC2** A seeded regression is blocked by the gate in a test. **AC3** Gate results are attached to the model record permanently.

### P19-T3 · Drift → retrain loop, with a human
Your PSI monitoring already exists. Wire it: drift above threshold → alert → automatic candidate retraining → evaluation gates → **explicit human approval** → shadow → canary → promote. **Never auto-promote.** Never auto-retrain from analyst feedback without review — that is a poisoning vector and your existing `feedback.py` policy is correct; formalise it as a reviewed queue.

**AC1** The full loop runs end to end in staging. **AC2** Human approval is mandatory and audited. **AC3** Feedback-driven retraining requires review; a test asserts no path bypasses it.

### P19-T4 · Model cards and governance
A `MODEL_CARD.md` per released model: intended use, training data and its provenance, evaluation results including failures, known limitations, out-of-scope uses, ethical considerations, and the LOAO/transfer numbers. Plus a model inventory for AI-governance requirements (EU AI Act classification, if relevant to your customers).

**AC1** A model card ships with every released model. **AC2** Limitations section is specific, not boilerplate. **AC3** Model inventory maintained for governance.

### P19 Definition of Done
- [ ] Experiment tracking + data versioning; historical runs reproduce
- [ ] Automated promotion gates including fairness and faithfulness
- [ ] Drift→retrain→approve→canary loop with mandatory human approval
- [ ] Model cards and governance inventory

---

## P20 — General Availability

**Goal:** ship it — installable, documented, supported, and legally clean.
**Exit demo:** someone outside your organisation installs it from published artifacts and reaches a working system using only the docs.

### P20-T1 · Packaging and deployment
- **Helm chart** for Kubernetes: configurable, with sane defaults, HA, PDBs, resource requests, upgrade path, and `helm test` hooks.
- **Appliance bundle**: single-node Docker Compose (or a signed OVA/installer) that runs fully air-gapped with bundled models. **This is your differentiator for CII — treat it as a first-class release artifact, not a dev convenience.**
- Blue/green or rolling deploy with automated smoke tests and one-command rollback.
- Semantic versioning, a real `CHANGELOG.md`, a documented upgrade and migration path between minor versions.

**AC1** Both deployment shapes install from published artifacts. **AC2** Upgrade from N-1 to N tested with data preserved. **AC3** Rollback tested. **AC4** Air-gapped install verified on a genuinely disconnected machine.

### P20-T2 · Documentation site
Docusaurus or Nextra. Four distinct audiences, four distinct sections — do not merge them:
- **Analyst guide** — how to investigate, what the numbers mean, the feature glossary (generated from `FeatureRegistry`)
- **Administrator guide** — install, configure, connect sources, manage users, backup, upgrade
- **Developer/API reference** — generated from OpenAPI, with runnable examples and client libraries
- **Concepts** — how the world model works, what lead time means, what the limitations are

Plus: a quickstart that works in under 10 minutes, troubleshooting, and a genuinely candid limitations page.

**AC1** Someone outside the team installs and operates it from the docs alone. **AC2** API reference generated, never hand-maintained. **AC3** Every code sample in the docs is tested in CI.

### P20-T3 · Legal, licensing and compliance
Apache-2.0 confirmed for the core. Decide and document the open-core boundary if there is one. Third-party attributions complete. Dataset licences and citations correct. Privacy policy, DPA template, and the compliance mappings you already have (`compliance.py` → NIST CSF / ISO 27001 / SOC 2) with **gaps listed honestly** — you already do this, keep doing it.

**AC1** Legal review completed. **AC2** All attributions and citations correct. **AC3** Compliance mappings state what is *not* covered.

### P20-T4 · Support and operations readiness
Support tiers and SLAs, an escalation path, a status page, a customer-facing incident communication template, a diagnostic bundle collector (`sentinel support-bundle` — logs, config, versions, health, **with secrets redacted**), and a defined release cadence with an LTS policy.

**AC1** Support bundle collects everything needed for diagnosis and leaks nothing. **AC2** Status page live. **AC3** Release cadence and LTS published.

### P20-T5 · Launch
- Final claim audit — every statement in every public artifact traced to evidence.
- Launch checklist signed off: security, performance, docs, legal, support, monitoring, rollback.
- A beta with 3–5 real users before GA. **Their feedback is worth more than another sprint of features.**
- Post-launch: a 30-day watch with daily SLO review.

**AC1** Claim audit complete, zero unbacked claims. **AC2** Launch checklist signed by an owner per area. **AC3** Beta feedback triaged; blockers fixed before GA.

### P20 Definition of Done
- [ ] Helm chart + air-gapped appliance bundle, both installable from published artifacts
- [ ] Upgrade and rollback tested with data preservation
- [ ] Four-audience documentation site; docs-only install verified externally
- [ ] Legal, licensing, privacy and compliance complete and honest
- [ ] Support tooling and process live
- [ ] Beta completed, claim audit clean, **GA**

---

# PART 4 — DESIGN SYSTEM & UX SPECIFICATION

*Reference material for P11–P15. Keep this file and `docs/design/DIRECTION.md` in sync.*

## 4.1 The five design rules, in priority order

1. **Observed and forecast are never confusable.** Different line style, different colour family, an explicit divider at "now", and a persistent legend. This is already a core principle of your codebase; make it a visual law.
2. **Insufficient evidence is not low risk.** Your detectors already distinguish these honestly. The UI must too — a distinct visual treatment (hatched/neutral, never a low value on the risk ramp) and a plain-language reason.
3. **Only probability is bright.** Chrome is neutral; colour is a measurement.
4. **Every number names its method.** No attribution, score or probability appears without the model version and method that produced it, reachable in one interaction.
5. **Time is shared.** One time context across the whole application; changing it anywhere changes it everywhere.

## 4.2 Risk encoding — the one thing to get exactly right

| Band | Probability | Ramp position | Also encoded by |
|---|---|---|---|
| Quiet | 0.00 – 0.25 | cool | numeral, low bar |
| Elevated | 0.25 – 0.50 | cool-mid | numeral, bar height |
| Concerning | 0.50 – 0.75 | warm-mid | numeral, bar, subtle border |
| Critical | 0.75 – 1.00 | hot | numeral, bar, border, icon |
| **Insufficient** | — | **outside ramp** | hatched fill + reason text |
| **Confirmed** | ground truth | **`#7A2E2E`, outside ramp** | solid marker + "OBSERVED" label |

Colour is **never** the only carrier. Verify with a colour-blindness simulator and with a greyscale screenshot — if the greyscale version is unreadable, the design is wrong.

## 4.3 Component API conventions

```tsx
// Every domain component takes the contract, not loose props.
<ProbabilityTimeline
  forecast={forecast}          // the Forecast contract from the API
  threshold={0.4}
  showUncertainty
  onBrush={(range) => ...}     // handlers named on<Event>
  density="compact"            // compact | comfortable
/>
```
- Props mirror API contract names exactly. Renaming between layers is where bugs live.
- Every component accepts `className` and forwards `ref`.
- Loading/empty/error are **props or children**, never internal assumptions.
- No component fetches its own data; containers fetch, components render.

## 4.4 The eleven screens and the one question each answers

| Screen | The question | The answer's shape |
|---|---|---|
| Overview | Is anything happening? | One trajectory + ranked entities |
| Live | What is happening right now? | Streaming timeline + detector grid |
| Forecasts | What is about to happen? | Forecast list with lead time and stage |
| Investigate | What happened to *this* host? | Multi-track synchronised timeline |
| Entities | Which assets are at risk? | Ranked inventory with trend |
| Cases | What do I need to work on? | Kanban + SLA |
| Explain | Why does it think that? | SHAP + attention + counterfactual + faithfulness |
| Models | Which model is running, and is it healthy? | Registry, drift, canary state |
| Data Sources | Am I seeing everything? | Coverage, gaps, health |
| Settings | — | Org, users, thresholds, retention |
| Admin | — | Tenants, keys, audit, compliance |

## 4.5 What to avoid (from the design-direction calibration)

These read as generic regardless of subject. If you find one in your UI, it arrived by default rather than by decision:
- A grid of identical rounded cards with the same soft grey shadow.
- One border radius on everything regardless of hierarchy.
- Tracked-out ALL-CAPS eyebrow labels above every heading.
- A single bright acid accent on near-black.
- Gradient washes used as decoration.
- Monospace for small labels (as opposed to for numeric data, where it does real work).
- `→` appended to every link and button.
- Fade-and-slide-up entrance animation on every section.
- Meta strings joined with middle dots.

---

# PART 5 — BACKEND SPECIFICATION

## 5.1 Service decomposition (extract only when data says to)

| Service | Extract when | Scales on |
|---|---|---|
| `api` | — (always separate) | request rate |
| `ingest-worker` | P7 | broker lag |
| `feature-worker` | P7 | window backlog |
| `inference-worker` | P10 | queue depth |
| `explain-worker` | P10 | explanation queue (slow, bursty — isolate it) |
| `scheduler` | P19 | n/a (singleton, leader-elected) |

Everything else stays in the modular monolith until measurements justify a split.

## 5.2 Error contract (RFC 9457) — one shape, everywhere

```json
{
  "type": "https://docs.sentinel.io/errors/insufficient-history",
  "title": "Insufficient history for forecast",
  "status": 422,
  "detail": "Entity 192.168.10.8 has 2 windows of history; 8 are required.",
  "instance": "/api/v2/forecasts",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "errors": [{"field": "entity_id", "code": "insufficient_history", "meta": {"have": 2, "need": 8}}]
}
```
Note this example is your *honest* behaviour expressed as an API contract: insufficient evidence gets its own error type with machine-readable context, so the UI can render the right thing instead of showing a fabricated zero.

## 5.3 Data retention defaults (per-tenant configurable)

| Data | Default | Rationale |
|---|---|---|
| Raw events | 7 days | Volume; forensics window |
| Network states | 90 days | Trend analysis, drift baselines |
| Forecasts | 1 year | Post-incident review |
| Findings | 1 year | — |
| Incidents/Cases | 7 years | Regulatory in many CII sectors |
| Audit log | 7 years | Immutable |
| Uploaded captures | 30 days or on-demand delete | Privacy-sensitive |
| Explanations | Same as forecasts | Must survive as long as the claim |

## 5.4 Backpressure policy

| Load | Behaviour | Announced? |
|---|---|---|
| < 80% | Full fidelity | — |
| 80–100% | Prioritise by asset criticality | Yes, status indicator |
| 100–150% | Sample at 1:2, widen windows | Yes, banner + API `degraded` flag |
| > 150% | Sample at 1:10, rules-only detection | Yes, banner + alert + audit record |

**Never drop silently.** Every degradation is visible in the UI, flagged in API responses, counted in metrics, and recorded.

---

# PART 6 — NON-FUNCTIONAL TARGETS

| Category | Target | Verified by |
|---|---|---|
| **Availability** | 99.9% | SLO monitoring, error budget |
| **API read p99** | < 200 ms | k6 + RUM |
| **Ingest→forecast p95** | < 30 s | end-to-end trace |
| **Inference p99** | < 100 ms/window | benchmark suite |
| **Throughput** | 50k events/sec/node | load test |
| **Event loss** | < 0.01% | reconciliation counter |
| **UI LCP p75** | < 1.5 s | Lighthouse CI + RUM |
| **UI INP p75** | < 200 ms | RUM |
| **Frame rate** | ≥ 55 fps p95 | Playwright performance traces |
| **Test coverage** | ≥ 80% overall, ≥ 90% on `domain/` | CI gate |
| **Critical CVEs** | 0 in shipped images | grype in CI |
| **Accessibility** | WCAG 2.2 AA | axe + manual SR pass |
| **RTO / RPO** | 1 h / 15 min | rehearsed DR drill |
| **Cold-start install** | < 10 min | external verification |
| **Model reproducibility** | exact to fp tolerance | `make reproduce` |

---

# PART 7 — DEFINITION OF PRODUCTION READY

Sign-off requires all of these. One owner per section, named.

### Functional
- [ ] Every problem-statement requirement met **and tested** (Phase A)
- [ ] World model proven to learn dynamics (prior beats persistence)
- [ ] Real SHAP with additivity verified; attention exported
- [ ] Technique-level MITRE mapping; Navigator export
- [ ] Measured lead time > 0, reported with false-early rate
- [ ] Generalisation tested via LOAO and cross-dataset transfer

### Engineering
- [ ] All state in Postgres with migrations, backups, and a rehearsed restore
- [ ] Streaming ingest with replay, watermarks, and announced backpressure
- [ ] API v2 versioned, documented, fuzz-clean, with a generated client
- [ ] Tenant isolation enforced by RLS and proven by a leakage suite
- [ ] Models served warm, batched, with shadow→canary→rollback
- [ ] ≥80% coverage; `make gate` green on all supported versions

### Experience
- [ ] Design system with a defended point of view, in Storybook
- [ ] All five core surfaces, usability-tested externally
- [ ] Deep-linkable state; keyboard-complete
- [ ] WCAG 2.2 AA; VPAT drafted
- [ ] Performance budgets enforced in CI

### Operations
- [ ] Distributed tracing; SLOs with error budgets; a runbook per alert
- [ ] Game day and DR drill completed within targets
- [ ] Capacity model published
- [ ] Chaos suite green; all degradation announced

### Security
- [ ] STRIDE + adversarial-ML threat model, externally reviewed
- [ ] ASVS L2; sandboxed and fuzzed PCAP parsing
- [ ] SBOM, signed images, zero high CVEs, clean secret history
- [ ] Third-party pen test passed and retested
- [ ] `SECURITY.md` with a disclosure SLA

### Governance
- [ ] Model cards with honest limitations
- [ ] Promotion gates including fairness and faithfulness
- [ ] Human approval mandatory for every promotion
- [ ] Data retention, deletion and subject-rights procedures operational
- [ ] Claim audit clean across every public artifact

---

# PART 8 — APPENDICES

## 8.1 Target repository layout

```
sentinel/
├── AGENTS.md                      agent operating rules (entry point)
├── Makefile · pyproject.toml · uv.lock
├── docs/
│   ├── adr/                       architecture decision records
│   ├── design/                    DIRECTION.md · VOICE.md · tokens rationale
│   ├── runbooks/                  one per alert
│   └── site/                      Docusaurus source
├── src/sentinel/
│   ├── domain/                    pure logic — no I/O, no frameworks
│   │   ├── contracts/             Pydantic schemas (the current schemas.py)
│   │   ├── features/              ports.py flags.py packets.py registry.py
│   │   ├── graph/                 state.py gnn.py sequence.py
│   │   ├── world_model/           model.py heads.py imagine.py ensemble.py
│   │   ├── explain/               shap_engine.py attention.py counterfactual.py
│   │   ├── detect/                detectors.py correlation.py
│   │   ├── mitre/                 tactics.py techniques.py navigator.py
│   │   └── evaluate/              metrics.py replay.py generalisation.py
│   ├── application/               use cases, orchestration
│   ├── infrastructure/            db/ storage/ queue/ cache/ auth/
│   └── interfaces/                api/ cli/ workers/ lab/(streamlit)
├── alembic/
├── datasets/                      cic_ids2017 ctu13 unsw_nb15 lanl_auth
├── models/release/                versioned, checksummed bundles
├── tests/                         unit/ integration/ e2e/ performance/ security/
├── web/
│   ├── apps/console/              Next.js analyst console
│   ├── packages/tokens/           design tokens (source of truth)
│   ├── packages/ui/               component library
│   ├── packages/api-client/       generated from OpenAPI
│   └── packages/viz/              timeline + graph engines
├── deploy/
│   ├── helm/ · compose/ · terraform/ · appliance/
└── .github/workflows/             ci · security · release · nightly-load
```

## 8.2 Sprint → gap coverage

| Sprint | Closes | Primary artifact |
|---|---|---|
| P1 | G04, G05, G06 | Complete, transferable feature set |
| P2 | G02 | GNN with exported attention |
| P3 | **G01** | RSSM world model |
| P4 | **G03** | SHAP + attention + counterfactual |
| P5 | G09, G10, G11, G12 | MITRE engine + lead time + generalisation |
| P6–P10 | — | Production backend |
| P11–P15 | G07 (superseded) | Analyst console |
| P16–P18 | — | Operable, defensible platform |
| P19–P20 | — | Shippable product |

## 8.3 Command reference (target state)

```bash
make setup              # uv sync --all-extras && pnpm install
make gate               # ruff + mypy + pytest + eslint + tsc + vitest
make dev                # full stack: db, redis, redpanda, api, workers, web
make demo               # appliance mode, pretrained weights, sample capture
make train              # full reproducible training
make reproduce          # regenerate every published number, fail on drift
make bench              # k6 load + pytest-benchmark
make security           # bandit + semgrep + grype + gitleaks + zap
make a11y               # axe across every route
make release VERSION=x  # build, SBOM, sign, tag, publish
make appliance          # air-gapped single-node bundle
```

## 8.4 Risk register

| Risk | L | I | Mitigation |
|---|:--:|:--:|---|
| World model underperforms the GRU | M | H | Keep every baseline; the persistence comparison still proves dynamics learning. Publish the honest result. |
| Lead time stays 0 after P5 | M | H | P5-T4 measures the achievable ceiling *first*. LANL auth has genuine dwell time — use it. |
| Frontend rewrite stalls the ML work | M | H | Phases are ordered so Phase A finishes first. Keep Streamlit alive as `lab/` throughout. |
| Scope creep in Phase C | H | M | The eleven screens in §4.4 are the scope. Anything else is a P21 backlog item. |
| Tenant leakage bug reaches production | L | **C** | Write the leakage suite in P9-T3 *before* the endpoints; prove the suite detects a deliberately-removed RLS policy. |
| Malicious PCAP exploits Scapy | M | H | P17-T2: sandboxed subprocess, resource limits, fuzzing. Do not skip this — it is an attack on *this* product specifically. |
| Training/serving skew | M | H | P10-T2 skew test comparing offline and online features for the same window. |
| Agent context collapse on large files | H | M | `app.py` is still 1,388 lines — finish the split in P1. Enforce a 400-line ceiling in CI. |
| Dependency bloat breaks appliance mode | M | H | Every sprint's DoD includes "appliance mode still works". Hand-rolled GAT over PyG for this reason. |
| Honesty culture erodes under deadline | M | **H** | Skill C3 + the claim audit + `PENDING` convention. This culture is your most valuable asset; losing it costs more than any feature gains. |

## 8.5 If you have to cut

**The irreducible core** — without these it is not the product you are describing:
`P1 → P3 → P4 → P6 → P8 → P9 → P11 → P12 → P13 → P17 → P20`

That is 11 sprints: complete features, a real world model, real explainability, real persistence, a real API, real tenant isolation, a real design system and the three screens that matter, security hardening, and a shippable release.

**Defer if you must:** P2 (GNN — tabular world model still satisfies the sequence-model requirement), P14 (advanced viz — good SVG charts get you a long way), P18 (scale — until you have load), P19 (MLOps automation — manual promotion with gates works at low volume).

**Never cut:** P9 (tenant isolation) or P17 (security). A security product with a security hole is unrecoverable — not technically, reputationally.

---

## CLOSING NOTE

Two things are true about this repository at once.

The first is that the engineering culture is unusually good. Leak guards that refuse to train. Checksums on every artifact. Detectors that return zero *with a warning* rather than guessing. A results file that says, in plain language, "lead time is 0.0 and here is why." Most production systems at real companies do not have this discipline. **It is the thing that will make this credible to a security buyer, and it is the thing most likely to be sacrificed under deadline pressure. Protect it above any feature.**

The second is that the distance to production is real and it is roughly what this document describes. Not because anything here is badly built, but because a research prototype and a deployable platform are different artifacts with different obligations — persistence, isolation, observability, accessibility, supportability — and no amount of prototype quality substitutes for them.

Work the phases in order. Finish the intelligence before building the machinery around it. Build the backend before the frontend, so the frontend renders something real. And when a measurement disappoints you, publish it and then fix it — that habit is already in this codebase, and it is worth more than any single feature you could add.
