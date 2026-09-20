# SENTINEL Enterprise Roadmap

Status-dated 2026-09-13. The prototype is complete and demo-ready for
SIH26153; this document maps the enterprise transformation phases to what
exists today, with the scale-level ladder from prototype to platform.

## Scale-level ladder

| Level | Stack | Status |
|---|---|---|
| 1 — Hackathon demo | Streamlit + local files | **Current — done** |
| 2 — Pilot / MVP | + FastAPI inference API, key-based auth + RBAC + audit | **Shipped** (`trajectory/api.py`, `trajectory/auth.py`) |
| 3 — Production SaaS | + React UI, Kafka, PostgreSQL, Redis, MLflow | 🟡 API-side ops shipped in-process (`registry.py`, `drift.py`, `/metrics`); React/Kafka/Postgres/Redis not started |
| 4 — Enterprise platform | + TimescaleDB, Kubernetes, permissioned chain | 🟡 Case lifecycle (`cases.py`), compliance exports, signed feedback; K8s/TSDB/permissioned chain not started |
| 5 — Ecosystem | Multi-tenant SaaS, federated learning, marketplace | 🟡 FedAvg simulation (`federated.py`), org-scoped API keys; real federated infra not started |

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 1 — API layer | FastAPI service over the trained artifacts | ✅ `/health`, `/model`, `/v1/forecast`, `/v1/detect` with structured errors and per-request timing (`tests/test_api.py`) |
| 2 — Auth + RBAC | API keys, RBAC, audit logging | 🟡 Shipped: hashed API keys (`trajectory/auth.py`), 4-role permission matrix, admin key lifecycle, append-only audit trail, org_id tenant field on keys + audit. Not built: SSO/OIDC, MFA — these need a real identity provider |
| 3 — Real-time ingestion | Kafka/syslog sources feeding the window builder | 🟡 **Real-packet path verified live**: `realtime` compose profile streams a genuine nmap SYN scan from tcpdump capture through `POST /v1/events` into the push engine (4,835 real packets, recon incident detected live); live URLhaus feed refresh (`scripts/fetch_threat_feed.py`, 19,233 indicators). Kafka transport remains future work |
| 4 — Enhanced detection | Scan classification, C2 from DNS/TLS, phishing, insider | 🟡 Nine detectors plus threat-intel enrichment: C2/exfil scores rise when a destination matches a loaded feed (URLhaus-format, TTL-bound, list evidence — not verdicts); recon detector verified against a **real nmap SYN scan** (not synthetic); validated quiet-on-benign, not on real multi-stage attack data |
| 5 — Enterprise dashboard | Analyst console, CISO risk views, threat hunt | 🟡 Streamlit Live tab has risk grid + incidents + verdicts + case panel; no React split |
| 6 — Blockchain trust | Hash anchoring, cross-org verification | 🟡 `ledger.py` hash chain + HMAC-signed analyst feedback (`feedback.py`); no distributed ledger or PKI |
| 7 — Model ops | Registry, drift, shadow deployment | 🟡 `registry.py` (register→approve→rollback), `drift.py` (PSI monitoring + `POST /v1/drift`); shadow deployment not started |
| 8 — Observability | Prometheus, tracing, paging | 🟡 `/metrics` Prometheus text endpoint + validated scrape stack: `docker compose --profile obs up` runs Prometheus (target verified `up`) and Grafana with the auto-provisioned SENTINEL API Overview dashboard; tracing/paging not started |
| 9 — Deployment infra | K8s, CI/CD, Vault, Postgres | 🟡 GitHub Actions CI (lint+tests+wheel), `docker-compose.yml` pilot (dashboard+API); K8s/Vault/Postgres not started |
| 10 — Enterprise features | Compliance exports, case management, retention | 🟡 `cases.py` lifecycle (OPEN→RESOLVED, SLA by severity) with `/v1/cases`; `compliance.py` NIST CSF/ISO 27001/SOC 2 control report (0.75 coverage, gaps listed); retention policies not started |
| 11 — Advanced detection | GNN, federated learning, ZK proofs | 🟡 `federated.py` FedAvg simulation (weights-only sharing, verified vs centralized); GNN/ZK remain research scope |

## What the roadmap builds on (already true)

- Typed Pydantic contracts end to end — the API reuses the exact schemas the
  dashboard trains and scores with, so REST consumers get identical results.
- Leakage-safe scenario splits and every claim-status banner discipline.
- Attack-type detectors that state what they cannot detect instead of
  fabricating scores.
- Trust-ledger hash chain as the integration seam for Phase 6.

## Honest constraints

- The API is single-process, in-memory — level 2 by design. Keys carry an
  org_id for multi-tenancy, but per-org data isolation is not enforced yet.
- Registry/drift/cases state lives in JSONL files, not a database — right
  for a pilot, wrong for concurrent multi-instance deployments.
- Detector validation remains synthetic-only; Phase 4 enhancements should
  start with real-traffic validation of the existing six before adding types.
- Weeks-level estimates in the original proposal assume a team; a solo
  contributor should treat phases as ordered, not scheduled.
