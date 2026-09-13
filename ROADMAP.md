# SENTINEL Enterprise Roadmap

Status-dated 2026-09-13. The prototype is complete and demo-ready for
SIH26153; this document maps the enterprise transformation phases to what
exists today, with the scale-level ladder from prototype to platform.

## Scale-level ladder

| Level | Stack | Status |
|---|---|---|
| 1 — Hackathon demo | Streamlit + local files | **Current — done** |
| 2 — Pilot / MVP | + FastAPI inference API, key-based auth + RBAC + audit | **Shipped** (`trajectory/api.py`, `trajectory/auth.py`) |
| 3 — Production SaaS | + React UI, Kafka, PostgreSQL, Redis, MLflow | Not started |
| 4 — Enterprise platform | + TimescaleDB, Kubernetes, permissioned chain | Not started |
| 5 — Ecosystem | Multi-tenant SaaS, federated learning, marketplace | Not started |

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 1 — API layer | FastAPI service over the trained artifacts | ✅ `/health`, `/model`, `/v1/forecast`, `/v1/detect` with structured errors and per-request timing (`tests/test_api.py`) |
| 2 — Auth + RBAC | API keys, RBAC, audit logging | 🟡 Shipped: hashed API keys (`trajectory/auth.py`), 4-role permission matrix on every endpoint, admin key lifecycle, append-only audit trail. Not built: SSO/OIDC, MFA, tenant isolation — these need a real identity provider |
| 3 — Real-time ingestion | Kafka/syslog sources feeding the window builder | 🟡 `SyslogTailSource` tails syslog-format files into the live engine (Phase 3); DNS/auth stubs normalize into `UnifiedEvent`; Kafka/syslog-socket transport is future work |
| 4 — Enhanced detection | Scan classification, C2 from DNS/TLS, phishing, insider | 🟡 Six detectors shipped with measured thresholds; C2/DDoS are honest stubs pending real telemetry/scenario data |
| 5 — Enterprise dashboard | Analyst console, CISO risk views, threat hunt | 🟡 Streamlit Live tab has risk grid + incidents + verdicts; no React split |
| 6 — Blockchain trust | Hash anchoring, cross-org verification | 🟡 `ledger.py` demonstrates the hash-chain path; no distributed ledger |
| 7 — Model ops | Registry, drift, shadow deployment | 🟡 SHA-256 artifacts + calibration records exist; no registry/drift monitoring |
| 8 — Observability | Prometheus, tracing, paging | ❌ Only `x-process-time-ms` timing header so far |
| 9 — Deployment infra | K8s, CI/CD, Vault, Postgres | 🟡 Dockerfile + HF Spaces config + Streamlit Cloud config exist |
| 10 — Enterprise features | Compliance exports, case management, retention | ❌ |
| 11 — Advanced detection | GNN, federated learning, ZK proofs | ❌ Research scope |

## What the roadmap builds on (already true)

- Typed Pydantic contracts end to end — the API reuses the exact schemas the
  dashboard trains and scores with, so REST consumers get identical results.
- Leakage-safe scenario splits and every claim-status banner discipline.
- Attack-type detectors that state what they cannot detect instead of
  fabricating scores.
- Trust-ledger hash chain as the integration seam for Phase 6.

## Honest constraints

- The API is single-process, single-tenant, in-memory — level 2 by design.
  Auth (Phase 2) is the gate to anything user-facing beyond the lab.
- Detector validation remains synthetic-only; Phase 4 enhancements should
  start with real-traffic validation of the existing six before adding types.
- Weeks-level estimates in the original proposal assume a team; a solo
  contributor should treat phases as ordered, not scheduled.
