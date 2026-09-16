# Third-Party Dependencies

Auto-generated from `pyproject.toml` runtime dependencies.

| Package | Version Constraint | License | Purpose |
|---|---|---|---|
| joblib | >=1.6.0 | BSD-3-Clause | Model serialization and parallelism |
| numpy | >=2.0,<3 | BSD-3-Clause | Numerical array operations |
| pandas | >=2.2,<3 | BSD-3-Clause | DataFrame-based data loading and manipulation |
| pydantic | >=2.8,<3 | MIT | Data validation and schema contracts |
| pyyaml | >=6.0,<7 | MIT | YAML config file parsing |
| scikit-learn | >=1.5,<2 | BSD-3-Clause | Logistic regression baseline, metrics, preprocessing |
| networkx | >=3.3,<4 | BSD-3-Clause | Graph construction for network topology |
| plotly | >=5.24,<7 | MIT | Interactive visualisation in dashboard |
| streamlit | >=1.40,<2 | Apache-2.0 | Dashboard web application framework |
| torch | >=2.4,<3 | BSD-3-Clause | GRU temporal model (optional, deep-learning extra) |
| scapy | >=2.6,<3 | GPL-2.0-only | PCAP packet parsing (optional, pcap extra) |
| fastapi | >=0.115,<1 | MIT | REST API framework (optional, api extra) |
| uvicorn | >=0.32,<1 | BSD-3-Clause | ASGI server for FastAPI (optional, api extra) |

**Note:** `scapy` is GPL-2.0 and is an optional dependency used only for PCAP
ingestion in `scripts/`. It is not part of the core runtime and is excluded
from the distributed package unless explicitly installed via `pip install
trajectory-sih26153[pcap]`.
