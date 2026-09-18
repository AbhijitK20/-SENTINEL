# SENTINEL Demo Deployment

This deployment packages the Streamlit dashboard and local pilot services as a
Docker-based demonstration. It covers synthetic replay, forecast explanation,
Replay/Demo evaluation, the Attack Story case study, live detection, local
attack simulation, admin response, Grafana observability, and the
tamper-evident trust ledger.

## What This Deploys

```text
Browser
   |
   v
Hugging Face Space
   |
   +-- Streamlit dashboard
   +-- deterministic synthetic traffic
   +-- baseline + GRU training in memory
   +-- forecast and evidence display
    +-- local hash-chained alert ledger
    +-- optional vulnerable target + scanner + admin response dashboard
    +-- optional Prometheus + Grafana observability
```

The deployment is a prototype demo, not a production network sensor. It does
not capture the teacher's traffic, block connections, or store raw PCAP data.
The blockchain-themed trust feature is a local hash-chained ledger. It is the
integration boundary for a future permissioned blockchain.

## Run Locally with Docker

Build the image:

```bash
docker build -t sentinel-demo .
```

Start it:

```bash
docker run --rm -p 8501:8501 sentinel-demo
```

Open `http://localhost:8501`.

The first model training operation can take a little time because the demo
trains the baseline and temporal models in memory. After training, use the
Forecast tab and click `Record Alert` followed by `Verify Ledger`.

The dashboard defaults to a fast hosted-demo training profile: six scenarios,
three temporal horizons, a smaller GRU, and twelve maximum epochs. Enable
`Full temporal training (slower)` only for local experimentation or a stronger
benchmark run; it is not recommended on free Streamlit Cloud resources.

## Create a Hugging Face Space

1. Create a new Space at `https://huggingface.co/new-space`.
2. Select `Docker` as the Space SDK.
3. Choose a CPU hardware tier for the first demo.
4. Upload or push this repository, including:
   - `Dockerfile`
   - `.dockerignore`
   - `pyproject.toml`
   - `uv.lock`
   - `src/`
   - `configs/`
   - `scripts/`
5. Wait for the Docker build to finish.
6. Open the generated `*.hf.space` URL.

The root `README.md` contains the Space metadata that sets the Docker SDK and
port `8501`.

## Teacher Demo Flow

Use this sequence during the presentation:

1. Open the dashboard.
2. Click `Train / Retrain` once in the sidebar.
3. Open `Overview` and explain scenario-level train/validation/test splits.
4. Open `Network States` and show time-windowed traffic features and edges.
5. Open `Forecast` and move the walk-forward slider.
6. Open `Replay`, run the evaluation, switch scenarios, and download the report.
7. Open `Demo`, move through all five steps, and distinguish observed values from forecast values.
8. Open `Attack Story`, advance the phase replay, then simulate firewall containment.
9. In `Trust Ledger`, click `Record Alert` followed by `Verify Ledger`.
10. Explain that raw traffic stays off-ledger while forecast and evidence fingerprints are auditable.

For the shortest guided story, use the `Demo` tab after training:

```text
Normal traffic -> reconnaissance -> forecast -> evidence -> reality check

For the local operational demo:

```bash
docker compose --profile demo up --build -d
```

For a fresh clone or after pulling code changes, rebuild the project image so
port 8501 serves this checkout's SENTINEL dashboard rather than a cached image:

```bash
docker compose down --remove-orphans
docker compose build --no-cache
docker compose up --build -d
```

Open `http://localhost:5001`, use `Reset System` before a new attack, launch
an attack from `Force Attack`, then exercise `Block All Attackers` and
`Unblock All` while watching the scanner and API state update.
```

## Deployment Limitations

- The demo trains models per application session; it is not a model-serving service.
- The local ledger uses the container filesystem and is not durable across a Space restart.
- The live packet-capture path is not suitable for Hugging Face hosting.
- The synthetic data validates the pipeline, not real-world network performance.
- The port-5000 vulnerable app is intentionally unsafe and must remain local to the training environment.
- Attack-trigger buttons exercise the local demo target; they are not production attack simulation.
- Public deployment should not receive sensitive traffic or confidential reports.

For a production-like deployment, move model artifacts to an immutable artifact
bundle, store alerts in durable storage, add authentication, and replace the
local ledger with a permissioned blockchain or managed audit store.

## Streamlit Community Cloud

The repository also contains `requirements.txt` for Streamlit Community Cloud.
It explicitly installs Plotly, Streamlit, NetworkX, and PyTorch, which are
optional dependencies in `pyproject.toml` but required by the dashboard.

Deploy with:

1. Push the repository to GitHub.
2. Open `https://share.streamlit.io`.
3. Choose the repository and branch.
4. Set the main file to `src/sentinel/dashboard/app.py`.
5. Deploy and wait for dependency installation to finish.

After changing `requirements.txt`, use **Manage app -> Reboot app** or push a
new commit so Community Cloud rebuilds the environment.

### Hosted Live Detection Controls

The Live Detection tab is designed to work without a terminal on Streamlit
Cloud:

- `Synthetic attack replay` generates the deterministic benign -> reconnaissance -> lateral-movement event stream in memory.
- `CSV replay` accepts a supported CICFlowMeter CSV through the upload control.
- `JSONL sensor file` accepts the sensor JSONL format through the upload control.

The original localhost attack command is still useful for local development,
but it is not required or used by the hosted workflow.

### Local Packet Capture

To include packet-derived features locally, install Scapy and run the dashboard
with capture privileges:

```bash
uv sync --extra dashboard --extra pcap
sudo -E uv run streamlit run src/sentinel/dashboard/app.py
```

Select `Local loopback capture` and interface `lo`. This captures packets on
the machine hosting Streamlit. It is not available as a browser or hosted-cloud
capture source. The synthetic/local attack button remains a safe flow/JSONL
sensor simulation and may still show the packet-features-unavailable warning.

## Deploying the REST API (Hugging Face Space or any container host)

`Dockerfile.api` builds a container that serves the FastAPI service
(`sentinel/api/`) on one port (default 7860 for HF Spaces).

```bash
docker build -f Dockerfile.api -t sentinel-api .
docker run --rm -p 7860:7860 -e SENTINEL_BOOTSTRAP_KEY='<choose-a-long-random-key>' sentinel-api
```

On first start the container trains a small deterministic synthetic baseline
(`scripts/bootstrap_api_artifacts.py`) so the API works with zero external
state — the `/model` endpoint reports this demo model honestly. Deployers
with real artifacts set `SENTINEL_ARTIFACTS_DIR` to a volume mount instead.

### Environment variables

| Variable | Purpose | Default |
|---|---|---|
| `SENTINEL_PORT` | Port the API listens on (HF Spaces expects 7860) | `7860` |
| `SENTINEL_ARTIFACTS_DIR` | Baseline artifacts directory (auto-bootstrapped if empty) | `/tmp/sentinel-artifacts` |
| `SENTINEL_AUTH_DIR` | Keys/audit/cases/registry storage | `reports/api` |
| `SENTINEL_BOOTSTRAP_KEY` | Operator-chosen first admin API key (provision once, then rotate via `/admin/keys`) | unset |
| `SENTINEL_THRESHOLD` | Override the decision threshold | artifact-calibrated |
| `SENTINEL_THREAT_FEED_FILE` | Local URLhaus-format threat-intel CSV path (optional enrichment; refresh out-of-band, e.g. cron — the API never fetches URLs itself) | unset |

### Creating an Hugging Face Space for the API

1. New Space → SDK `Docker` → upload this repo.
2. Set the Dockerfile to `Dockerfile.api` (Space settings → Dockerfile path,
   or rename). Add `SENTINEL_BOOTSTRAP_KEY` as a **Secret**.
3. The Space serves `/health`, `/docs` (interactive OpenAPI), and all `/v1/*`
   endpoints on port 7860.

## Observability stack (local pilot)

Prometheus scrapes the API's `/metrics` endpoint and Grafana renders the
provisioned `SENTINEL API Overview` dashboard:

```bash
docker compose --profile obs up --build -d      # api + prometheus + grafana
# Grafana: http://localhost:3000 (anonymous viewer; admin/admin)
# Prometheus targets: http://localhost:9090/targets
```

Scraped metrics: `sentinel_requests_total` (by status), request latency
sum/count, `sentinel_windows_emitted_total`, `sentinel_push_incidents_total`,
`sentinel_cases_open`, `sentinel_threat_indicators`,
`sentinel_live_events_seen`, `sentinel_live_peak_probability`,
`sentinel_live_alert_active`, and `sentinel_live_findings`.

## Real-traffic detection demo (profile: realtime)

The `realtime` compose profile runs a **genuine live attack** against a
containerized target and detects it from the wire — no synthetic data anywhere
in the chain:

```text
demo-attacker (nmap -sS, real SYN scan)
        |  real packets across the demo network
        v
demo-target (nginx victim)  <-  demo-sensor (tcpdump -tttt in the target's
        |                       network namespace: NET_RAW capture of every
        |                       probe/response on the wire)
        v
scripts/packet_sensor.py  ->  POST /v1/events  ->  SENTINEL live push engine
        ->  30s event-time windows  ->  trained forecaster + 9 detectors
        ->  incident correlation (risk-critical recon alerts, live)
```

Run it (needs an analyst-or-higher API key with `POST /v1/events`):

```bash
export SENTINEL_API_KEY=sent_<analyst-key>        # see /admin/keys
docker compose --profile realtime up --build -d           # api + target + sensor, then attacker
docker compose logs -f demo-attacker demo-sensor  # watch the scan + ALERT lines
```

Verified end-to-end (2026-09-13): a 411-second nmap SYN scan of 1027 ports
streamed 4,835 real packet events; SENTINEL correlated **INC-001
Reconnaissance, risk critical**, tracking the scan live across 14 windows
(`172.28.0.2/3/4`, first_seen 14:39:42Z, last_seen 14:46:42Z, with
recommended actions) — from captured packets only, no replayed data.

### Flow sensor (model-scored realtime path)

`scripts/flow_sensor.py` replaces `packet_sensor.py` in the demo-sensor
command when you want the **trained forecaster** to score live traffic. It
aggregates the same tcpdump stream into 5-tuple flows (SYN start, RST/FIN
teardown, 15s idle / 60s max-age sweeps) and emits one `event_type="flow"`
event per connection — the exact shape the baseline was fit on
(CICFlowMeter semantics: bidirectional Fwd+Bwd, per-flag counts,
`flow_iat_mean_ms`). Verified with the real
`TrafficLabelling/Friday-PortScan` day: streaming the first 2,000 genuine
attack-day flows through `POST /v1/events` produced a model alert
(`peak=0.221 > 0.15 threshold`) with a critical 5-type incident on the real
2017 attacker/target IPs. The push engine windows in event time — restart
the `api` container before streaming a historical capture so the window
grid anchors to the capture's own timeline.

Honest scope notes:

- The trained forecaster stays quiet on the two-container nmap demo's
  volume: CIC training windows average ~4,600 flows / ~105 MB per 60s, and
  a single nmap scan against one nginx container is ~3 orders of magnitude
  below that. The model is volume-sensitive (large positive weights on
  `packets`/`ack_count`/`bytes`); on real attack-day traffic at real volume
  (the Friday PortScan replay) it alerts. The **recon detector** (pattern
  rules) fires at any volume, including the small demo scan.
- The attacker scans only `demo-target` inside the compose network. Nothing
  on the host or the internet is scanned; the sensor captures only
  demo-network traffic.
- `nmap -T2` keeps the scan slow enough to span stride boundaries; a T4 scan
  finishes inside one window and can be missed by the 30s window grid.

## Threat-intel feed refresh (free, keyless, out-of-band)

`scripts/fetch_threat_feed.py` pulls the abuse.ch URLhaus dump (free, no API
key) into `reports/threat_intel/feed.json`. The runtime never fetches URLs
itself (offline-first contract, `tests/test_offline.py`); the compose
`feed-refresher` one-shot service refreshes it at `up` (skipping when the file
is younger than 12h), and the API loads it at boot:

```bash
uv run python scripts/fetch_threat_feed.py        # manual refresh
docker compose run --rm feed-refresher            # same, via compose
```

The API accepts both the saved `.json` snapshot and a raw URLhaus `.csv` body
(`SENTINEL_THREAT_FEED_FILE`). Verified live: 19,233 indicators loaded at API
boot; a window touching a listed host raises C2/exfil findings with explicit
"list evidence, not verdicts" warnings. Cron example for a host deployment:

```cron
0 */6 * * *  cd /opt/sentinel && uv run python scripts/fetch_threat_feed.py --max-age-hours 5
```
