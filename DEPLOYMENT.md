# SENTINEL Demo Deployment

This deployment packages the existing Streamlit dashboard as a Docker-based
Hugging Face Space. It is intended for a teacher-friendly demonstration of the
synthetic replay, forecast explanation, and tamper-evident trust ledger.

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
```

The deployment is a prototype demo, not a production network sensor. It does
not capture the teacher's traffic, block connections, or store raw PCAP data.
The blockchain-themed trust feature is a local hash-chained ledger. It is the
integration boundary for a future permissioned blockchain.

## Run Locally with Docker

Build the image:

```bash
docker build -t trajectory-demo .
```

Start it:

```bash
docker run --rm -p 8501:8501 trajectory-demo
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

1. Open the Space URL.
2. Click `Train / Retrain` once in the sidebar.
3. Open `Overview` and explain scenario-level train/validation/test splits.
4. Open `Network States` and show the time-windowed traffic features.
5. Open `Forecast` and select a test scenario.
6. Explain the probability timeline, predicted stage, affected entities, and evidence.
7. In `Trust Ledger`, click `Record Alert`.
8. Click `Verify Ledger` and show the verified hash chain.
9. Explain that raw traffic stays off-ledger while the forecast and evidence fingerprints are auditable.

For the shortest guided story, use the `Demo` tab after training:

```text
Normal traffic -> reconnaissance -> forecast -> evidence -> reality check
```

## Deployment Limitations

- The demo trains models per application session; it is not a model-serving service.
- The local ledger uses the container filesystem and is not durable across a Space restart.
- The live packet-capture path is not suitable for Hugging Face hosting.
- The synthetic data validates the pipeline, not real-world network performance.
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
4. Set the main file to `src/trajectory/dashboard/app.py`.
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
