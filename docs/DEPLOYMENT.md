# SENTINEL Isolated Lab Deployment

This is the operator path for the checked-in synthetic lab scenario. It uses
the Docker Compose `lab` profile and must remain local to the isolated Compose
network. It is not a production deployment and does not capture or scan host
or internet traffic.

## Profile And Services

The scenario runner is enabled only with `--profile lab`:

```bash
docker compose config --profiles
```

The checked-in profiles include `lab`; the lab profile expands the base
services and adds the one-shot `lab-scenario-runner` service. Its verified
service command is:

```text
python scripts/run_lab_scenario.py
  --scenario recon-auth-progression
  --manifest /app/configs/lab/scenarios.json
  --target http://idurar-target:8888
  --api http://api:8100
```

Expected endpoints and service names:

| Service | Internal name | Host port |
|---|---|---:|
| SENTINEL API | `api` | `8100` |
| Streamlit dashboard | `dashboard` | `8501` |
| Synthetic lab target | `idurar-target` | internal `8888`; no host port |
| Bounded runner | `lab-scenario-runner` | none; exits after one run |

The runner is profile-gated, has `restart: "no"`, mounts the scenario manifest
read-only, and has no host network mode or privileged flag. The checked-in
Compose file does not define the `idurar-target` service. Therefore, starting
the profile alone is not documented as a successful live scenario run; the
target must first be attached to the same isolated Compose network.

## Start The Lab Base Services

Build and start the API and dashboard locally:

```bash
docker compose --profile lab up --build -d api dashboard
```

Open the verified host endpoints:

- Dashboard: `http://localhost:8501`
- API: `http://localhost:8100`

The API uses the local synthetic bootstrap key `sent_demo_key_2026` unless
`SENTINEL_BOOTSTRAP_KEY` is set before startup.

## Run The Scenario

First verify the bounded manifest path without network requests:

```bash
docker compose --profile lab run --rm lab-scenario-runner \
  uv run --no-sync python scripts/run_lab_scenario.py \
  --scenario recon-auth-progression \
  --manifest /app/configs/lab/scenarios.json \
  --target idurar-target \
  --api api \
  --api-key synthetic-demo-key \
  --dry-run
```

For the live bounded run, set the API key used by the local API and ensure an
isolated `idurar-target:8888` service is present on the Compose network:

```bash
export SENTINEL_API_KEY=sent_demo_key_2026
docker compose --profile lab run --rm lab-scenario-runner
```

The runner sends the checked-in `recon-auth-progression` scenario only. It
posts synthetic `UnifiedEvent` batches to `/v1/events` and then exits.

## Cleanup

```bash
docker compose --profile lab down --remove-orphans
```

This removes the lab-profile containers and orphaned Compose resources. It does
not turn the scenario into a production sensor or remove host data outside the
Compose-managed resources.

## Synthetic/Demo Limitations

- All scenario request values and event features are synthetic.
- The runner is bounded and allowlisted; it is not an attack framework or a general-purpose traffic generator.
- The scenario validates the local ingestion path and event contract, not real-world network performance, model accuracy, or attack impact.
- The API and dashboard are local demo services. Do not expose the synthetic target, demo credentials, or API without appropriate local isolation.
- No claim of a completed live run is made for this checkout while `idurar-target` remains absent from the checked-in Compose file.
