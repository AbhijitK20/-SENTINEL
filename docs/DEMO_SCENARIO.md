# Synthetic Lab Scenario

## Scope

`recon-auth-progression` is the only checked-in scenario. It is a bounded,
synthetic demonstration for the isolated Docker Compose `lab` profile. The
runner uses fixed local request paths and synthetic values; it does not perform
credential theft, arbitrary command execution, MITM, wireless attacks, covert
transport, persistence, or evasion.

The runner exits after one scenario and is not a persistent attack service.

## Services And Ports

| Service | Compose name | Port | Exposure |
|---|---|---:|---|
| SENTINEL API | `api` | `8100` | Published as `localhost:8100` |
| Dashboard | `dashboard` | `8501` | Published as `localhost:8501` |
| Lab target | `idurar-target` | `8888` | Internal runner target; not published by the checked-in Compose file |
| Scenario runner | `lab-scenario-runner` | none | One-shot service on profile `lab` |

The runner posts normalized events to `http://api:8100/v1/events` and sends its
bounded requests to `http://idurar-target:8888`. The checked-in Compose file
does not define an `idurar-target` service, so the live scenario command needs
that target attached to the same isolated Compose network before it can run.

## Verified Dry Run

The dry run validates the checked-in manifest and prints all four bounded steps
without making network requests:

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

Expected stages are:

```text
reconnaissance GET /api/health
failed-login POST /api/auth/login
api-probe GET /api/users?search=sentinel-test
synthetic-upload POST /api/uploads/synthetic.txt
```

## Bounded Live Run

After an isolated target named `idurar-target` is available on the Compose
network and the API is running, provide an API key and run the one-shot runner:

```bash
export SENTINEL_API_KEY=sent_demo_key_2026
docker compose --profile lab up --build -d api dashboard
docker compose --profile lab run --rm lab-scenario-runner
```

The live run sends only the four manifest-defined requests and posts events in
batches of at most two to the API. The default API bootstrap key above is a
synthetic local-demo credential; use a different local value when the API is
configured with another key.

## Cleanup

Stop and remove the lab-profile containers and orphaned Compose resources:

```bash
docker compose --profile lab down --remove-orphans
```

## Caveats

- This is synthetic/demo telemetry, not real traffic and not a field-validated detection result.
- The scenario demonstrates request progression and API ingestion; it does not prove that a real attacker or production service would behave this way.
- Keep the target and API on the isolated lab network. Do not expose the intentionally synthetic target or demo credentials to an untrusted network.
- No live run is claimed for the checked-in Compose file until an `idurar-target` service is added or attached to that network.
