# Runbook: Forecast Latency High

## Symptom

Prometheus alert: `ForecastLatencyHigh` — p95 forecast latency above 30s.

## Likely Causes

1. **Model not loaded**: cold start or crash
2. **Large windows**: too many features per window
3. **Batching timeout**: batch not filling within latency budget

## Diagnostic Commands

```bash
# Check inference worker status
curl -s http://localhost:8000/metrics | grep inference

# Check model version
curl -s http://localhost:8000/model | jq '.version'

# Check batch metrics
curl -s http://localhost:8000/metrics | grep batch
```

## Remediation

1. **Model not loaded**: restart inference worker, check artifact path
2. **Large windows**: reduce window size or feature count
3. **Batching timeout**: increase max_latency_ms or reduce batch_size

## Escalation

- If model fails to load, verify artifact checksums with `verify_release_artifacts.py`
- If sustained high latency, check for memory pressure causing GC pauses
