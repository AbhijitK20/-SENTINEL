# Runbook: High CPU Usage

## Symptom

Prometheus alert: `HighCpuUsage` — CPU usage above 80% for > 5 minutes.

## Likely Causes

1. **Model inference spike**: many concurrent forecast requests
2. **Windowing backlog**: events arriving faster than processed
3. **Streamlit re-render**: dashboard polling at high frequency

## Diagnostic Commands

```bash
# Check which process is using CPU
top -bn1 | head -20

# Check SENTINEL-specific metrics
curl -s http://localhost:8100/metrics | grep sentinel

# Check windowing backlog
curl -s http://localhost:8100/metrics | grep queue_depth
```

## Remediation

1. **If inference spike**: scale workers horizontally or increase batch size
2. **If windowing backlog**: check event ingestion rate, enable backpressure
3. **If dashboard**: reduce polling frequency or disable auto-refresh

## Escalation

- If CPU stays high after remediation, check for runaway training jobs
- If sustained > 95%, check for infinite loops in feature computation
