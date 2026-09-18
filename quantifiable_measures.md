# Quantifiable Measures

This project now emits live, quantifiable solution metrics from real runtime data.

## Live API

- Endpoint: /api/solution/measures
- Example:
  - curl -s "http://127.0.0.1:8000/api/solution/measures" | jq .

## Persisted File

Each API call writes a fresh snapshot file:

- state/solution/quantifiable_measures.json

## Measured Outputs

The snapshot includes:

- totals.alerts
- totals.grouped_log_clusters
- totals.response_actions_total
- totals.rules_total
- totals.logs_total
- totals.honeypot_sessions
- totals.honeypot_sessions_analyzed
- severity_distribution
- warning_level_distribution
- runtime_controls.blocked_ips
- runtime_controls.disabled_accounts
- runtime_controls.rate_limits
- runtime_controls.isolated_hosts
- runtime_controls.quarantined_endpoints

These values are computed from live Elasticsearch indices plus runtime control and honeypot session state files.
