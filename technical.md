# Technical Stack

## Runtime and Languages

- Python 3.11 in containers
- Python 3.10 on host-side helper execution
- TypeScript for the frontend
- Next.js 15 for the UI
- FastAPI for the backend API
- Docker Compose for local orchestration

## Detection and Security Technologies

### Elasticsearch

Used for:

- primary indexed log storage
- rule catalog indexing
- log catalog indexing
- alert indexing
- search and aggregation
- BM25 ranking

Main index families:

- `logs-linux.auditd-*`
- `fda-syslog-*`
- `fda-suricata.eve-*`
- `wazuh-alerts-*`
- `wazuh-archives-*`
- `.alerts-security.alerts-*`
- `security-response-*`
- `rule-catalog`
- `log-catalog`

### Kibana

Used for:

- Elastic Security detection rule hosting
- detection engine management
- imported rule visibility

### Logstash

Used for:

- file-based input ingestion
- ECS-style normalization
- auditd parsing
- syslog parsing
- Suricata EVE shaping
- Elasticsearch output routing

### Wazuh

Used for:

- native rule evaluation
- native event archival
- custom XML rules and decoders
- parallel alert path independent of Elastic Security

### Suricata

Used for:

- PCAP-driven live network telemetry generation
- EVE output production
- flow-based and protocol-based evidence generation

### Sigma

Used for:

- vendor-neutral rule source
- conversion to Elastic-compatible detections
- readable rule content in the catalog

### Elastic Detection Rules

Used for:

- native Elastic Security detections
- direct loading without custom translation

### Panther Analysis Tool

Used for:

- local Panther rule validation
- rule corpus quality checking

## Search and Ranking

BM25 is used for fast ranking in:

- natural-language rule search
- log-to-rule pivots
- rule-to-log pivots

The project does not use LLMs for the rule/log retrieval step because BM25 is already appropriate and fast for this use case.

## Backend Stack

### FastAPI

Endpoints include:

- health
- dashboard and overview
- alerts
- logs
- log analytics
- rules and rule evidence
- query resolve
- playbooks
- agents
- ZeroClaw status
- response policy
- response runtime
- response preview
- response execute
- run start, stop, current, history
- generator catalog

### Runtime Middleware

FastAPI middleware enforces response state at request time.

Supported enforcement examples:

- blocked IP returns `403`
- disabled account returns `403`
- rate-limited path returns `429`

## Frontend Stack

### Next.js

Used for:

- page routing
- reusable live dashboard components
- browser-based operator workflows

### Recharts

Used for:

- timelines
- pies
- bar charts
- protocol distributions
- port distributions
- source/destination summaries
- agent mix summaries

### Fonts

- Montserrat for headings
- Courier Prime for body content

## Orchestration Layer

### ZeroClaw-Oriented Hand System

Hands are defined under `zeroclaw/hands/`.

Current responsibilities include:

- `orchestrator_main`
- `elastic_sensor`
- `wazuh_sensor`
- `suricata_sensor`
- `rule_mapper`
- `query_analyst`
- `mitre_mapper`
- `playbook_resolver`
- `response_planner`
- `bandwidth_governor`
- `validation_agent`
- `alert_correlator`
- `evidence_curator`
- `policy_guardian`
- `run_supervisor`
- `telemetry_curator`
- `threat_summarizer`
- `zeroclaw_runtime`

### Real ZeroClaw Binary

The real ZeroClaw binary is mounted into the API and orchestration containers from `/tmp/zeroclaw`.

The UI/API use it to surface:

- provider/runtime status
- workspace status
- ZeroClaw environment details

The runtime is explicitly configured to use the Groq provider through container environment overrides.

### ZeroClaw Daemon

The stack also runs a dedicated `zeroclaw-daemon` service.

That service exposes the real ZeroClaw gateway and health endpoint, and the backend reads its live state to show:

- gateway reachability
- scheduler status
- pairing requirement
- daemon uptime
- runtime availability beyond static CLI status output

Important runtime note:

- the `Service: stopped` line in `zeroclaw status` refers to the OS-level service manager state
- the project now also reads the daemon `/health` endpoint, which is the actual live runtime indicator used by the backend and UI

## LLM Usage

LLM usage in this project is intentionally constrained.

### Used

- Groq for response planning assistance
- Groq for terse incident note generation
- ZeroClaw provider selection configured to Groq for the mounted ZeroClaw runtime surface

### Not Used

- retrieval of rules to logs
- retrieval of logs to rules
- ranking of query results where BM25 evidence is sufficient

## Docker Services

Main services:

- `elasticsearch`
- `kibana`
- `logstash`
- `wazuh.manager`
- `suricata`
- `api`
- `frontend`
- `response-engine`
- `orchestration-engine`
- `detector-tools`

## Important Project Scripts

- `scripts/bootstrap_stack.py`
- `scripts/import_elastic_rules.py`
- `scripts/import_sigma_rules.py`
- `scripts/catalog_rules.py`
- `scripts/catalog_logs.py`
- `scripts/map_logs_to_rules.py`
- `scripts/map_rules_to_logs.py`
- `scripts/evaluate_existing_rule_pipeline.py`
- `scripts/run_orchestration_engine.py`
- `scripts/run_response_watcher.py`
- `scripts/run_response_action.py`
- `scripts/apply_response_control.py`
- `scripts/run_suricata_watcher.py`
- `scripts/generators/*`

## Data and State Paths

Important state paths:

- `state/orchestration/`
- `state/response/`
- `state/response/runtime/`
- `state/demo_runs/`

Important ingest paths:

- `ingest/auditd/`
- `ingest/syslog/`
- `ingest/json/`
- `ingest/pcap/`
- `ingest/suricata/`

## Validation Approach

The project validates on:

- true positives
- false positives
- true negatives
- false negatives
- detection latency
- response execution behavior
- log-to-rule mapping
- rule-to-log mapping

The validation harness currently verifies the existing wired scenarios and reports:

- `tp=9`
- `fn=0`
- `fp=0`
- `tn=4`

## UI Surface Summary

Current UI areas:

- mission
- command center
- runs
- log explorer
- rule studio
- playbooks
- responses
- agents

## Development Notes

- Runtime state is intentionally stored on disk and written by live services.
- Generated hand context files are operational state, not source-of-truth code.
- The repo ignores runtime state and generated artifacts where appropriate.
