# Project Explanations

## What This Project Is

This project is a live cyber-detection and response workspace that combines:

- Elastic Security detections from `detection-rules`
- Sigma detections imported into Elastic and mapped back to logs
- Wazuh native detections and Wazuh custom correlation
- Suricata network telemetry for packet-driven network detections
- BM25-backed rule-to-log and log-to-rule mapping
- MITRE ATT&CK technique mapping
- SOAR playbook resolution from the MITRE ATT&CK Playbooks repository
- ZeroClaw-oriented orchestration with visible hands, validation, and runtime status
- A FastAPI backend for the frontend and automation surface
- A Next.js frontend for live dashboards and operator workflows

The system is designed so that the pipeline runs continuously, and operators can:

- watch logs arrive live
- see which existing rules matched
- inspect rule logic in readable form
- inspect mapped playbooks in readable form
- see the response command before it runs
- choose to execute a response
- see live control state after response execution

## Core Design Goals

The project is built around these principles:

1. Existing-rule-first detection.
   The main detection path uses rules already present in `sigma/`, `detection-rules/`, and Wazuh rule content. The system is intentionally designed to avoid hardcoded demo-only detections as the primary signal path.

2. Realtime operation.
   The stack is meant to stay up. Manual generator commands can be run in a separate terminal while the UI updates through polling and live dashboards.

3. Operator readability.
   The frontend is intended to show readable cards and structured sections instead of raw JSON, TOML, XML, or YAML.

4. Cross-source evidence.
   The same operator view should tie together live logs, detections, MITRE mapping, playbooks, orchestration state, and response state.

5. Safe response controls.
   The response engine applies safe local runtime controls such as disabled accounts, blocked IPs, and rate limits through managed state rather than unsafe system-destructive automation.

## High-Level Architecture

The platform is split into five layers.

### 1. Telemetry Generation and Ingestion

Inputs arrive from:

- `ingest/auditd/audit.log`
- `ingest/syslog/fda.log`
- `ingest/json/events.jsonl`
- `ingest/pcap/*.pcap`
- `ingest/suricata/eve.json`
- `ingest/suricata/fda-eve.jsonl`

The project includes manual telemetry generators in `scripts/generators/` that emit safe audit, syslog, JSON, and PCAP inputs for live validation against existing rules.

### 2. Detection Engines

Detection is handled in parallel by:

- Elastic Security rule engine
- Wazuh rule engine
- Suricata network parsing and EVE output

Elastic detections are loaded from:

- `detection-rules/rules/`
- converted Sigma rules from `sigma/rules/`

Wazuh detections are produced by:

- built-in Wazuh parsing and rule handling
- custom rules in `config/wazuh/manager/rules/local_rules.xml`

### 3. Mapping and Cataloging

Two important Elasticsearch catalogs support fast pivots:

- `rule-catalog`
- `log-catalog`

These catalogs enable:

- natural-language query to rule matching
- rule to likely logs
- log to likely rules
- readable enrichment for UI drilldowns

The search/ranking mechanism is BM25-backed.

### 4. Response and Orchestration

Response has two levels:

- preview
- execution

Previews show:

- action title
- operator summary
- exact command to be executed
- success criteria
- mapped playbook content

Execution is performed by:

- `scripts/run_response_action.py`
- `scripts/apply_response_control.py`

Runtime control state is held under:

- `state/response/runtime/`

Current supported live controls include:

- blocked source IPs
- disabled accounts
- rate limits
- isolated hosts
- quarantined endpoints

ZeroClaw-oriented orchestration is implemented through visible hands in `zeroclaw/hands/` and the orchestration runtime in `scripts/run_orchestration_engine.py`.

### 5. Backend and Frontend

The API layer is provided by FastAPI in `backend/app/`.

The UI is provided by Next.js in `frontend/`.

The frontend is split into focused live dashboards so the operator does not need to digest everything on one page.

## Project Flow

The normal operator flow looks like this:

1. Start the stack.
2. Start a live run from the UI or the API.
3. Execute one or more manual generator commands in another terminal.
4. Watch new logs arrive in the log explorer.
5. Watch Elastic and Wazuh alerts appear in the command center.
6. Click a log to see mapped rules.
7. Click a rule to see readable rule detail, MITRE mapping, and playbooks.
8. Review the response preview.
9. Execute the response if desired.
10. Observe the response state in the response dashboard.
11. Stop the run and retain the run history.

## Folder-by-Folder Explanation

### `backend/`

FastAPI backend used by the frontend and external API calls.

Important files:

- `backend/app/main.py`
- `backend/app/services.py`
- `backend/app/schemas.py`
- `backend/app/runtime_controls.py`

Responsibilities:

- dashboard aggregation
- live alerts
- live logs
- log-to-rule mapping
- rule-to-evidence mapping
- playbook detail serving
- response preview
- response execution
- live run control
- ZeroClaw runtime status
- API middleware enforcement for active controls

### `frontend/`

Next.js frontend that provides the operator-facing UI.

Important areas:

- `frontend/app/`
- `frontend/components/`
- `frontend/lib/api.ts`

Responsibilities:

- live command center
- runs dashboard
- log explorer
- rule studio
- playbook gallery
- response center
- agent orchestration dashboard

### `scripts/`

Automation, validation, ingestion support, and runtime workers.

Key scripts:

- `scripts/run_orchestration_engine.py`
- `scripts/run_response_watcher.py`
- `scripts/run_response_action.py`
- `scripts/apply_response_control.py`
- `scripts/run_suricata_watcher.py`
- `scripts/evaluate_existing_rule_pipeline.py`
- `scripts/generators/*`

### `config/`

Runtime configuration for the Docker stack and detection engines.

Key files:

- `config/logstash/pipeline/20-filter.conf`
- `config/wazuh/manager/ossec.conf`
- `config/wazuh/manager/rules/local_rules.xml`
- `config/wazuh/manager/decoders/local_decoder.xml`

### `zeroclaw/`

ZeroClaw hand definitions and runtime hand context files.

Key files:

- `zeroclaw/hands/*.toml`

The hands provide different responsibilities such as:

- orchestration
- sensors
- mapping
- validation
- bandwidth
- policy
- run supervision
- playbook resolution
- ZeroClaw runtime status

### `state/`

Operational runtime state. This is where the stack writes live state, response state, orchestration output, and run history.

Subareas include:

- `state/orchestration/`
- `state/response/`
- `state/demo_runs/`

### `ingest/`

Shared host-mounted ingest directories used by Logstash, Wazuh, and Suricata.

## How Detection Works

### Elastic Path

Logs are normalized by Logstash and indexed into Elasticsearch.
Elastic Security rules execute on schedules and create detections in `.alerts-security.alerts-*`.

### Wazuh Path

Wazuh reads shared telemetry and produces alerts in `wazuh-alerts-*`.
Archives are also visible in `wazuh-archives-*`.

### Suricata Path

PCAP files are processed by Suricata.
Suricata emits EVE data that is ingested into:

- `fda-suricata.eve-*`
- compact Suricata summaries for Wazuh correlation

## How Mapping Works

The system performs mapping in both directions.

### Rule to Logs

The platform can take:

- a natural-language query
- a selected rule
- a live alert

and pivot to candidate logs and evidence.

### Logs to Rules

The platform can take a selected live log and run a BM25-backed search against `rule-catalog` so the UI can show likely matching rules and their playbooks.

## How Response Works

Response selection starts with MITRE technique mapping.

The response engine chooses or plans an action from the supported set:

- `block_source_ip`
- `throttle_service`
- `disable_account`
- `isolate_host`
- `quarantine_endpoint`
- `block_egress`
- `observe_only`

Groq is used to assist with response planning inside the allowed action space. Execution is still restricted to safe known control types.

After execution:

- the result is indexed as a `security.response` event
- runtime control state is updated
- API middleware begins enforcing the control immediately where applicable

## How ZeroClaw Is Used Here

The project uses the real ZeroClaw binary for runtime status visibility and operator-facing surfacing of the ZeroClaw environment.

The frontend shows:

- ZeroClaw runtime status
- ZeroClaw-derived live status lines
- hand-by-hand orchestration state

The orchestration hand loop itself is implemented in the project runtime and exposed in a ZeroClaw-oriented structure.

## What Is Realtime

Realtime here means:

- the stack stays running continuously
- logs are polled into the UI repeatedly
- alerts are refreshed repeatedly
- agent state is refreshed repeatedly
- run state is refreshed repeatedly
- response controls are enforced immediately after activation

## Current Demo-Capable Existing-Rule Flows

The current live manual generators support these validation flows:

- Linux system information discovery
- Linux password policy discovery
- Linux sudoers persistence file event
- External SSH brute force
- Wazuh failed SSH
- Suricata-driven network sweep
- benign controls for auth, file activity, and network flow

## What To Read Next

- `TECHNICAL.md`
- `INSTRUCTIONS.md`
- `DEMO.md`
