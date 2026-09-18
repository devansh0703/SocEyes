# Technical Overview for Frontend Rebuild/Integration

---

## 1. SYSTEM OVERVIEW

### High-Level Architecture
- **Frontend:** Next.js (TypeScript), React, Recharts for visualization
- **Backend:** FastAPI (Python 3.11+), REST API
- **Database/Storage:** Elasticsearch (primary log/rule/alert storage), BM25 for search/ranking
- **Supporting Services:**
  - Kibana (Elastic Security UI)
  - Logstash (log ingestion/normalization)
  - Wazuh (host-based detection/correlation)
  - Suricata (network telemetry)
  - ZeroClaw (orchestration/response)
  - Panther Analysis Tool (local rule validation)
- **Orchestration:** Docker Compose (multi-service stack)

### Technologies Used
- **Frontend:** Next.js 15, React, TypeScript, Recharts, CSS modules
- **Backend:** FastAPI, Python 3.11+, requests, asyncio
- **Infrastructure:** Docker Compose, Dockerfiles for each service
- **Other:** BM25 search, MITRE ATT&CK mapping, SOAR playbooks

### Component Interaction & Data Flow
- Logs/telemetry ingested via Logstash/Wazuh/Suricata → Elasticsearch
- Detection rules (Elastic, Sigma, Wazuh) loaded into Elasticsearch
- Backend FastAPI exposes REST endpoints for logs, rules, alerts, playbooks, response, orchestration
- Frontend calls backend API for dashboards, logs, rules, playbooks, response preview/execute, agent/orchestration state
- Operator actions (response execution, run control) flow from frontend → backend → orchestration/response engine

---

## 2. API DOCUMENTATION

### General
- **Base URL:** `http://localhost:8000`
- **Authentication:** No explicit login/token in current code (assumption: local/dev use, see section 4)
- **Headers:** Some endpoints may use custom headers (e.g., `x-user` for enforcement)

### Endpoints

| Path | Method | Purpose | Params | Auth | Example |
|------|--------|---------|--------|------|---------|
| `/api/health` | GET | Health check | None | None | `{ "status": "ok" }` |
| `/api/dashboard` | GET | Dashboard summary | `start`, `end` (query) | None | `{ ...dashboard data... }` |
| `/api/overview` | GET | Overview (same as dashboard) | `start`, `end` (query) | None | `{ ...overview... }` |
| `/api/rules/search` | GET | Search rules | `q`, `limit`, `engines` (query) | None | `{ "query": "...", "matches": [...] }` |
| `/api/rules/{rule_id}` | GET | Rule detail | `rule_id` (path) | None | `{ ...rule... }` |
| `/api/rules/{rule_id}/evidence` | GET | Rule evidence | `rule_id` (path), `limit`, `start`, `end` (query) | None | `{ ...evidence... }` |
| `/api/logs/search` | GET | Search logs | `q`, `limit`, `start`, `end` (query) | None | `{ "query": "...", "matches": [...] }` |
| `/api/logs/live` | GET | Live logs | `limit`, `start`, `end` (query) | None | `{ "items": [...] }` |
| `/api/logs/{log_id}/rules` | GET | Rules for a log | `log_id` (path), `limit` (query) | None | `{ ...payload... }` |
| `/api/logs/analytics` | GET | Log analytics | `start`, `end` (query) | None | `{ ...analytics... }` |
| `/api/query/resolve` | POST | Natural language query to rules | JSON: `{ query, limit, engines, start, end }` | None | `{ "query": "...", "matches": [...] }` |
| `/api/alerts/live` | GET | Live alerts | `limit`, `start`, `end` (query) | None | `{ "items": [...] }` |
| `/api/playbooks/{technique_id}` | GET | Playbook detail | `technique_id` (path) | None | `{ ...playbook... }` |
| `/api/agents/live` | GET | Live agent/orchestration state | None | None | `{ ...agents... }` |
| `/api/agents/{hand_name}/history` | GET | Agent run history | `hand_name` (path), `limit` (query) | None | `{ "items": [...] }` |
| `/api/zeroclaw/status` | GET | ZeroClaw runtime status | None | None | `{ ...status... }` |
| `/api/runs/current` | GET | Current run state | None | None | `{ ...run... }` |
| `/api/runs/history` | GET | Run history | `limit` (query) | None | `{ "items": [...] }` |
| `/api/runs/start` | POST | Start a run | JSON: `{ name, note }` | None | `{ ...run... }` |
| `/api/runs/stop` | POST | Stop a run | JSON: `{}` | None | `{ ...run... }` |
| `/api/generators` | GET | List generator scenarios | None | None | `{ "items": [...] }` |
| `/api/response/policy` | GET | Get response policy | None | None | `{ ...policy... }` |
| `/api/response/policy` | PUT | Update response policy | JSON: policy | None | `{ ...policy... }` |
| `/api/response/runtime` | GET | Get live response state | None | None | `{ ...runtime... }` |
| `/api/response/preview` | POST | Preview response | JSON: `{ ... }` | None | `{ ...preview... }` |
| `/api/response/execute` | POST | Execute response | JSON: `{ ... }` | None | `{ ...result... }` |
| `/api/stream/overview` | GET | SSE stream of overview | None | None | `event-stream` |

#### Example: `/api/rules/search`
- **Request:** `GET /api/rules/search?q=ssh&limit=5`
- **Response:**
```json
{
  "query": "ssh",
  "matches": [
    { "id": "fa210b61-b627-4e5e-86f4-17e8270656ab", "title": "External SSH brute force", ... }
  ]
}
```

#### Error Responses
- 404: Not found (e.g., rule/log not found)
- 400: Bad request (malformed input)
- 403: Forbidden (blocked IP/account, disabled manual response)
- 429: Rate limit (with `X-RateLimit-Remaining` header)

---

## 3. DATA MODELS

### Key Entities
- **LogItem:** `{ id, timestamp, message, source_ip, ... }`
- **Rule:** `{ id, title, engine, mitre_ids, logic, ... }`
- **Alert:** `{ id, timestamp, rule_id, technique_id, ... }`
- **Run:** `{ id, name, note, started_at, stopped_at, ... }`
- **Playbook:** `{ technique_id, path, available, sections }`
- **ResponsePolicy:** `{ blocked_ips, disabled_accounts, rate_limits, ... }`
- **Agent/Hand:** `{ name, status, history, ... }`

### Relationships
- Logs map to rules (log-to-rule and rule-to-log pivots)
- Rules map to MITRE techniques and playbooks
- Alerts reference rules and logs
- Runs track generator activity and validation

### Validation Rules
- Most fields are validated for presence/type in backend schemas (see `schemas.py`)
- Response execution is gated by policy (manual execution may be disabled)

---

## 4. AUTHENTICATION & AUTHORIZATION
- **Current state:** No explicit login/signup or token-based auth in codebase (assumption: local/lab use)
- **Enforcement:**
  - Backend middleware enforces blocked IPs, disabled accounts, and rate limits via response policy
  - Custom header `x-user` can be used for account enforcement
- **Assumption:** If production auth is needed, add JWT/session/OAuth at API layer

---

## 5. FRONTEND REBUILD GUIDE

### Required Screens/Pages
- Dashboard (live summary)
- Runs (start/stop run, view history)
- Logs (live log explorer, log-to-rule mapping)
- Rules (search, detail, evidence)
- Alerts (live alert feed)
- Playbooks (MITRE technique mapping, readable playbook content)
- Responses (preview/execute response, view policy/runtime)
- Agents (orchestration hands, agent state/history)

### API Mapping per Screen
- **Dashboard:** `/api/dashboard`, `/api/overview`, `/api/alerts/live`, `/api/logs/live`
- **Runs:** `/api/runs/current`, `/api/runs/history`, `/api/runs/start`, `/api/runs/stop`, `/api/generators`
- **Logs:** `/api/logs/live`, `/api/logs/{log_id}/rules`, `/api/logs/analytics`
- **Rules:** `/api/rules/search`, `/api/rules/{rule_id}`, `/api/rules/{rule_id}/evidence`, `/api/query/resolve`
- **Alerts:** `/api/alerts/live`
- **Playbooks:** `/api/playbooks/{technique_id}`
- **Responses:** `/api/response/preview`, `/api/response/execute`, `/api/response/policy`, `/api/response/runtime`
- **Agents:** `/api/agents/live`, `/api/agents/{hand_name}/history`

### State Management Considerations
- Use React context or a state manager (Zustand, Redux, etc.) for global state (run state, user, policy)
- Use SWR/React Query for API data fetching/caching
- Handle SSE for live streams (`/api/stream/overview`)

### Important UX Flows
- No login/signup (unless added)
- Start/stop run, fire generator, observe logs/alerts, drill into rules/playbooks, preview/execute response
- CRUD for response policy (block IP, disable account, etc.)

---

## 6. ENVIRONMENT & SETUP

### Base URLs
- **Frontend:** `http://localhost:3000`
- **Backend API:** `http://localhost:8000`
- **Kibana:** `http://localhost:5602`
- **Elasticsearch:** `http://localhost:9201`
- **ZeroClaw Daemon:** `http://localhost:9393/health`

### Environment Variables
- `NVIDIA_API_KEY`, etc. (see `.env`)

### Local Run Instructions
1. Populate `.env` with required secrets
2. `docker compose up -d --build`
3. Open frontend at `http://localhost:3000`
4. Use Makefile for common tasks (e.g., `make up`, `make bootstrap`, `make test-pipeline`)

---

## 7. DEPENDENCIES & EXTERNAL SERVICES

### Third-Party APIs/Integrations
- **Elastic Stack:** Elasticsearch, Kibana, Logstash
- **Wazuh:** Host-based detection
- **Suricata:** Network telemetry
- **ZeroClaw:** Orchestration/response
- **MITRE ATT&CK Playbooks:** Playbook content
- **Panther Analysis Tool:** Rule validation
- **BM25:** Search/ranking (internal)
- NVIDIA API: for Nemotron 3.5 Lightning LLM responses

### No payment/storage gateways; all data is local or via open-source services.

---

## Assumptions
- No user login/signup in current codebase; add as needed for production
- All API endpoints are public on local network
- If any endpoints are missing, infer from backend/app/main.py and services.py

---

*This document is auto-generated for integration/rebuild planning. Update as the system evolves.*
