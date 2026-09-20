# FDA Cyber Control

Single-box IDS/IPS with AI-driven triage and nftables enforcement. Detects real network traffic, correlates across engines, explains in plain English, and enforces containment on the kernel.

![Dashboard](screenshots/Dashboard.png)
![Alerts](screenshots/Alerts.png)
![Agents](screenshots/Agents.png)
![Incidents](screenshots/Incidents.png)
![Audit Log](screenshots/Audit_Log.png)
![Command Center](screenshots/Command_Center.png)
![Detection Rules](screenshots/Detection_Rules.png)
![MITRE Playbooks](screenshots/MITRE_Playbooks.png)

## What It Does

1. **Real packet capture** — Go agent captures raw traffic via AF_PACKET (eBPF ready)
2. **Real log ingestion** — journald, auditd, syslog, nginx, Windows Event Log
3. **Detection** — 6000+ rules (Sigma, Elastic, Wazuh, Panther) with BM25 search
4. **AI triage** — NVIDIA LLM analyzes raw packet context + correlated timeline
5. **Enforcement** — nftables rules for block/throttle/isolate with TTL-based rollback
6. **ZeroClaw agents** — 18 TOML-configured hands run deterministic logic on real events

## Architecture

```
[Go Agent: AF_PACKET] -> [FastAPI: store_event()] -> [SQLite: zstd-compressed]
                                                    |
                                [ZeroClaw Runtime: 18 hands on schedule]
                                        |
                    [NVIDIA LLM: AI triage]    [nftables: enforcement]
                                        |
                            [React dashboard: incidents + audit]
```

## Installation

### Prerequisites

- Python 3.10+
- Go 1.25+ (for the capture agent)
- libpcap-dev (compile-time for Go agent)
- nftables (kernel module, already present on most Linux)
- NVIDIA API key (optional, enables AI triage)

### 1. Install

```bash
./scripts/fetch_rule_corpora.sh   # fetch detection rule corpora (Sigma, Elastic, Wazuh, Panther)
./install.sh                      # venv, deps, frontend build, rule indexing
```

The fetcher pulls the gitignored rule corpora from their upstream repos (shallow clone, tarball fallback) and is safe to re-run. `install.sh` then indexes every corpus into the rule catalog — Sigma, Elastic, Wazuh, and Panther engines all appear in the rule explorer.

### 2. Configure

```bash
cp .env.example .env
# Edit .env:
#   NVIDIA_API_KEY=your-key-here    (optional, enables AI triage)
#   FDA_RESPONSE_DRY_RUN=true        (default: true, set false for live enforcement)
#   FDA_RESPONSE_TTL_SECONDS=1800   (enforcement TTL, default 30 minutes)
```

Get an NVIDIA API key at https://integrate.api.nvidia.com/

### 3. Start

```bash
./fda start
```

This starts:
- The API server on http://localhost:8000
- The ZeroClaw runtime (18 agent hands)
- The event receiver (Go agent HTTP endpoint on http://localhost:8001)
- The retention auto-prune thread

### 4. Run the Go capture agent

In another terminal (requires root for AF_PACKET):

```bash
cd agent
go build -o fda-agent .
sudo setcap cap_net_raw=ep fda-agent   # packet capture without running as root
./fda-agent
```

The agent captures packets on the default interface, **excludes its own API traffic** (no feedback loop), and POSTs decoded events to the API at `FDA_API_URL` (default http://127.0.0.1:8000/api/events/ingest). Point it at your server with `FDA_API_URL=http://<host>:<port>` and choose the interface with `FDA_AGENT_INTERFACE` (default `lo`).

## Screenshots

### Dashboard

The main mission control view showing live telemetry, detection stats, and system status.

![Dashboard](screenshots/Dashboard.png)

### Alerts

Live alert feed from Elastic, Wazuh, and Suricata with severity indicators and MITRE technique mapping.

![Alerts](screenshots/Alerts.png)

### Agents

ZeroClaw agent hands status showing 18 parallel execution channels.

![Agents](screenshots/Agents.png)

### Incidents

Correlated incident view combining multiple detection engines into unified incident timelines.

![Incidents](screenshots/Incidents.png)

### Audit Log

Complete audit trail of all AI decisions and enforcement actions with rollback status.

![Audit Log](screenshots/Audit_Log.png)

### Command Center

Operational command center with detection metrics, run history, and system health.

![Command Center](screenshots/Command_Center.png)

### Detection Rules

Searchable rule explorer with BM25 full-text search across 6000+ detection rules.

![Detection Rules](screenshots/Detection_Rules.png)

### MITRE Playbooks

MITRE ATT&CK playbook browser with live detection context and executable response commands.

![MITRE Playbooks](screenshots/MITRE_Playbooks.png)

## API Endpoints

### Events

```
POST /api/events/ingest         Ingest captured events (single or batch)
GET  /api/events/status         Event receiver status
```

### AI Triage

```
GET  /api/health                 Health check + config status
```

### Dashboard

```
GET  /                          React frontend (Command Center)
```

## Configuration (.env)

| Variable | Default | Purpose |
|----------|---------|---------|
| `FDA_PORT` | 8000 | API server port |
| `FDA_AGENT_PORT` | 8001 | Go agent HTTP endpoint |
| `NVIDIA_API_KEY` | (empty) | Enables AI triage |
| `NVIDIA_MODEL` | nvidia/nemotron-3.5-lightning-30b-a3b | LLM model |
| `FDA_RESPONSE_DRY_RUN` | true | Dry-run mode (no nftables changes) |
| `FDA_RESPONSE_TTL_SECONDS` | 1800 | Enforcement TTL |
| `RETENTION_HOURS` | 168 | Event retention (7 days) |
| `FDA_ES_TIMEOUT_SECONDS` | 30 | ES query timeout |

## Enforcement Actions

| Action | What it does | Kernel mechanism |
|--------|-------------|-------------------|
| `block_source_ip` | Drops all packets from a source IP | `nftables` rule |
| `throttle_service` | Rate-limits requests per minute | `nftables limit` |
| `isolate_host` | Drops all traffic to/from an IP | dual `nftables` rules |
| `disable_account` | Locks a Linux account | `usermod -L` |
| `observe_only` | Logs only, no enforcement | — |

Every enforcement action has a TTL. After TTL expires, the rule is automatically removed (rollback). Every action is logged to `/tmp/fda-enforcement.log`.

## ZeroClaw Agents

18 TOML-configured agent hands run on a schedule:
- `alert_correlator` — clusters alerts by source IP
- `threat_summarizer` — summarizes high/critical alerts
- `response_planner` — checks policy gates before execution
- `policy_guardian` — verifies response policy compliance
- `mitre_mapper` — maps alerts to MITRE ATT&CK techniques
- `validation_agent` — validates rules firing on real events
- `evidence_curator` — collects forensic artifacts
- `playbook_resolver` — resolves MITRE playbook references
- `orchestrator_main` — meta-hand for runtime health

Every hand is real code in `agents/orchestration_engine.py::execute_hand()`. Every hand reads from the unified store, produces findings, and persists context.

## Storage

SQLite with:
- WAL mode (concurrent reads/writes)
- `synchronous=NORMAL` (performance)
- Batch inserts (`BEGIN IMMEDIATE + executemany`)
- zstd compression on raw payloads
- Retention auto-pruning

Expected disk usage: ~50-100 MB/day on a busy network.

## Testing

```bash
make test                  # Python unit tests (pytest)
make test-pipeline         # Integration test (requires sudo for AF_PACKET)
cd agent && go test ./...  # Go agent tests (requires sudo for real capture)
```

## Limitations

- AF_PACKET requires root (or CAP_NET_RAW capability)
- nftables requires root
- AI triage requires a valid NVIDIA API key
- SQLite is single-writer; batch insert is used for throughput
- No horizontal scaling (single-box design)

## Design

See [DESIGN.md](DESIGN.md) for the full design document including the 11 approved design decisions from the design review.

## Internal architecture

- `backend/app/core/orchestrator.py`: Real ZeroClaw runtime that loads TOML hands and executes them on live events published from the event bus.
- `backend/app/core/enforce.py`: Real nftables enforcement with block/throttle/isolate actions, TTL rollback scheduling, and log persistence.
- `agents/orchestration_engine.py`: Existing Python orchestration implementation used by the standalone runtime and tests.
- `agents/zeroclaw_daemon.py`: Runtime daemon that runs the full ZeroClaw hand loop and exposes health/run status over HTTP.
- `app_shared/nvidia_ai.py`: Enhanced AI triage using packet context and correlated timeline with NVIDIA API, including a rule-based offline fallback.
- `app_shared/unified_store.py`: SQLite storage with zstd-compressed payloads and batch ingestion.
- `agent/capture/afpacket.go`: Production AF_PACKET capture loop.
- `agent/capture/afpacket.go`: Real packet decoders for Ethernet, IPv4, TCP, and ICMP.
