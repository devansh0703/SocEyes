# SocEyes — Installation

## Prerequisites

You need:
- **Python 3.10+** 
- **npm** (optional, to build the web frontend)
- A `.env` file populated from `.env.example`

## Quick Start

### 1. Install

```bash
./soceyes install          # CLI file kept; prints "SocEyes"
```

This creates a Python virtual environment, installs dependencies, and builds the web frontend.

### 2. Configure

Edit `.env` to set your NVIDIA API key for LLM-powered features:

```bash
cp .env.example .env
# Edit .env and set NVIDIA_API_KEY=your-key-here
```

Get your key at: https://integrate.api.nvidia.com/

### 3. Start

```bash
./soceyes start
```

The server starts on `http://localhost:8000/`

- Dashboard: `http://localhost:8000/`
- API: `http://localhost:8000/api/health`

### 4. Bootstrap Rules

Index detection rules from vendor directories:

```bash
./soceyes bootstrap
```

## Server Commands

| Command | Description |
|---------|-------------|
| `./soceyes start` | Start the server (SocEyes CLI) |
| `./soceyes stop` | Stop the server |
| `./soceyes restart` | Restart the server |
| `./soceyes status` | Show health + DB stats |
| `./soceyes logs -n 50` | Tail server logs |
| `./soceyes stats` | Process resource usage |
| `./soceyes dashboard` | Open web UI |
| `./soceyes clean` | Remove all runtime state |

## Architecture

- **Single-process** FastAPI server (no Docker, no JVM)
- **SQLite** backend for events, alerts, rules, runs
- **NVIDIA Nemotron 3.5 Lightning** LLM for AI-powered features
- **Background attack simulator** generates live correlated alerts across all IDS engines
- **Retention auto-pruning** removes old events (configurable, default 24h)
- **Pre-built static frontend** served on `/`

## API Endpoints

### Health & Dashboard
```
GET  /api/health
GET  /api/dashboard
GET  /api/overview
GET  /api/stream/overview   (SSE)
```

### Rules
```
GET  /api/rules/search?q=<query>
GET  /api/rules/{rule_id}
GET  /api/rules/{rule_id}/evidence
```

### Logs & Alerts
```
GET  /api/logs/live
GET  /api/logs/search?q=<query>
GET  /api/logs/grouped
GET  /api/logs/{log_id}/rules
GET  /api/logs/{log_id}/detail
GET  /api/alerts/live
GET  /api/logs/analytics
```

### AI Features
```
POST /api/chat                    (NVIDIA LLM chat)
POST /api/query/resolve           (natural language → rules + logs)
```

### Response Actions
```
POST /api/response/preview
POST /api/response/execute
GET  /api/response/policy
PUT  /api/response/policy
```

### Runs (Live Sessions)
```
POST /api/runs/start
POST /api/runs/stop
GET  /api/runs/current
GET  /api/runs/history
GET  /api/runs/{run_id}
```

### Agents & Timeline
```
GET  /api/agents/live
GET  /api/timeline?entity_type=ip&entity_id=...
```

## Resource Usage

Designed to run on minimal hardware:
- **Memory**: ~200-500 MB (Python server + SQLite + background threads)
- **CPU**: <5% idle, <50% under load
- **Disk**: SQLite DB grows with events; auto-pruning keeps it bounded
- **No external dependencies** (no Elasticsearch, no Docker, no JVM)

## Configuration (`.env`)

```env
SOC_PORT=8000
NVIDIA_API_KEY=your-key-here
NVIDIA_MODEL=nvidia/nemotron-3.5-lightning-30b-a3b
RETENTION_HOURS=24
RESPONSE_AUTO_EXECUTE=false
```

## Troubleshooting

```bash
# Check if server is running
./soceyes status

# View logs
./soceyes logs -n 100

# Restart
./soceyes restart

# Clean slate (removes DB + logs)
./soceyes clean
./soceyes start
```
