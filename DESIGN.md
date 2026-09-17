# FDA Cyber Control — Design Document

**Status:** DRAFT  
**Date:** 2026-09-18  
**Author:** devansh

## Problem Statement

Mid-market companies (50–500 employees) cannot afford Splunk + a SOC team. Existing open-source IDS tools (Elastic Security, Wazuh, Suricata, Sigma, Panther) each cover a slice of detection but require a SOC team to operate and integrate. A unified, single-box IDS/IPS that captures real traffic, detects real attacks, explains them in plain English via AI, and enforces containment on the kernel does not exist for this price point.

## Existing State (What's Real)

| Layer | Status |
|---|---|
| Detection rules (2000+ Elastic/Sigma/Wazuh/Panther) | Real — BM25 indexed, searchable |
| 18-hand orchestration engine (ZeroClaw TOML hands) | Real — correlates events, maps MITRE, plans response |
| Unified store (SQLite/ES fallback) | Real — WAL mode, schema defined |
| AI triage via NVIDIA API | Real — Nemotron LLM call with alert context |
| Attack generators | Synthetic only — must be replaced with real capture |
| ZeroClaw daemon | Stub — /health endpoint only |
| Response enforcement | Stub — JSON registry, not kernel |
| Dashboard (Next.js) | Real — 11 pages, Recharts |
| install.sh + Makefile | Real — functional |

## Target State

A single-box IDS/IPS that:
1. Captures real network traffic via AF_PACKET on the agent
2. Ingests real logs (journald, auditd, syslog, nginx, Windows Event Log)
3. Detects against the existing 6000-rule catalog
4. Triages via NVIDIA LLM: verdict, severity, plain-English summary, recommended action
5. Enforces containment via nftables (block IPs, rate-limit, isolate hosts)
6. Every action has TTL, auto-reverses, and is auditable

## Architecture

```
[Agent: AF_PACKET Capture]
    |
    v
[FastAPI Core: store_event()]
    |
    v
[SQLite: events + alerts + rules]
    |
    v
[Orchestrator: 18 ZeroClaw hands]
    |
    +---> [NVIDIA LLM: AI triage]
    |
    +---> [Enforcement: nftables]
```

## Components

### 1. Agent (Go, eBPF/AF_PACKET)
- Captures packets via AF_PACKET or eBPF/XDP
- Tails journald, auditd, syslog
- Ships events to core via NATS or HTTP
- ~30MB RAM, <5% CPU at 1000 eps

### 2. Core (Python, FastAPI)
- unified_store.py: SQLite WAL with zstd compression on raw payloads
- Orchestrator: executes 18 ZeroClaw hands on each new event
- Response engine: real nftables enforcement via subprocess
- NVIDIA AI: per-alert triage call with full context

### 3. Frontend (Next.js)
- Incidents page: active alerts with AI verdict + one-click Acknowledge/Contain/Dismiss
- Fleet health: agent status, last-seen
- Audit log: every AI decision and enforcement action

## Storage

SQLite with:
- WAL mode + synchronous=NORMAL
- Batch inserts (BEGIN IMMEDIATE + executemany)
- zstd compression on raw payloads
- Retention pruning (configurable, default 7 days)
- Expected: 50-100MB/day disk on a busy network

## Dependencies

```
libpcap-dev (compile-time for agent)
nftables (already in kernel)
python3.11, uvicorn, fastapi, requests
sqlite3 (already on any Linux)
NVIDIA_API_KEY (user's .env)
```

## What Gets Removed

- agents/zeroclaw_daemon.py (stub)
- app_shared/attack_generators.py (synthetic only)
- README.md Docker claims (code doesn't match)
- tests/test_es_client.py (no ES in deployment)

## Distribution

`fda install` downloads/installs the agent binary + core. `fda start` runs both in the foreground under systemd. Agent phone-homes to core on first boot.

