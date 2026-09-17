# Implementation Plan — FDA Cyber Control Real Build

**Generated:** 2026-09-18  
**Mode:** plan-eng-review  
**Scope:** B-Modified real product build

## Step 1: Agent (Go binary with AF_PACKET)

**Workstream:** agent/

Files:
- `agent/main.go` — entry, config, event loop
- `agent/capture/afpacket.go` — AF_PACKET socket + packet decode
- `agent/ingest/journald.go`, `auditd.go`, `syslog.go` — log tailers
- `agent/shipper/nats.go` — event transport
- `agent/go.mod`

Tests: `agent/capture/afpacket_test.go` — decode known pcap bytes into event fields.

2. Core (Python orchestrator wiring)

Files:
- `backend/app/main.py` — replace generators with NATS subscriber
- `backend/app/core/orchestrator.py` — ZeroClaw runtime that loads zeroclaw/hands/*.toml
- `backend/app/core/enforce.py` — nftables enforcement worker
- `backend/app/core/ai_triage.py` — NVIDIA LLM call with full context

Tests: `tests/test_orchestrator.py`, `tests/test_enforce.py`, `tests/test_ai_triage.py`

3. Real enforcement

Files:
- `agents/response_engine.py` — replace JSON registry with real nftables subprocess calls
- `config/nftables/fda-rules.nft` — default nftables ruleset

4. AI Triage

Files:
- `app_shared/nvidia_ai.py` — extend existing NVIDIA call with raw packet + correlated timeline

Prompts in `app_shared/prompts/` structured per-alert.

5. Frontend

Files:
- `frontend/app/incidents/page.tsx` — combine alerts + AI verdict + action buttons
- `frontend/components/action-bar.tsx` — per-incident enforce/observe/dismiss
- `frontend/app/audit/page.tsx` — audit trail of every decision + action

6. Install + distribution

Files:
- `install.sh` — add agent binary download + nftables agent setup
- `Makefile` — add `make agent` target for Go build

Tests: `tests/test_install.sh` — verify install flow in a container.

+ 6 unresolved from prior reviews
