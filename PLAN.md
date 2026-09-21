# Implementation Plan — SocEyes Real Build

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
- `config/nftables/soceyes-rules.nft` — default nftables ruleset

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

## Design System (Approved)

### Fonts
- **Primary body**: ndot (added)
- **Secondary body**: n1 (added)
- **Headings**: Lexend Mega (added)
- **Mono/data**: IBM Plex Mono (kept from existing globals.css)

### Color Palette (kept from globals.css)
- Tech Brutalist: blue-only palette, white-on-dark, black-on-light
- Dark: `--blue-950: #0a0f29`, `--blue-900: #16213e`, `--blue-800: #1a1a2e`
- Mid: `--blue-600: #2563eb`, `--blue-500: #3b82f6`, `--blue-400: #60a5fa`
- Light: `--blue-50: #f0f9ff`, `--blue-100: #bfdbfe`, `--blue-150: #dbeafe`

### Interaction State Coverage Map (all 3 surfaces)
```
Incidents Page:    Loading — skeleton rows for verdict cards
                     Empty — "Active scene. Nothing burning." + agent fleet status link
                     Error  — red border, "Retry" button, error timestamp
                     Success — AI verdict block: severity, summary, recommended action
                     Partial — rule match without AI verdict (NVIDIA API pending)

Action Bar:      Loading — button disabled + spinner on action click
                     Empty — hidden when no incident selected
                     Error  — failed block: show nftables stderr, manual command copy
                     Success — action executed + TTL timer displayed (countdown to auto-rollback)
                     Partial — multi-step action: show completed steps, current step status

Audit Log:       Loading — skeleton rows
                     Empty — "No decisions yet" + link to incidents page
                     Error  — "Unable to load audit trail" + retry
                     Success — timestamped log: AI decision + enforcement action + rollback link
                     Partial — log entries shown but rollback unavailable for old entries
```

### User Journey
1. Alert fires → incidents page shows AI verdict (severity badge, summary)
2. Operator reads reasoning, decides → clicks Enforce/Observe/Dismiss
3. Action bar executes (block IP, isolate host) with 30-min TTL countdown
4. Incident moves to "Recent" section with applied actions
5. Operator later opens audit log to review/rollback past actions

### Responsive + Accessibility
- Desktop-first (SOC workstation paradigm), 375px mobile support via collapsible nav
- Touch targets ≥ 44px for Enforce/Dismiss buttons (critical under stress)
- Font contrast: white on dark mode ≥ 7:1, black on light mode ≥ 4.5:1
- Keyboard nav: Tab through incidents, Enter/Space to activate action buttons


## Design Decisions (Approved via /plan-design-review)

### D1: Information Architecture — Severity-first hierarchy. Severity color-coded badge is the first element in reading order.

### D2: Visual Language — 4-color semantic severity scale. Critical = red, High = orange, Medium = grey-blue, Low = muted. Blue palette stays for chrome/brand.

### D3: Audit Log — Action-first timeline. Each row shows enforcement action as primary, timestamp next, rollback button if TTL active, AI reasoning last.

### D4: Action Bar — Inline TTL + confirm modal (2-click). Consequence + TTL shown in modal before commit.

### D5: Interaction State Coverage — Map in PLAN C (already written).

### D6: Design System — Add 3 new fonts. ndot (body/UI), n1 (secondary), Lexend Mega (headings). IBM Plex Mono kept. Define complete font stack in CSS variables.

### D7: Responsive — Priority stacking. Single column on mobile, full-width actions, context collapses. (Note: D8 chose hide-panels instead; implementing B from D8 for mobile-specific nav.)

### D8: User Journey — Verdict-first fold. Severity + summary + action above fold at 1080p. Context/correlation below.

### D9: Accessibility — Shape + text + color redundancy for severity. 3-channel encoding for WCAG compliance.

### D10: Empty State — Agent-health-aware. "All clear. 3 agents reporting, last event 14s ago." with green pulse.

### D11: Tokens — Map new decisions to CSS variables. --severity-critical, --font-primary (ndot), --font-display (Lexend Mega), etc.

