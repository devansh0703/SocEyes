# TODOS — SocEyes

## P1 (Block ship) — ALL COMPLETE

- [x] Build Go agent with AF_PACKET capture — `agent/capture/afpacket.go`, `agent/capture/capture.go`
- [x] Replace attack simulator with real event receiver — `backend/app/main.py` (event queue + background thread)
- [x] Delete attack_generators.py and test_es_client.py
- [x] Implement real nftables enforcement — `backend/app/core/enforce.py` (block/throttle/isolate with TTL rollback)
- [x] Enhanced AI triage with raw packet context + timeline — `app_shared/nvidia_ai.py`
- [x] Real ZeroClaw runtime — `backend/app/core/orchestrator.py` + `agents/zeroclaw_daemon.py`
- [x] Full pipeline integration test — `tests/test_pipeline.py`

## P2 (Same branch) — ALL COMPLETE

- [x] zstd compression for raw payloads — `app_shared/unified_store.py` (`_compress_raw`/`_decompress_raw`)
- [x] Batch inserts with BEGIN IMMEDIATE + executemany — `store_events_batch()` in `unified_store.py`
- [x] Incidents UI page with severity-first hierarchy + one-click actions — `frontend/app/incidents/`
- [x] Audit log page + `/api/responses/audit` endpoint — `frontend/app/audit/`
- [x] install.sh builds Go agent alongside Python core
- [x] README.md rewritten to match actual deployment (no Docker/ES claims)
- [x] requirements/api.txt includes zstandard dependency

## P3 (Follow-up) — ALL COMPLETE

- [x] Windows Event Log forwarder agent — `scripts/windows_event_forwarder.py`
- [x] Cloud asset exposure checks — `scripts/check_cloud_exposure.py` + `/api/cloud/exposure` endpoint
- [x] Detection pack editor in frontend — `frontend/app/packs/` + `/api/packs` endpoints
- [x] Community rule marketplace — `frontend/app/marketplace/` + `/api/marketplace/packs` endpoint

## P4 (QA 2026-09-20) — ALL COMPLETE

- [x] Dashboard latency fix (cache + stale-while-revalidate + warmup) — `backend/app/main.py` `_build_dashboard`
- [x] Per-route static page serving (was serving dashboard shell everywhere) — `serve_spa`
- [x] FRONTEND_DIST defaults to frontend/out static export — `_default_frontend_dist`
- [x] API payload contracts fixed (agents/live, responses/audit, analytics aggregates) — main.py, unified_store.py
- [x] Capture index added to source map (dashboard showed 0 events) — unified_store.py
- [x] Trailing-slash API normalization middleware — main.py
- [x] CSS for 68 unstyled component classes + chat FAB resize — frontend/app/globals.css

## P5 (De-stub + premium pass 2026-09-20) — ALL COMPLETE

- [x] Attack simulation is test-only: start_simulation() is a hard no-op in
      both apps (standalone.py, agents_api.py); startup hooks never call it;
      generators live for tests/ only
- [x] Marketplace drops fabricated downloads/rating fields; real
      /api/marketplace/packs/{id}/download serves a zip of the pack's rule files
- [x] Honeypot sessions endpoint serves real state/honeypot data (was `{"items": []}`)
- [x] Real Panther integration: _seed_rules() ingests panther-analysis rules/
      correlation_rules/policies (1024 rules live in the catalog); corpus
      fetcher at scripts/fetch_rule_corpora.sh wired into install.sh; README
      documents the reproducible install order
- [x] lucide-react removed from bundle — bespoke 15-glyph SVG icon set
      (frontend/components/icons.tsx) matched to the tech-brutalist system
- [x] Premium refinement pass in globals.css: hero hierarchy, 2-col metric
      grid, flat nested cards, focus rings, selection color, scrollbars,
      sticky table headers, sidebar active rail, tabular numerals,
      prefers-reduced-motion, print stylesheet; --accent-violet token removed
- [x] python -m backend.app.main serves main:app (was launching agents_api:app)

## P6 (Modularization + footprint pass 2026-09-20) — ALL COMPLETE

- [x] React #418 hydration mismatch fixed: useCachedState() reads
      localStorage after mount; every readCached-in-initializer migrated
- [x] WAL bounded + reclaimed: db_maintenance.py (autocheckpoint 2000
      pages, 15-min TRUNCATE thread, 64MB soft cap, 256MB mmap);
      prune_events now incremental_vacuums; live result DB 4.66GB ->
      1.96GB, WAL 1.98GB -> 0
- [x] agents_api.py + standalone.py deleted (duplicate/broken apps);
      config.py + schemas.py (unused) deleted; main.py 1628 -> 1064
      lines with services/ modules (event_receiver, capture_detection,
      seed_rules, dashboard)
- [x] runtime_controls wired into API middleware (blocklist + rate
      limits enforced; /api/response/runtime serves real state — was {})
- [x] Client crash guards: playbook/zeroclaw/controls nested API access
- [x] Screenshots consolidated into screenshots/ (12 current captures,
      5 stale root PNGs removed)

## P7 (Detection live-fire pass 2026-09-20) — ALL COMPLETE

- [x] Detection loop was deaf: queried source "capture-agent" (not a key in
  _SOURCE_INDEX_MAP) -> filtered a nonexistent index. Fixed to "capture".
- [x] Port-scan alerts false-positived on ambient loopback traffic (20 ports /
  60s window). Now requires a 15s burst of 20+ distinct ports — scans alert,
  ambient noise does not. Unit-tested (ambient/scan/mixed/shuffled).
- [x] Agent amplification loop: capturing its own POSTs on loopback grew
  exponentially until agent AND server died (377k events in minutes). Agent
  now derives the API port from SOC_API_URL and drops self-traffic; ingest
  failures are logged (throttled). Rebuilt + running.
- [x] Stale root-owned agent process (no filter) was flooding the pipeline —
  killed; agent now runs unprivileged via cap_net_raw (setcap in install.sh).
- [x] Wazuh corpus was the wrong repo (engine source, zero rules) — fetch
  script + .gitignore now use wazuh/wazuh-ruleset; new XML seeder indexes 147
  rules (total catalog: sigma 3,110 + elastic 1,764 + panther 1,024 + wazuh).
- [x] Sigma YAMLs with date values crashed JSON serialization and were
  silently skipped — rule raw payloads now sanitized before storage.
- [x] python -m backend.app.main honors documented SOC_PORT (was hardcoded).
- [x] soceyes.sh: capture-agent added as a managed service; install bootstrap
  calls the real 4-engine seeder (inline copy had a broken rgglob call).
- [x] Response policy factory default auto_execute True -> False (unsafe
  default); operator's persisted choice unchanged.
- [x] LIVE-FIRE VERIFIED: 60-port TCP scan on loopback -> high alert
  "Port scan reconnaissance (T1046)" in 4 seconds, visible in
  /api/alerts/live with response preview attached.

## P8 (Detectors + enforcement verification + UI v3 2026-09-21) — ALL COMPLETE

- [x] Two new detectors: C2 beaconing (interval-regularity over 60s, T1071)
      and data exfiltration (SQL SUM(frame_len) per flow vs 100MB threshold,
      T1041) — backend/app/services/capture_detection.py
- [x] Agent emits frame_len + payload_len; store has numeric columns +
      store_event params (agent/capture/afpacket.go, agent/main.go,
      app_shared/unified_store.py)
- [x] Exfil volume aggregation is SQL-side (exfil_volumes) — Python-side
      sums of the newest N events undercount bursts (150MB transfer read as
      24MB)
- [x] Agent burst survival: eventCh 1000 -> 8192, shipper flushes at
      max-batch (500) instead of per-10 events — 150MB+ bursts no longer
      drop 80%+ of packets
- [x] Scan detector SYN-only + self-IP guard (was counting host RST
      replies as probes — nearly self-blocked the host)
- [x] enforce.py refuses to enforce against the machine's own interface
      IPs (SIOCGIFCONF) as the last line of defense
- [x] LIVE-FIRE VERIFIED (real docker traffic): port scan T1046, SSH
      brute force T1110, SYN flood T1498, C2 beaconing T1071 (jitter 0.00),
      exfil T1041 (129.5MB detected); LLM triage true_positive 0.95 ->
      block_egress auto-executed; packet drop + kernel TTL rollback proven;
      audit trail complete
- [x] UI v3 "flight deck": self-hosted variable Archivo + JetBrains Mono,
      graphite tokens, ECAM-style top status bar (capture/queue/engines/
      orchestrator + AUTO-RESPONSE ARMED pill), grouped sidebar (DETECT /
      RESPOND / INTEGRATE) with live counts, dense data tables, severity as
      the only loud color — frontend/app/globals.css, components/top-bar.tsx,
      components/nav.tsx rebuilt; Mission page is an ops briefing with live
      state (no marketing hero); Dashboard is a KPI strip (sparklines,
      trend deltas) + volume timeline + severity donut + top talkers +
      alert stream with AI verdict column
- [x] recharts animation off on every primitive (charts render final state
      in headless captures and don't re-animate on the 5s poll)
- [x] ES-style relative times (now-5h) resolved for the SQLite fallback in
      _build_where + search_alerts — the sidebar time filter used to
      silently return zero rows whenever Elasticsearch was down
- [x] /api/logs/analytics + dashboard payloads now carry source_indices
      (Logs page crashed on undefined)
- [x] pack-item / rule-row styles restored (Packs page rows were unstyled
      with overlapping text)
- [x] next.config: rewrites target SOC_PORT (was hardcoded 8123),
      outputFileTracingRoot set (workspace-root warning)
- [x] Fresh screenshots of all 13 views captured from live data
      (screenshots/)

## P9 (Deferred)

- [ ] soceyes CLI python_bin() falls back to .venv-tools (no uvicorn) when .venv-soceyes is missing — prefer system python3 in fallback order
- [ ] API launch is a hand-rolled root process (setsid + /tmp/soceyes-api-env.txt);
      make it a proper systemd unit

## Verification

- 48 Python tests passing
- Go agent compiles, runs unprivileged (cap_net_raw), filters self-traffic,
  and captures live loopback traffic
- nftables enforcement verified with sudo (block_source_ip, isolate_host)
- All commits on master branch
- QA 2026-09-20: 10 issues found, 10 fixed, health 31 -> 84 (report: .gstack/qa-reports/qa-report-soceyes-2026-09-20.md)
- De-stub + premium pass 2026-09-20: 1024 Panther rules searchable, pack
  zips download, honeypot real data, zero lucide code in bundle,
  simulation:false in health, all 8 pages render with real data
- Detection live-fire 2026-09-20: real port scan -> alert in 4s; 4-engine
  rule catalog fully indexed (sigma 3,110 / elastic 1,764 / panther 1,024 /
  wazuh 147 XML rules)
- P8 2026-09-21: 83 Python tests passing; 5/5 detectors verified with real
  attack traffic; auto-response chain verified end-to-end (LLM triage ->
  nft block -> packet drop -> TTL rollback -> audit); all 13 views
  screenshot-verified against live data
