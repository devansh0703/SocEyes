# TODOS — FDA Cyber Control

## P1 (Block ship)

- [ ] Build Go agent with AF_PACKET capture — `agent/main.go`
- [ ] Replace NATS/gRPC receiver for real events (not generators) — `backend/app/main.py`
- [ ] Implement ZeroClaw runtime: load TOML hands, execute on real events — `backend/app/core/orchestrator.py`
- [ ] Implement real nftables enforcement — `backend/app/core/enforce.py`
- [ ] Extend AI triage with raw packet context + timeline — `app_shared/nvidia_ai.py`
- [ ] Replace stub zeroclaw_daemon.py with real runtime — `agents/zeroclaw_runtime.py`
- [ ] Write tests for full real-event pipeline — `tests/test_pipeline.py`

## P2 (Same branch)

- [ ] Add zstd compression to raw payloads in unified_store
- [ ] Batch inserts in store_event (BEGIN IMMEDIATE + executemany)
- [ ] New incidents UI page with one-click action buttons
- [ ] Audit log page showing every AI decision + enforcement action
- [ ] Rewrite install.sh to install Go agent alongside Python core
- [ ] Delete attack_generators.py, test_es_client.py
- [ ] Rewrite README.md to match actual deployment mode

## P3 (Follow-up)

- [ ] Windows Event Log forwarder agent
- [ ] Cloud asset exposure checks (AWS/Azure/GCP metadata)
- [ ] Detection pack editor in frontend
- [ ] Community rule marketplace (download curated packs)
