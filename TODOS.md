# TODOS — FDA Cyber Control

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

## Verification

- 48 Python tests passing
- Go agent compiles and captures real ICMP traffic (verified with sudo)
- nftables enforcement verified with sudo (block_source_ip, isolate_host)
- All commits on master branch
